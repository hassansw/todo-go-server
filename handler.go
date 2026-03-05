package handler

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"todo-server-secure/internal/auth"
	mw "todo-server-secure/internal/middleware"
	"todo-server-secure/internal/model"
	"todo-server-secure/internal/store"
	"todo-server-secure/internal/upload"
	"todo-server-secure/internal/validator"
)

type Handler struct {
	store    *store.Store
	tokenSvc *auth.TokenService
	uploader *upload.Service
}

func New(s *store.Store, ts *auth.TokenService, up *upload.Service) *Handler {
	return &Handler{store: s, tokenSvc: ts, uploader: up}
}

// ============================================================
// Helpers
// ============================================================

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func respondOK(w http.ResponseWriter, data interface{}) {
	respondJSON(w, http.StatusOK, model.APIResponse{Data: data})
}

func respondCreated(w http.ResponseWriter, data interface{}) {
	respondJSON(w, http.StatusCreated, model.APIResponse{Data: data})
}

func respondError(w http.ResponseWriter, status int, msg string) {
	respondJSON(w, status, model.APIResponse{Error: msg})
}

func respondMsg(w http.ResponseWriter, msg string) {
	respondJSON(w, http.StatusOK, model.APIResponse{Message: msg})
}

func extractID(path, prefix string) string {
	trimmed := strings.TrimPrefix(path, prefix)
	trimmed = strings.TrimRight(trimmed, "/")
	// Handle sub-paths like /todos/5/image
	parts := strings.SplitN(trimmed, "/", 2)
	return parts[0]
}

func methodNotAllowed(w http.ResponseWriter) {
	respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
}

// ============================================================
// Health
// ============================================================

func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	ctx := r.Context()
	if err := h.store.Ping(ctx); err != nil {
		respondError(w, http.StatusServiceUnavailable, "Database unreachable")
		return
	}
	respondOK(w, map[string]string{"status": "ok", "time": time.Now().UTC().Format(time.RFC3339)})
}

// ============================================================
// Auth Routes
// ============================================================

func (h *Handler) HandleAuth(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimRight(r.URL.Path, "/")

	switch {
	case path == "/auth/register" && r.Method == http.MethodPost:
		h.register(w, r)
	case path == "/auth/login" && r.Method == http.MethodPost:
		h.login(w, r)
	case path == "/auth/refresh" && r.Method == http.MethodPost:
		h.refresh(w, r)
	case path == "/auth/logout" && r.Method == http.MethodPost:
		h.logout(w, r)
	default:
		respondError(w, http.StatusNotFound, "Not found")
	}
}

func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	var req model.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	// Validate
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.Name = validator.SanitiseString(req.Name, 100)

	if !validator.ValidEmail(req.Email) {
		respondError(w, http.StatusBadRequest, "Invalid email address")
		return
	}
	if ok, msg := validator.ValidPassword(req.Password); !ok {
		respondError(w, http.StatusBadRequest, msg)
		return
	}
	if ok, msg := validator.ValidName(req.Name); !ok {
		respondError(w, http.StatusBadRequest, msg)
		return
	}

	// Check uniqueness
	existing, err := h.store.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		log.Printf("register db error: %v", err)
		respondError(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if existing != nil {
		respondError(w, http.StatusConflict, "Email already registered")
		return
	}

	// Hash password
	hash, err := h.tokenSvc.HashPassword(req.Password)
	if err != nil {
		log.Printf("hash password error: %v", err)
		respondError(w, http.StatusInternalServerError, "Internal error")
		return
	}

	user, err := h.store.CreateUser(r.Context(), req.Email, hash, req.Name)
	if err != nil {
		log.Printf("create user error: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}

	// Generate tokens
	authResp, err := h.generateTokenPair(r.Context(), user)
	if err != nil {
		log.Printf("generate tokens error: %v", err)
		respondError(w, http.StatusInternalServerError, "Internal error")
		return
	}

	respondCreated(w, authResp)
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var req model.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	// Constant-time-ish: always hash-check even on missing user
	user, err := h.store.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		log.Printf("login db error: %v", err)
		respondError(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if user == nil {
		// Still do a dummy bcrypt compare to prevent timing attacks
		h.tokenSvc.CheckPassword("$2a$12$000000000000000000000000000000000000000000000000000000", req.Password)
		respondError(w, http.StatusUnauthorized, "Invalid email or password")
		return
	}

	if !h.tokenSvc.CheckPassword(user.PasswordHash, req.Password) {
		respondError(w, http.StatusUnauthorized, "Invalid email or password")
		return
	}

	authResp, err := h.generateTokenPair(r.Context(), user)
	if err != nil {
		log.Printf("generate tokens error: %v", err)
		respondError(w, http.StatusInternalServerError, "Internal error")
		return
	}

	respondOK(w, authResp)
}

func (h *Handler) refresh(w http.ResponseWriter, r *http.Request) {
	var req model.RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	if req.RefreshToken == "" {
		respondError(w, http.StatusBadRequest, "Refresh token is required")
		return
	}

	tokenHash := h.tokenSvc.HashToken(req.RefreshToken)

	stored, err := h.store.GetRefreshToken(r.Context(), tokenHash)
	if err != nil {
		log.Printf("refresh token db error: %v", err)
		respondError(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if stored == nil || stored.Revoked || time.Now().After(stored.ExpiresAt) {
		respondError(w, http.StatusUnauthorized, "Invalid or expired refresh token")
		return
	}

	// Rotate: revoke old, issue new (prevents replay attacks)
	if err := h.store.RevokeRefreshToken(r.Context(), tokenHash); err != nil {
		log.Printf("revoke token error: %v", err)
		respondError(w, http.StatusInternalServerError, "Internal error")
		return
	}

	user, err := h.store.GetUserByID(r.Context(), stored.UserID)
	if err != nil || user == nil {
		respondError(w, http.StatusUnauthorized, "User not found")
		return
	}

	authResp, err := h.generateTokenPair(r.Context(), user)
	if err != nil {
		log.Printf("generate tokens error: %v", err)
		respondError(w, http.StatusInternalServerError, "Internal error")
		return
	}

	respondOK(w, authResp)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	var req model.RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	if req.RefreshToken != "" {
		tokenHash := h.tokenSvc.HashToken(req.RefreshToken)
		_ = h.store.RevokeRefreshToken(r.Context(), tokenHash)
	}

	respondMsg(w, "Logged out successfully")
}

func (h *Handler) generateTokenPair(ctx context.Context, user *model.User) (*model.AuthResponse, error) {
	accessToken, err := h.tokenSvc.GenerateAccessToken(user.ID, user.Email)
	if err != nil {
		return nil, err
	}

	refreshPlain, refreshHash, err := h.tokenSvc.GenerateRefreshToken()
	if err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(h.tokenSvc.RefreshTokenExpiry())

	if err := h.store.SaveRefreshToken(ctx, user.ID, refreshHash, expiresAt); err != nil {
		return nil, err
	}

	return &model.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshPlain,
		ExpiresIn:    int(h.tokenSvc.AccessTokenExpiry().Seconds()),
		User:         *user,
	}, nil
}

// ============================================================
// Todo Routes
// ============================================================

func (h *Handler) HandleTodos(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimRight(r.URL.Path, "/")

	// POST /todos/{id}/image
	if strings.HasSuffix(r.URL.Path, "/image") || strings.HasSuffix(r.URL.Path, "/image/") {
		if r.Method == http.MethodPost {
			h.uploadTodoImage(w, r)
			return
		}
		methodNotAllowed(w)
		return
	}

	if path == "/todos" {
		switch r.Method {
		case http.MethodGet:
			h.listTodos(w, r)
		case http.MethodPost:
			h.createTodo(w, r)
		default:
			methodNotAllowed(w)
		}
		return
	}

	// /todos/{id}
	switch r.Method {
	case http.MethodGet:
		h.getTodo(w, r)
	case http.MethodPut, http.MethodPatch:
		h.updateTodo(w, r)
	case http.MethodDelete:
		h.deleteTodo(w, r)
	default:
		methodNotAllowed(w)
	}
}

func (h *Handler) listTodos(w http.ResponseWriter, r *http.Request) {
	userID := mw.GetUserID(r.Context())

	var completed *bool
	if q := r.URL.Query().Get("completed"); q != "" {
		val := q == "true"
		completed = &val
	}

	todos, err := h.store.ListTodos(r.Context(), userID, completed)
	if err != nil {
		log.Printf("listTodos error: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to list todos")
		return
	}
	if todos == nil {
		todos = []model.Todo{}
	}
	respondOK(w, todos)
}

func (h *Handler) getTodo(w http.ResponseWriter, r *http.Request) {
	userID := mw.GetUserID(r.Context())
	todoID := extractID(r.URL.Path, "/todos/")

	todo, err := h.store.GetTodo(r.Context(), userID, todoID)
	if err != nil {
		log.Printf("getTodo error: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to get todo")
		return
	}
	if todo == nil {
		respondError(w, http.StatusNotFound, "Todo not found")
		return
	}
	respondOK(w, todo)
}

func (h *Handler) createTodo(w http.ResponseWriter, r *http.Request) {
	userID := mw.GetUserID(r.Context())

	var req model.CreateTodoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	req.Title = validator.SanitiseString(req.Title, 500)
	req.Description = validator.SanitiseString(req.Description, 5000)

	if req.Title == "" {
		respondError(w, http.StatusBadRequest, "Title is required")
		return
	}
	if req.Priority != "" && !validator.ValidPriority(req.Priority) {
		respondError(w, http.StatusBadRequest, "Priority must be low, medium, or high")
		return
	}

	todo, err := h.store.CreateTodo(r.Context(), userID, req)
	if err != nil {
		log.Printf("createTodo error: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to create todo")
		return
	}
	respondCreated(w, todo)
}

func (h *Handler) updateTodo(w http.ResponseWriter, r *http.Request) {
	userID := mw.GetUserID(r.Context())
	todoID := extractID(r.URL.Path, "/todos/")

	var req model.UpdateTodoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	if req.Title != nil {
		trimmed := validator.SanitiseString(*req.Title, 500)
		if trimmed == "" {
			respondError(w, http.StatusBadRequest, "Title cannot be empty")
			return
		}
		req.Title = &trimmed
	}
	if req.Description != nil {
		trimmed := validator.SanitiseString(*req.Description, 5000)
		req.Description = &trimmed
	}
	if req.Priority != nil && !validator.ValidPriority(*req.Priority) {
		respondError(w, http.StatusBadRequest, "Priority must be low, medium, or high")
		return
	}

	todo, err := h.store.UpdateTodo(r.Context(), userID, todoID, req)
	if err != nil {
		log.Printf("updateTodo error: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to update todo")
		return
	}
	if todo == nil {
		respondError(w, http.StatusNotFound, "Todo not found")
		return
	}
	respondOK(w, todo)
}

func (h *Handler) deleteTodo(w http.ResponseWriter, r *http.Request) {
	userID := mw.GetUserID(r.Context())
	todoID := extractID(r.URL.Path, "/todos/")

	deleted, err := h.store.DeleteTodo(r.Context(), userID, todoID)
	if err != nil {
		log.Printf("deleteTodo error: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to delete todo")
		return
	}
	if deleted == nil {
		respondError(w, http.StatusNotFound, "Todo not found")
		return
	}

	// Clean up image file if any
	if deleted.ImagePath != nil {
		_ = h.uploader.Delete(*deleted.ImagePath)
	}

	respondMsg(w, "Todo deleted successfully")
}

// POST /todos/{id}/image — multipart image upload
func (h *Handler) uploadTodoImage(w http.ResponseWriter, r *http.Request) {
	userID := mw.GetUserID(r.Context())
	// Extract ID from /todos/{id}/image
	path := strings.TrimPrefix(r.URL.Path, "/todos/")
	parts := strings.SplitN(path, "/", 2)
	todoID := parts[0]

	// Verify ownership
	existing, err := h.store.GetTodo(r.Context(), userID, todoID)
	if err != nil {
		log.Printf("uploadImage db error: %v", err)
		respondError(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if existing == nil {
		respondError(w, http.StatusNotFound, "Todo not found")
		return
	}

	// Upload image
	filename, err := h.uploader.HandleUpload(r)
	if err != nil {
		switch err {
		case upload.ErrFileTooLarge:
			respondError(w, http.StatusRequestEntityTooLarge, "File too large (max 5MB)")
		case upload.ErrInvalidType:
			respondError(w, http.StatusBadRequest, "Only JPEG, PNG, GIF, and WebP images are allowed")
		default:
			log.Printf("upload error: %v", err)
			respondError(w, http.StatusInternalServerError, "Failed to upload image")
		}
		return
	}

	// Delete old image if replacing
	if existing.ImagePath != nil {
		_ = h.uploader.Delete(*existing.ImagePath)
	}

	todo, err := h.store.SetTodoImage(r.Context(), userID, todoID, filename)
	if err != nil {
		log.Printf("setTodoImage error: %v", err)
		_ = h.uploader.Delete(filename) // rollback
		respondError(w, http.StatusInternalServerError, "Failed to save image")
		return
	}
	respondOK(w, todo)
}
