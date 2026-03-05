package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"todo-server-secure/internal/auth"
	"todo-server-secure/internal/config"
	"todo-server-secure/internal/handler"
	mw "todo-server-secure/internal/middleware"
	"todo-server-secure/internal/store"
	"todo-server-secure/internal/upload"

	"github.com/joho/godotenv"
)

func main() {
	// ---------- Load .env (ignored if file absent) ----------
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, reading from environment")
	}

	// ---------- Config ----------
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Config error: %v", err)
	}

	// ---------- Database ----------
	db, err := store.New(cfg.DatabaseURL, cfg.DBMaxOpen, cfg.DBMaxIdle, cfg.DBMaxLife)
	if err != nil {
		log.Fatalf("Database error: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := db.Migrate(ctx); err != nil {
		log.Fatalf("Migration error: %v", err)
	}
	log.Println("Database migrated")

	// ---------- Services ----------
	tokenSvc := auth.NewTokenService(
		cfg.JWTSecret,
		cfg.AccessTokenExpiry,
		cfg.RefreshTokenExpiry,
		cfg.BcryptCost,
	)

	uploader, err := upload.NewService(cfg.UploadDir, cfg.MaxUploadSize)
	if err != nil {
		log.Fatalf("Upload service error: %v", err)
	}

	h := handler.New(db, tokenSvc, uploader)

	// ---------- Routes ----------
	mux := http.NewServeMux()

	// Public routes
	mux.HandleFunc("/health", h.HandleHealth)
	mux.HandleFunc("/auth/", h.HandleAuth)
	mux.HandleFunc("/auth/register", h.HandleAuth)
	mux.HandleFunc("/auth/login", h.HandleAuth)
	mux.HandleFunc("/auth/refresh", h.HandleAuth)
	mux.HandleFunc("/auth/logout", h.HandleAuth)

	// Serve uploaded images (static files with restricted path)
	fileServer := http.StripPrefix("/uploads/", http.FileServer(http.Dir(cfg.UploadDir)))
	mux.Handle("/uploads/", fileServer)

	// Protected routes — wrap with auth middleware
	authMux := http.NewServeMux()
	authMux.HandleFunc("/todos", h.HandleTodos)
	authMux.HandleFunc("/todos/", h.HandleTodos)

	protectedHandler := mw.Auth(tokenSvc)(authMux)
	mux.Handle("/todos", protectedHandler)
	mux.Handle("/todos/", protectedHandler)

	// ---------- Global Middleware Stack ----------
	var finalHandler http.Handler = mux
	finalHandler = mw.Chain(finalHandler,
		mw.Recover,
		mw.Logging,
		mw.SecurityHeaders,
		mw.CORS(cfg.AllowedOrigins),
		mw.RateLimit(cfg.RateLimit, cfg.RateBurst),
		mw.MaxBodySize(cfg.MaxUploadSize+1024*1024), // upload size + 1MB overhead
	)

	// ---------- HTTP Server ----------
	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      finalHandler,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,

		// Limit header size to prevent abuse
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	// ---------- Background: clean expired tokens ----------
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 30*time.Second)
			n, err := db.CleanExpiredTokens(cleanCtx)
			cleanCancel()
			if err != nil {
				log.Printf("Token cleanup error: %v", err)
			} else if n > 0 {
				log.Printf("Cleaned %d expired/revoked refresh tokens", n)
			}
		}
	}()

	// ---------- Graceful Shutdown ----------
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		log.Printf("Received %v, shutting down...", sig)

		shutCtx, shutCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer shutCancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			log.Fatalf("Forced shutdown: %v", err)
		}
	}()

	// ---------- Start ----------
	fmt.Printf(`
===========================================
  TODO Server (Secure) — net/http + pgx
===========================================
  Port:        %s
  Upload dir:  %s
  Max upload:  %d MB
  Rate limit:  %.0f req/s (burst %d)
===========================================

  PUBLIC ENDPOINTS:
    GET    /health
    POST   /auth/register
    POST   /auth/login
    POST   /auth/refresh
    POST   /auth/logout
    GET    /uploads/{filename}

  PROTECTED ENDPOINTS (Bearer token):
    GET    /todos              ?completed=true|false
    POST   /todos
    GET    /todos/{id}
    PUT    /todos/{id}
    DELETE /todos/{id}
    POST   /todos/{id}/image   (multipart: field "image")

===========================================
`, cfg.Port, cfg.UploadDir, cfg.MaxUploadSize/(1024*1024), cfg.RateLimit, cfg.RateBurst)

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
	log.Println("Server stopped gracefully")
}
