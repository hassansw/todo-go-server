package upload

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

var (
	ErrFileTooLarge   = errors.New("file exceeds maximum size")
	ErrInvalidType    = errors.New("invalid file type; only JPEG, PNG, GIF, and WebP are allowed")
	ErrUploadFailed   = errors.New("failed to save uploaded file")
)

// Allowed MIME types and their canonical extensions.
var allowedTypes = map[string]string{
	"image/jpeg": ".jpg",
	"image/png":  ".png",
	"image/gif":  ".gif",
	"image/webp": ".webp",
}

type Service struct {
	uploadDir   string
	maxFileSize int64
}

func NewService(uploadDir string, maxFileSize int64) (*Service, error) {
	// Ensure upload directory exists with restrictive permissions.
	if err := os.MkdirAll(uploadDir, 0750); err != nil {
		return nil, fmt.Errorf("create upload dir: %w", err)
	}
	return &Service{uploadDir: uploadDir, maxFileSize: maxFileSize}, nil
}

// HandleUpload reads the "image" field from a multipart form, validates, and
// saves it with a random UUID filename. Returns the relative storage path.
func (s *Service) HandleUpload(r *http.Request) (string, error) {
	// Limit total request body
	r.Body = http.MaxBytesReader(nil, r.Body, s.maxFileSize+1024) // +1KB for form overhead

	if err := r.ParseMultipartForm(s.maxFileSize); err != nil {
		return "", ErrFileTooLarge
	}

	file, header, err := r.FormFile("image")
	if err != nil {
		return "", fmt.Errorf("read form file: %w", err)
	}
	defer file.Close()

	// Check declared size
	if header.Size > s.maxFileSize {
		return "", ErrFileTooLarge
	}

	// Read first 512 bytes to sniff real content type (don't trust header)
	buf := make([]byte, 512)
	n, err := file.Read(buf)
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("read file header: %w", err)
	}
	detectedType := http.DetectContentType(buf[:n])

	ext, ok := allowedTypes[detectedType]
	if !ok {
		return "", ErrInvalidType
	}

	// Seek back to start after sniffing
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("seek file: %w", err)
	}

	// Generate a safe random filename — prevents path traversal and collisions
	filename := uuid.New().String() + ext
	destPath := filepath.Join(s.uploadDir, filename)

	// Verify the final path is still within the upload directory (defence in depth)
	absDir, _ := filepath.Abs(s.uploadDir)
	absDest, _ := filepath.Abs(destPath)
	if !strings.HasPrefix(absDest, absDir+string(os.PathSeparator)) {
		return "", fmt.Errorf("path traversal detected")
	}

	// Write to disk with restrictive permissions
	dst, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0640)
	if err != nil {
		return "", ErrUploadFailed
	}
	defer dst.Close()

	// Copy with size limit
	written, err := io.Copy(dst, io.LimitReader(file, s.maxFileSize))
	if err != nil {
		os.Remove(destPath) // clean up partial file
		return "", ErrUploadFailed
	}
	if written > s.maxFileSize {
		os.Remove(destPath)
		return "", ErrFileTooLarge
	}

	return filename, nil
}

// Delete removes an uploaded file by filename.
func (s *Service) Delete(filename string) error {
	if filename == "" {
		return nil
	}
	path := filepath.Join(s.uploadDir, filepath.Base(filename)) // Base() prevents traversal
	return os.Remove(path)
}
