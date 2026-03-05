package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	// Server
	Port            string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration

	// Database
	DatabaseURL string
	DBMaxOpen   int
	DBMaxIdle   int
	DBMaxLife   time.Duration

	// JWT
	JWTSecret          string
	AccessTokenExpiry   time.Duration
	RefreshTokenExpiry  time.Duration

	// Upload
	UploadDir     string
	MaxUploadSize int64 // bytes

	// Rate Limiting
	RateLimit       float64 // requests per second
	RateBurst       int

	// CORS
	AllowedOrigins []string

	// Security
	BcryptCost int
}

func Load() (*Config, error) {
	jwtSecret := getEnv("JWT_SECRET", "")
	if jwtSecret == "" {
		return nil, fmt.Errorf("JWT_SECRET environment variable is required")
	}

	return &Config{
		// Server
		Port:            getEnv("PORT", "8080"),
		ReadTimeout:     getDurationEnv("READ_TIMEOUT", 10*time.Second),
		WriteTimeout:    getDurationEnv("WRITE_TIMEOUT", 15*time.Second),
		IdleTimeout:     getDurationEnv("IDLE_TIMEOUT", 60*time.Second),
		ShutdownTimeout: getDurationEnv("SHUTDOWN_TIMEOUT", 15*time.Second),

		// Database
		DatabaseURL: getEnv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/tododb?sslmode=disable"),
		DBMaxOpen:   getIntEnv("DB_MAX_OPEN", 25),
		DBMaxIdle:   getIntEnv("DB_MAX_IDLE", 10),
		DBMaxLife:   getDurationEnv("DB_MAX_LIFE", 5*time.Minute),

		// JWT
		JWTSecret:          jwtSecret,
		AccessTokenExpiry:  getDurationEnv("ACCESS_TOKEN_EXPIRY", 15*time.Minute),
		RefreshTokenExpiry: getDurationEnv("REFRESH_TOKEN_EXPIRY", 7*24*time.Hour),

		// Upload
		UploadDir:     getEnv("UPLOAD_DIR", "./uploads"),
		MaxUploadSize: int64(getIntEnv("MAX_UPLOAD_SIZE_MB", 5)) * 1024 * 1024,

		// Rate Limiting
		RateLimit: getFloatEnv("RATE_LIMIT", 10),
		RateBurst: getIntEnv("RATE_BURST", 20),

		// CORS
		AllowedOrigins: []string{getEnv("ALLOWED_ORIGIN", "http://localhost:3000")},

		// Security
		BcryptCost: getIntEnv("BCRYPT_COST", 12),
	}, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getIntEnv(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}

func getFloatEnv(key string, fallback float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return fallback
}

func getDurationEnv(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
