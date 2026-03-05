# TODO Server — Production-Grade Secure Go API

A security-hardened REST API built with **Go stdlib `net/http`**, **`database/sql` + pgx v5**, and **PostgreSQL**.

## Security Features

| Feature | Implementation |
|---|---|
| **Authentication** | JWT access tokens (short-lived, 15 min) |
| **Refresh Tokens** | Opaque random tokens, SHA-256 hashed in DB, rotation on use |
| **Password Hashing** | bcrypt (cost 12) with timing-attack mitigation on login |
| **SQL Injection** | 100% parameterised queries (`$1`, `$2`) — zero string concatenation |
| **Input Validation** | Email (RFC 5322), password strength, field length limits, sanitisation |
| **File Upload** | Content-type sniffing (not trusting headers), UUID filenames, path traversal prevention |
| **Rate Limiting** | Per-IP token bucket (10 req/s default, configurable) |
| **Security Headers** | HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy |
| **CORS** | Configurable allowed origins |
| **Request Size** | Max body size enforcement |
| **Graceful Shutdown** | SIGINT/SIGTERM handling, connection draining |
| **Token Cleanup** | Background job cleans expired/revoked refresh tokens hourly |
| **Data Isolation** | All todo queries scoped to authenticated `user_id` |
| **Panic Recovery** | Middleware catches panics, returns 500 |
| **HTTP Timeouts** | Read, Write, Idle timeouts configured |

## Quick Start

```bash
# 1. Create database
createdb tododb

# 2. Set required env
export JWT_SECRET="your-secret-key-at-least-32-chars-long"
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/tododb?sslmode=disable"

# 3. Run
cd todo-server-secure
go mod tidy
go run ./cmd/server
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `JWT_SECRET` | **(required)** | HMAC signing key for JWT tokens |
| `DATABASE_URL` | `postgres://postgres:postgres@localhost:5432/tododb?sslmode=disable` | PostgreSQL connection string |
| `PORT` | `8080` | Server port |
| `ACCESS_TOKEN_EXPIRY` | `15m` | JWT access token lifetime |
| `REFRESH_TOKEN_EXPIRY` | `168h` | Refresh token lifetime (7 days) |
| `UPLOAD_DIR` | `./uploads` | Directory for uploaded images |
| `MAX_UPLOAD_SIZE_MB` | `5` | Max image upload size in MB |
| `RATE_LIMIT` | `10` | Requests per second per IP |
| `RATE_BURST` | `20` | Rate limit burst allowance |
| `ALLOWED_ORIGIN` | `http://localhost:3000` | CORS allowed origin |
| `BCRYPT_COST` | `12` | bcrypt hash cost |

## API Reference

### Public Endpoints

#### `POST /auth/register`
```bash
curl -s -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "password": "SecurePass1",
    "name": "Alice"
  }' | jq
```
Response:
```json
{
  "data": {
    "access_token": "eyJhbGciOi...",
    "refresh_token": "a1b2c3d4e5...",
    "expires_in": 900,
    "user": { "id": 1, "email": "alice@example.com", "name": "Alice", ... }
  }
}
```

#### `POST /auth/login`
```bash
curl -s -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "SecurePass1"}' | jq
```

#### `POST /auth/refresh`
```bash
curl -s -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "a1b2c3d4e5..."}' | jq
```
The old refresh token is revoked and a new pair is issued (rotation).

#### `POST /auth/logout`
```bash
curl -s -X POST http://localhost:8080/auth/logout \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "a1b2c3d4e5..."}' | jq
```

### Protected Endpoints

All require `Authorization: Bearer <access_token>`.

```bash
TOKEN="eyJhbGciOi..."
```

#### `GET /todos`
```bash
curl -s http://localhost:8080/todos -H "Authorization: Bearer $TOKEN" | jq

# Filter by completion
curl -s "http://localhost:8080/todos?completed=false" -H "Authorization: Bearer $TOKEN" | jq
```

#### `POST /todos`
```bash
curl -s -X POST http://localhost:8080/todos \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title": "Deploy v2", "description": "Push to prod", "priority": "high"}' | jq
```

#### `GET /todos/{id}`
```bash
curl -s http://localhost:8080/todos/1 -H "Authorization: Bearer $TOKEN" | jq
```

#### `PUT /todos/{id}`
```bash
curl -s -X PUT http://localhost:8080/todos/1 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"completed": true}' | jq
```

#### `DELETE /todos/{id}`
```bash
curl -s -X DELETE http://localhost:8080/todos/1 -H "Authorization: Bearer $TOKEN" | jq
```

#### `POST /todos/{id}/image`
```bash
curl -s -X POST http://localhost:8080/todos/1/image \
  -H "Authorization: Bearer $TOKEN" \
  -F "image=@photo.jpg" | jq
```
The image is validated (JPEG, PNG, GIF, WebP only — verified by content sniffing, not file extension), saved with a random UUID filename, and the URL is returned in the todo's `image_url` field. Accessible at `GET /uploads/{filename}`.

## Project Structure

```
todo-server-secure/
├── cmd/
│   └── server/
│       └── main.go              # Entry point, wiring, startup
├── internal/
│   ├── auth/
│   │   └── auth.go              # JWT + bcrypt + refresh token generation
│   ├── config/
│   │   └── config.go            # Env-based configuration
│   ├── handler/
│   │   └── handler.go           # HTTP handlers (auth + todos)
│   ├── middleware/
│   │   └── middleware.go         # Security headers, CORS, rate limit, auth, logging
│   ├── model/
│   │   └── model.go             # Domain types + request/response structs
│   ├── store/
│   │   └── store.go             # Database operations (all parameterised)
│   ├── upload/
│   │   └── upload.go            # Secure file upload with content sniffing
│   └── validator/
│       └── validator.go         # Input validation + sanitisation
├── uploads/                     # Uploaded images (gitignore this)
├── go.mod
└── README.md
```

## Security Design Notes

**Why short-lived access tokens?** The 15-minute access token means a compromised token has a limited window. The refresh token (7 day, stored hashed in DB) can be revoked server-side instantly.

**Why refresh token rotation?** Each time a refresh token is used, the old one is revoked and a new one is issued. If an attacker replays a stolen refresh token after the legitimate user has already rotated it, the request fails — and you know the token was compromised.

**Why SHA-256 for refresh tokens but bcrypt for passwords?** Refresh tokens are high-entropy random values (32 bytes), so a fast hash is sufficient — they can't be brute-forced. Passwords are low-entropy human-chosen values, so they need the intentional slowness of bcrypt.

**Why content sniffing on uploads?** File extensions and `Content-Type` headers can be trivially spoofed. `http.DetectContentType` reads the actual file magic bytes to verify the real type.

**Why UUID filenames?** Prevents path traversal attacks, prevents filename collisions, and doesn't leak any user information in the URL.
