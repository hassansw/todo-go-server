# ─── Stage 1: Build ───────────────────────────────────────────
FROM golang:1.22-alpine AS builder

# Install git (needed for go mod download with VCS deps)
RUN apk add --no-cache git

WORKDIR /app

# Cache module downloads separately from source
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build a fully-static binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /todo-server .

# ─── Stage 2: Run ─────────────────────────────────────────────
FROM alpine:3.19

# ca-certificates needed for TLS outbound connections
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Non-root user for security
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

COPY --from=builder /todo-server /app/todo-server

# Upload directory lives inside the container; mount a volume in prod
RUN mkdir -p /app/uploads && chown -R appuser:appgroup /app

USER appuser

EXPOSE 8080

ENTRYPOINT ["/app/todo-server"]
