# Stage 1: Build the Go binary from source
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy dependency manifests and download modules
COPY go.mod go.sum ./
RUN go mod download

# Copy source code and build binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o chat-server ./cmd/server/main.go

# Stage 2: Minimal runtime image
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /root/

# Copy compiled binary from builder stage
COPY --from=builder /app/chat-server .

EXPOSE 8080

CMD ["./chat-server"]
