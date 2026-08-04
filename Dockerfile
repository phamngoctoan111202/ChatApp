# --- Stage 1: Build Stage ---
FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o chat-server cmd/server/main.go

# --- Stage 2: Final Run Stage ---
FROM alpine:latest  

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /root/

COPY --from=builder /app/chat-server .

EXPOSE 8080

CMD ["./chat-server"]
