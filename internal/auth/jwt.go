package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type JWTClaims struct {
	UserID   string `json:"user_id"`
	DeviceID int    `json:"device_id"`
	Exp      int64  `json:"exp"`
}

func getJWTSecret() []byte {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "signal-lite-default-secret-key-change-in-prod"
	}
	return []byte(secret)
}

// GenerateToken generates HMAC-SHA256 JWT Token with user_id, device_id and expiration duration
func GenerateToken(userID string, deviceID int, duration time.Duration) (string, error) {
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	headerBytes, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)

	claims := JWTClaims{
		UserID:   userID,
		DeviceID: deviceID,
		Exp:      time.Now().Add(duration).Unix(),
	}
	claimsBytes, _ := json.Marshal(claims)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsBytes)

	unsignedToken := fmt.Sprintf("%s.%s", headerB64, claimsB64)

	h := hmac.New(sha256.New, getJWTSecret())
	h.Write([]byte(unsignedToken))
	signatureB64 := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return fmt.Sprintf("%s.%s", unsignedToken, signatureB64), nil
}

// GenerateTokenPair generates access and refresh tokens
func GenerateTokenPair(userID string, deviceID int) (string, string, error) {
	accessToken, err := GenerateToken(userID, deviceID, 24*time.Hour)
	if err != nil {
		return "", "", err
	}
	refreshToken, err := GenerateToken(userID, deviceID, 30*24*time.Hour)
	if err != nil {
		return "", "", err
	}
	return accessToken, refreshToken, nil
}

// VerifyToken checks HMAC-SHA256 signature and expiration of a JWT Token
func VerifyToken(tokenStr string) (*JWTClaims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	unsignedToken := fmt.Sprintf("%s.%s", parts[0], parts[1])
	h := hmac.New(sha256.New, getJWTSecret())
	h.Write([]byte(unsignedToken))
	expectedSig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		return nil, errors.New("invalid token signature")
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var claims JWTClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, err
	}

	if time.Now().Unix() > claims.Exp {
		return nil, errors.New("token has expired")
	}

	return &claims, nil
}

// AuthMiddleware validates Authorization Bearer JWT Token and populates user_id & device_id in context
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, `{"error":"Unauthorized: Missing or invalid token format"}`, http.StatusUnauthorized)
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := VerifyToken(tokenStr)
		if err != nil {
			http.Error(w, `{"error":"Unauthorized: `+err.Error()+`"}`, http.StatusUnauthorized)
			return
		}

		// Inject user_id and device_id into Request Context
		ctx := r.Context()
		ctx = setContextValue(ctx, "user_id", claims.UserID)
		ctx = setContextValue(ctx, "device_id", claims.DeviceID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type contextKey string

func setContextValue(ctx context.Context, key string, val interface{}) context.Context {
	return context.WithValue(ctx, contextKey(key), val)
}

func GetUserIDFromContext(ctx context.Context) string {
	if val, ok := ctx.Value(contextKey("user_id")).(string); ok {
		return val
	}
	return ""
}

func GetDeviceIDFromContext(ctx context.Context) int {
	if val, ok := ctx.Value(contextKey("device_id")).(int); ok {
		return val
	}
	return 1
}
