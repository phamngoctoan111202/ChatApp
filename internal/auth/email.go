package auth

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"chat-app/internal/email"
	"chat-app/internal/logger"
	"golang.org/x/crypto/bcrypt"
)

type SendEmailOTPRequest struct {
	Email string `json:"email"`
}

type RegisterEmailRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	OTP         string `json:"otp"`
	IdentityKey string `json:"identity_key"`
	DeviceName  string `json:"device_name"`
}

type LoginEmailRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	IdentityKey string `json:"identity_key"`
	DeviceName  string `json:"device_name"`
}

// In-memory store for Email OTP verification
var (
	emailOTPStore = make(map[string]emailOTPItem)
	emailOTPMutex sync.RWMutex
)

type emailOTPItem struct {
	Code      string
	ExpiresAt time.Time
}

func generate6DigitCode() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	return fmt.Sprintf("%06d", n.Int64())
}

// SendEmailOTP generates and sends a 6-digit OTP code to the recipient's email address
func (h *AuthHandler) SendEmailOTP(w http.ResponseWriter, r *http.Request) {
	var req SendEmailOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Email) == "" {
		http.Error(w, `{"error":"Invalid JSON format or missing email"}`, http.StatusBadRequest)
		return
	}

	cleanEmail := strings.ToLower(strings.TrimSpace(req.Email))
	otpCode := generate6DigitCode()

	emailOTPMutex.Lock()
	emailOTPStore[cleanEmail] = emailOTPItem{
		Code:      otpCode,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	emailOTPMutex.Unlock()

	// Send email async
	go func() {
		_ = email.SendEmailOTP(cleanEmail, otpCode)
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "OTP verification code sent to " + cleanEmail,
		"email":   cleanEmail,
	})
}

// RegisterWithEmail verifies Email OTP, hashes password with bcrypt, creates user record in PostgreSQL, and issues JWT tokens
func (h *AuthHandler) RegisterWithEmail(w http.ResponseWriter, r *http.Request) {
	var req RegisterEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	cleanEmail := strings.ToLower(strings.TrimSpace(req.Email))
	if cleanEmail == "" || req.Password == "" {
		http.Error(w, `{"error":"Missing email or password"}`, http.StatusBadRequest)
		return
	}

	// 1. Verify OTP Code if provided
	if req.OTP != "" {
		emailOTPMutex.RLock()
		item, found := emailOTPStore[cleanEmail]
		emailOTPMutex.RUnlock()

		if !found || item.Code != req.OTP || time.Now().After(item.ExpiresAt) {
			http.Error(w, `{"error":"Invalid or expired email OTP code"}`, http.StatusUnauthorized)
			return
		}

		emailOTPMutex.Lock()
		delete(emailOTPStore, cleanEmail)
		emailOTPMutex.Unlock()
	}

	// 2. Hash Password using bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, `{"error":"Failed to hash password"}`, http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 3. Create or fetch User in PostgreSQL
	var userID string
	err = h.db.QueryRow(ctx, "SELECT id FROM users WHERE email = $1 OR username = $1", cleanEmail).Scan(&userID)

	if err == nil {
		http.Error(w, `{"error":"Email address already registered"}`, http.StatusConflict)
		return
	}

	err = h.db.QueryRow(ctx,
		"INSERT INTO users (username, email, password_hash, email_verified, created_at) VALUES ($1, $1, $2, TRUE, NOW()) RETURNING id",
		cleanEmail, string(hashedPassword),
	).Scan(&userID)

	if err != nil {
		logger.Log.Error("Failed to create user with email", "err", err)
		http.Error(w, `{"error":"Failed to create user account"}`, http.StatusInternalServerError)
		return
	}

	// 4. Register Primary Device (device_id = 1)
	deviceName := req.DeviceName
	if deviceName == "" {
		deviceName = "Android Device"
	}

	_, _ = h.db.Exec(ctx, `
		INSERT INTO devices (user_id, device_id, device_name, created_at, last_seen)
		VALUES ($1, 1, $2, NOW(), NOW())
		ON CONFLICT (user_id, device_id) DO UPDATE SET last_seen = NOW()
	`, userID, deviceName)

	// 5. Register Signal Protocol Identity Key
	if req.IdentityKey != "" {
		_, _ = h.db.Exec(ctx, `
			INSERT INTO identity_keys (user_id, device_id, identity_key)
			VALUES ($1, 1, $2)
			ON CONFLICT (user_id, device_id) DO UPDATE SET identity_key = $2
		`, userID, req.IdentityKey)
	}

	// 6. Generate Access & Refresh JWT Tokens
	accessToken, refreshToken, err := GenerateTokenPair(userID, 1)
	if err != nil {
		http.Error(w, `{"error":"Failed to generate JWT tokens"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		UserID:       userID,
		DeviceID:     1,
	})
}

// LoginWithEmail verifies email and bcrypt password, then returns JWT tokens
func (h *AuthHandler) LoginWithEmail(w http.ResponseWriter, r *http.Request) {
	var req LoginEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	cleanEmail := strings.ToLower(strings.TrimSpace(req.Email))
	if cleanEmail == "" || req.Password == "" {
		http.Error(w, `{"error":"Missing email or password"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var userID string
	var storedPasswordHash string
	err := h.db.QueryRow(ctx, "SELECT id, password_hash FROM users WHERE email = $1 OR username = $1", cleanEmail).Scan(&userID, &storedPasswordHash)

	if err != nil || storedPasswordHash == "" {
		http.Error(w, `{"error":"Invalid email or password"}`, http.StatusUnauthorized)
		return
	}

	// Verify bcrypt password hash
	if err := bcrypt.CompareHashAndPassword([]byte(storedPasswordHash), []byte(req.Password)); err != nil {
		http.Error(w, `{"error":"Invalid email or password"}`, http.StatusUnauthorized)
		return
	}

	deviceName := req.DeviceName
	if deviceName == "" {
		deviceName = "Android Device"
	}

	_, _ = h.db.Exec(ctx, `
		INSERT INTO devices (user_id, device_id, device_name, created_at, last_seen)
		VALUES ($1, 1, $2, NOW(), NOW())
		ON CONFLICT (user_id, device_id) DO UPDATE SET last_seen = NOW()
	`, userID, deviceName)

	if req.IdentityKey != "" {
		_, _ = h.db.Exec(ctx, `
			INSERT INTO identity_keys (user_id, device_id, identity_key)
			VALUES ($1, 1, $2)
			ON CONFLICT (user_id, device_id) DO UPDATE SET identity_key = $2
		`, userID, req.IdentityKey)
	}

	accessToken, refreshToken, err := GenerateTokenPair(userID, 1)
	if err != nil {
		http.Error(w, `{"error":"Failed to generate JWT tokens"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		UserID:       userID,
		DeviceID:     1,
	})
}
