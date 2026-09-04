package auth

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

type RegisterRequest struct {
	Username     string `json:"username"`
	Password     string `json:"password"`
	IdentityKey  string `json:"identity_key"`
	DeviceName   string `json:"device_name"`
	CaptchaToken string `json:"captcha_token"`
}

type LoginRequest struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	DeviceName string `json:"device_name"`
}

type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	UserID       string `json:"user_id"`
	DeviceID     int    `json:"device_id"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type AuthHandler struct {
	db *pgxpool.Pool
}

func NewAuthHandler(db *pgxpool.Pool) *AuthHandler {
	return &AuthHandler{db: db}
}

// VerifyTurnstile verifies captcha token with Cloudflare API
func VerifyTurnstile(token string) (bool, error) {
	secret := os.Getenv("TURNSTILE_SECRET")
	if secret == "" {
		// Skip verification if secret is not configured (dev environment)
		return true, nil
	}

	apiURL := "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	data := url.Values{}
	data.Set("secret", secret)
	data.Set("response", token)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.PostForm(apiURL, data)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var result struct {
		Success bool     `json:"success"`
		Errors  []string `json:"error-codes"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}

	return result.Success, nil
}

// Register handles user registration with username, password, identity key, and creates Primary Device (device_id = 1)
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" || req.IdentityKey == "" {
		http.Error(w, `{"error":"Missing required fields: username, password, or identity_key"}`, http.StatusBadRequest)
		return
	}

	// Verify Captcha
	ok, err := VerifyTurnstile(req.CaptchaToken)
	if err != nil || !ok {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"Captcha verification failed or suspected spam"}`))
		return
	}

	// Hash password using bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Password hashing failed: %v\n", err)
		http.Error(w, `{"error":"Internal server error processing security credentials"}`, http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx, err := h.db.Begin(ctx)
	if err != nil {
		http.Error(w, `{"error":"Internal database transaction error"}`, http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(ctx)

	// 1. Insert User
	var userID string
	queryUser := `
		INSERT INTO users (username, password_hash, identity_key) 
		VALUES ($1, $2, $3)
		RETURNING id
	`
	err = tx.QueryRow(ctx, queryUser, req.Username, string(hashedPassword), req.IdentityKey).Scan(&userID)
	if err != nil {
		log.Printf("Failed to insert user: %v\n", err)
		http.Error(w, `{"error":"Username already registered"}`, http.StatusConflict)
		return
	}

	// 2. Create Primary Device (device_id = 1)
	devName := req.DeviceName
	if devName == "" {
		devName = "Primary Device"
	}

	queryDevice := `
		INSERT INTO devices (user_id, device_id, name, platform)
		VALUES ($1, 1, $2, 'primary')
	`
	_, err = tx.Exec(ctx, queryDevice, userID, devName)
	if err != nil {
		log.Printf("Failed to insert primary device: %v\n", err)
		http.Error(w, `{"error":"Failed to initialize primary device"}`, http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(ctx); err != nil {
		http.Error(w, `{"error":"Failed to commit transaction"}`, http.StatusInternalServerError)
		return
	}

	// Issue JWT Tokens
	accessToken, err := GenerateToken(userID, 1, 24*time.Hour)
	if err != nil {
		http.Error(w, `{"error":"Failed to generate access token"}`, http.StatusInternalServerError)
		return
	}
	refreshToken, _ := GenerateToken(userID, 1, 30*24*time.Hour)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		UserID:       userID,
		DeviceID:     1,
	})
}

// Login handles user login with username and password
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		http.Error(w, `{"error":"Missing username or password"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var userID, hashedPassword string
	err := h.db.QueryRow(ctx, "SELECT id, password_hash FROM users WHERE username = $1", req.Username).Scan(&userID, &hashedPassword)
	if err != nil {
		http.Error(w, `{"error":"Invalid username or password"}`, http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password)); err != nil {
		http.Error(w, `{"error":"Invalid username or password"}`, http.StatusUnauthorized)
		return
	}

	// Primary device_id defaults to 1 for standard logins
	deviceID := 1
	accessToken, err := GenerateToken(userID, deviceID, 24*time.Hour)
	if err != nil {
		http.Error(w, `{"error":"Failed to generate access token"}`, http.StatusInternalServerError)
		return
	}
	refreshToken, _ := GenerateToken(userID, deviceID, 30*24*time.Hour)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		UserID:       userID,
		DeviceID:     deviceID,
	})
}

// RefreshToken issues a new access token using a valid refresh token
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
		http.Error(w, `{"error":"Missing refresh token"}`, http.StatusBadRequest)
		return
	}

	claims, err := VerifyToken(req.RefreshToken)
	if err != nil {
		http.Error(w, `{"error":"Invalid or expired refresh token"}`, http.StatusUnauthorized)
		return
	}

	newAccessToken, err := GenerateToken(claims.UserID, claims.DeviceID, 24*time.Hour)
	if err != nil {
		http.Error(w, `{"error":"Failed to generate access token"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"access_token": newAccessToken,
	})
}
