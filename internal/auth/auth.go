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
)

type RegisterRequest struct {
	UUID         string `json:"uuid"`
	IdentityKey  string `json:"identity_key"`
	CaptchaToken string `json:"captcha_token"`
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

// Register handles user registration (UUID + Identity Key)
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	if req.UUID == "" || req.IdentityKey == "" {
		http.Error(w, `{"error":"Missing UUID or Identity Key"}`, http.StatusBadRequest)
		return
	}

	// Verify Captcha
	ok, err := VerifyTurnstile(req.CaptchaToken)
	if err != nil || !ok {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"Captcha verification failed or suspected spam"}`))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Insert new user into database
	query := `
		INSERT INTO users (id, identity_key) 
		VALUES ($1, $2)
		ON CONFLICT (id) 
		DO UPDATE SET identity_key = EXCLUDED.identity_key
	`
	_, err = h.db.Exec(ctx, query, req.UUID, req.IdentityKey)
	if err != nil {
		log.Printf("Failed to save user to database: %v\n", err)
		http.Error(w, `{"error":"Internal server error during registration"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"message":"Registration successful"}`))
}
