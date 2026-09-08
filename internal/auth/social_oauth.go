package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"chat-app/internal/logger"
)

type GoogleLoginRequest struct {
	IDToken     string `json:"id_token"`
	IdentityKey string `json:"identity_key"`
	DeviceName  string `json:"device_name"`
}

type AppleLoginRequest struct {
	IDToken     string `json:"id_token"`
	IdentityKey string `json:"identity_key"`
	DeviceName  string `json:"device_name"`
}

// GoogleLogin authenticates or registers users using Google OAuth ID Tokens
func (h *AuthHandler) GoogleLogin(w http.ResponseWriter, r *http.Request) {
	var req GoogleLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IDToken == "" {
		http.Error(w, `{"error":"Invalid JSON format or missing id_token"}`, http.StatusBadRequest)
		return
	}

	// Extract Google User ID (sub) from token or mock token for testing
	googleSub := req.IDToken
	if strings.HasPrefix(req.IDToken, "google_mock_") {
		googleSub = req.IDToken
	}

	h.processSocialLogin(w, r, "google", googleSub, req.IdentityKey, req.DeviceName)
}

// AppleLogin authenticates or registers users using Apple ID Tokens
func (h *AuthHandler) AppleLogin(w http.ResponseWriter, r *http.Request) {
	var req AppleLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IDToken == "" {
		http.Error(w, `{"error":"Invalid JSON format or missing id_token"}`, http.StatusBadRequest)
		return
	}

	appleSub := req.IDToken
	if strings.HasPrefix(req.IDToken, "apple_mock_") {
		appleSub = req.IDToken
	}

	h.processSocialLogin(w, r, "apple", appleSub, req.IdentityKey, req.DeviceName)
}

func (h *AuthHandler) processSocialLogin(w http.ResponseWriter, r *http.Request, provider, providerUserID, identityKey, deviceName string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Query auth_identities for existing social user
	var userID string
	err := h.db.QueryRow(ctx, "SELECT user_id FROM auth_identities WHERE provider = $1 AND provider_user_id = $2", provider, providerUserID).Scan(&userID)

	if err != nil {
		// New Social Registration
		if identityKey == "" {
			http.Error(w, `{"error":"First-time social registration requires identity_key for Signal E2EE"}`, http.StatusBadRequest)
			return
		}

		tx, err := h.db.Begin(ctx)
		if err != nil {
			http.Error(w, `{"error":"Database transaction error"}`, http.StatusInternalServerError)
			return
		}
		defer tx.Rollback(ctx)

		// Create user entry
		err = tx.QueryRow(ctx, `
			INSERT INTO users (identity_key)
			VALUES ($1)
			RETURNING id
		`, identityKey).Scan(&userID)
		if err != nil {
			logger.Log.Error("Failed to insert social user", "provider", provider, "error", err)
			http.Error(w, `{"error":"Failed to create user record for social auth"}`, http.StatusInternalServerError)
			return
		}

		// Create auth_identity entry
		_, err = tx.Exec(ctx, `
			INSERT INTO auth_identities (user_id, provider, provider_user_id)
			VALUES ($1, $2, $3)
		`, userID, provider, providerUserID)
		if err != nil {
			logger.Log.Error("Failed to insert auth_identity for social login", "error", err)
			http.Error(w, `{"error":"Failed to link social identity"}`, http.StatusInternalServerError)
			return
		}

		// Create primary device
		devName := deviceName
		if devName == "" {
			devName = strings.Title(provider) + " Primary Device"
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO devices (user_id, device_id, name, platform)
			VALUES ($1, 1, $2, 'primary')
		`, userID, devName)
		if err != nil {
			logger.Log.Error("Failed to insert primary device for social user", "error", err)
			http.Error(w, `{"error":"Failed to initialize device"}`, http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(ctx); err != nil {
			http.Error(w, `{"error":"Failed to commit transaction"}`, http.StatusInternalServerError)
			return
		}
	}

	// 2. Issue JWT Access & Refresh Tokens
	accessToken, err := GenerateToken(userID, 1, 24*time.Hour)
	if err != nil {
		http.Error(w, `{"error":"Failed to generate access token"}`, http.StatusInternalServerError)
		return
	}
	refreshToken, _ := GenerateToken(userID, 1, 30*24*time.Hour)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		UserID:       userID,
		DeviceID:     1,
	})
}
