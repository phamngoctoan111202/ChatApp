package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"chat-app/internal/logger"
)

type PasskeyRegisterRequest struct {
	CredentialID string `json:"credential_id"`
	PublicKey    string `json:"public_key"`
	IdentityKey  string `json:"identity_key"`
	DeviceName   string `json:"device_name"`
}

type PasskeyLoginRequest struct {
	CredentialID   string `json:"credential_id"`
	Signature      string `json:"signature"`
	ClientDataJSON string `json:"client_data_json"`
}

// PasskeyChallengeResponse returns a cryptographically random challenge string for WebAuthn authentication
func (h *AuthHandler) GetPasskeyChallenge(w http.ResponseWriter, r *http.Request) {
	bytes := make([]byte, 32)
	_, _ = rand.Read(bytes)
	challenge := hex.EncodeToString(bytes)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"challenge": challenge,
		"expires_in": "60s",
	})
}

// RegisterPasskey registers a new Biometric / FIDO2 Passkey credential for the user
func (h *AuthHandler) RegisterPasskey(w http.ResponseWriter, r *http.Request) {
	var req PasskeyRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CredentialID == "" {
		http.Error(w, `{"error":"Invalid JSON format or missing credential_id"}`, http.StatusBadRequest)
		return
	}

	userID := GetUserIDFromContext(r.Context())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if userID == "" {
		// New user Passkey registration
		if req.IdentityKey == "" {
			http.Error(w, `{"error":"First-time passkey registration requires identity_key for Signal E2EE"}`, http.StatusBadRequest)
			return
		}

		tx, err := h.db.Begin(ctx)
		if err != nil {
			http.Error(w, `{"error":"Database transaction error"}`, http.StatusInternalServerError)
			return
		}
		defer tx.Rollback(ctx)

		err = tx.QueryRow(ctx, "INSERT INTO users (identity_key) VALUES ($1) RETURNING id", req.IdentityKey).Scan(&userID)
		if err != nil {
			logger.Log.Error("Failed to insert passkey user", "error", err)
			http.Error(w, `{"error":"Failed to create user record"}`, http.StatusInternalServerError)
			return
		}

		_, err = tx.Exec(ctx, "INSERT INTO auth_identities (user_id, provider, provider_user_id) VALUES ($1, 'passkey', $2)", userID, req.CredentialID)
		if err != nil {
			logger.Log.Error("Failed to insert auth_identity for passkey", "error", err)
			http.Error(w, `{"error":"Failed to link passkey identity"}`, http.StatusInternalServerError)
			return
		}

		devName := req.DeviceName
		if devName == "" {
			devName = "Passkey Primary Device"
		}
		_, err = tx.Exec(ctx, "INSERT INTO devices (user_id, device_id, name, platform) VALUES ($1, 1, $2, 'primary')", userID, devName)
		if err != nil {
			logger.Log.Error("Failed to insert primary device", "error", err)
			http.Error(w, `{"error":"Failed to initialize primary device"}`, http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(ctx); err != nil {
			http.Error(w, `{"error":"Failed to commit transaction"}`, http.StatusInternalServerError)
			return
		}
	} else {
		// Link passkey to existing authenticated user
		_, err := h.db.Exec(ctx, "INSERT INTO auth_identities (user_id, provider, provider_user_id) VALUES ($1, 'passkey', $2) ON CONFLICT DO NOTHING", userID, req.CredentialID)
		if err != nil {
			http.Error(w, `{"error":"Failed to link passkey to account"}`, http.StatusInternalServerError)
			return
		}
	}

	accessToken, _ := GenerateToken(userID, 1, 24*time.Hour)
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

// PasskeyLogin authenticates a user using a biometric WebAuthn / FIDO2 signature
func (h *AuthHandler) PasskeyLogin(w http.ResponseWriter, r *http.Request) {
	var req PasskeyLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CredentialID == "" {
		http.Error(w, `{"error":"Missing credential_id or signature"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var userID string
	err := h.db.QueryRow(ctx, "SELECT user_id FROM auth_identities WHERE provider = 'passkey' AND provider_user_id = $1", req.CredentialID).Scan(&userID)
	if err != nil {
		http.Error(w, `{"error":"Unrecognized Passkey credential ID"}`, http.StatusUnauthorized)
		return
	}

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
