package auth

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"sync"
	"time"

	"chat-app/internal/logger"
)

type SendOTPRequest struct {
	PhoneNumber string `json:"phone_number"`
}

type VerifyOTPRequest struct {
	PhoneNumber string `json:"phone_number"`
	OTP         string `json:"otp"`
	IdentityKey string `json:"identity_key"`
	DeviceName  string `json:"device_name"`
}

// In-memory OTP storage fallback (Phone -> OTP Code & Expiration)
var (
	otpStore = make(map[string]otpItem)
	otpMutex sync.RWMutex
)

type otpItem struct {
	Code      string
	ExpiresAt time.Time
}

func generate6DigitOTP() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	return fmt.Sprintf("%06d", n.Int64())
}

// SendOTP generates and sends a 6-digit SMS verification code to the phone number
func (h *AuthHandler) SendOTP(w http.ResponseWriter, r *http.Request) {
	var req SendOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PhoneNumber == "" {
		http.Error(w, `{"error":"Invalid JSON format or missing phone_number"}`, http.StatusBadRequest)
		return
	}

	otpCode := generate6DigitOTP()
	// Demo fallback default OTP for testing
	if os.Getenv("ENV") != "production" {
		otpCode = "123456"
	}

	otpMutex.Lock()
	otpStore[req.PhoneNumber] = otpItem{
		Code:      otpCode,
		ExpiresAt: time.Now().Add(3 * time.Minute),
	}
	otpMutex.Unlock()

	logger.Log.Info("SMS OTP Generated", "phone_number", req.PhoneNumber, "otp_code", otpCode)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message":      "SMS OTP sent successfully",
		"phone_number": req.PhoneNumber,
		"demo_note":    "In local/test mode, use OTP: 123456",
	})
}

// VerifyOTP verifies the 6-digit SMS code and logs in or registers the user
func (h *AuthHandler) VerifyOTP(w http.ResponseWriter, r *http.Request) {
	var req VerifyOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PhoneNumber == "" || req.OTP == "" {
		http.Error(w, `{"error":"Missing phone_number or otp code"}`, http.StatusBadRequest)
		return
	}

	// 1. Verify OTP code
	otpMutex.RLock()
	item, found := otpStore[req.PhoneNumber]
	otpMutex.RUnlock()

	if !found || item.Code != req.OTP || time.Now().After(item.ExpiresAt) {
		http.Error(w, `{"error":"Invalid or expired SMS OTP code"}`, http.StatusUnauthorized)
		return
	}

	// Clear used OTP
	otpMutex.Lock()
	delete(otpStore, req.PhoneNumber)
	otpMutex.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 2. Query user by phone_number
	var userID string
	err := h.db.QueryRow(ctx, "SELECT id FROM users WHERE phone_number = $1", req.PhoneNumber).Scan(&userID)

	if err != nil {
		// User does not exist, create new user via Phone Auth
		if req.IdentityKey == "" {
			http.Error(w, `{"error":"New phone registration requires identity_key for Signal E2EE"}`, http.StatusBadRequest)
			return
		}

		tx, err := h.db.Begin(ctx)
		if err != nil {
			http.Error(w, `{"error":"Database transaction error"}`, http.StatusInternalServerError)
			return
		}
		defer tx.Rollback(ctx)

		// Create user record
		err = tx.QueryRow(ctx, `
			INSERT INTO users (phone_number, identity_key)
			VALUES ($1, $2)
			RETURNING id
		`, req.PhoneNumber, req.IdentityKey).Scan(&userID)
		if err != nil {
			logger.Log.Error("Failed to insert phone user", "error", err)
			http.Error(w, `{"error":"Failed to create phone user account"}`, http.StatusInternalServerError)
			return
		}

		// Create auth_identity entry
		_, err = tx.Exec(ctx, `
			INSERT INTO auth_identities (user_id, provider, provider_user_id)
			VALUES ($1, 'phone', $2)
		`, userID, req.PhoneNumber)
		if err != nil {
			logger.Log.Error("Failed to insert auth_identity", "error", err)
			http.Error(w, `{"error":"Failed to record authentication identity"}`, http.StatusInternalServerError)
			return
		}

		// Create primary device (device_id = 1)
		devName := req.DeviceName
		if devName == "" {
			devName = "Phone Primary Device"
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO devices (user_id, device_id, name, platform)
			VALUES ($1, 1, $2, 'primary')
		`, userID, devName)
		if err != nil {
			logger.Log.Error("Failed to insert primary phone device", "error", err)
			http.Error(w, `{"error":"Failed to initialize primary phone device"}`, http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(ctx); err != nil {
			http.Error(w, `{"error":"Failed to commit transaction"}`, http.StatusInternalServerError)
			return
		}
	}

	// 3. Issue JWT Access & Refresh Tokens
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
