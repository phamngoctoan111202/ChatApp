package device

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"chat-app/internal/auth"
	"chat-app/internal/logger"
)

type QRSession struct {
	SessionID   string    `json:"qr_session_id"`
	Approved    bool      `json:"approved"`
	UserID      string    `json:"user_id,omitempty"`
	DeviceID    int       `json:"device_id,omitempty"`
	AccessToken string    `json:"access_token,omitempty"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type ApproveQRRequest struct {
	QRSessionID string `json:"qr_session_id"`
	DeviceName  string `json:"device_name"`
	Platform    string `json:"platform"`
}

var (
	qrSessions = make(map[string]*QRSession)
	qrMutex    sync.RWMutex
)

// GenerateQRSession creates a temporary QR code session for Web/Desktop device linking
func (h *DeviceHandler) GenerateQRSession(w http.ResponseWriter, r *http.Request) {
	bytes := make([]byte, 16)
	_, _ = rand.Read(bytes)
	sessionID := hex.EncodeToString(bytes)

	session := &QRSession{
		SessionID: sessionID,
		Approved:  false,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	qrMutex.Lock()
	qrSessions[sessionID] = session
	qrMutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"qr_session_id": sessionID,
		"qr_payload":    "chatapp://link-device?session=" + sessionID,
		"expires_in":    "300s",
	})
}

// ApproveQRSession handles primary phone scanning and approving secondary device QR link
func (h *DeviceHandler) ApproveQRSession(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserIDFromContext(r.Context())
	if userID == "" {
		http.Error(w, `{"error":"Unauthorized request context"}`, http.StatusUnauthorized)
		return
	}

	var req ApproveQRRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.QRSessionID == "" {
		http.Error(w, `{"error":"Invalid JSON format or missing qr_session_id"}`, http.StatusBadRequest)
		return
	}

	qrMutex.Lock()
	session, exists := qrSessions[req.QRSessionID]
	if !exists || time.Now().After(session.ExpiresAt) {
		qrMutex.Unlock()
		http.Error(w, `{"error":"Expired or invalid QR session"}`, http.StatusUnauthorized)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Calculate next available secondary device_id
	var maxDeviceID int
	_ = h.db.QueryRow(ctx, "SELECT COALESCE(MAX(device_id), 0) FROM devices WHERE user_id = $1", userID).Scan(&maxDeviceID)
	newDeviceID := maxDeviceID + 1

	devName := req.DeviceName
	if devName == "" {
		devName = "QR Linked Device " + strconv.Itoa(newDeviceID)
	}
	platform := req.Platform
	if platform == "" {
		platform = "secondary_qr"
	}

	_, err := h.db.Exec(ctx, "INSERT INTO devices (user_id, device_id, name, platform) VALUES ($1, $2, $3, $4)", userID, newDeviceID, devName, platform)
	if err != nil {
		qrMutex.Unlock()
		logger.Log.Error("Failed to insert QR linked device", "error", err)
		http.Error(w, `{"error":"Failed to link secondary device"}`, http.StatusInternalServerError)
		return
	}

	accessToken, _ := auth.GenerateToken(userID, newDeviceID, 30*24*time.Hour)

	session.Approved = true
	session.UserID = userID
	session.DeviceID = newDeviceID
	session.AccessToken = accessToken
	qrMutex.Unlock()

	logger.Log.Info("QR Device Linking Approved", "user_id", userID, "new_device_id", newDeviceID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":      "QR Device linked successfully",
		"device_id":    newDeviceID,
		"access_token": accessToken,
	})
}

// GetQRSessionStatus checks if QR session has been approved by primary phone
func (h *DeviceHandler) GetQRSessionStatus(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		http.Error(w, `{"error":"Missing session_id query parameter"}`, http.StatusBadRequest)
		return
	}

	qrMutex.RLock()
	session, exists := qrSessions[sessionID]
	qrMutex.RUnlock()

	if !exists || time.Now().After(session.ExpiresAt) {
		http.Error(w, `{"error":"Expired or invalid QR session"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(session)
}
