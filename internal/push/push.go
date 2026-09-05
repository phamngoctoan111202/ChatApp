package push

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"chat-app/internal/auth"

	"github.com/jackc/pgx/v5/pgxpool"
)

type RegisterPushTokenRequest struct {
	PushToken string `json:"push_token"`
	Platform  string `json:"platform"` // 'android', 'ios', 'desktop'
}

type PushHandler struct {
	db *pgxpool.Pool
}

func NewPushHandler(db *pgxpool.Pool) *PushHandler {
	return &PushHandler{db: db}
}

// RegisterPushToken updates FCM/APNs push token for the authenticated device
func (h *PushHandler) RegisterPushToken(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserIDFromContext(r.Context())
	deviceID := auth.GetDeviceIDFromContext(r.Context())

	if userID == "" {
		http.Error(w, `{"error":"Unauthorized request context"}`, http.StatusUnauthorized)
		return
	}

	var req RegisterPushTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PushToken == "" {
		http.Error(w, `{"error":"Missing push_token parameter"}`, http.StatusBadRequest)
		return
	}

	platform := req.Platform
	if platform == "" {
		platform = "unknown"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `
		UPDATE devices 
		SET push_token = $1, platform = $2, last_seen = CURRENT_TIMESTAMP
		WHERE user_id = $3 AND device_id = $4
	`
	res, err := h.db.Exec(ctx, query, req.PushToken, platform, userID, deviceID)
	if err != nil {
		http.Error(w, `{"error":"Failed to update push token"}`, http.StatusInternalServerError)
		return
	}

	if res.RowsAffected() == 0 {
		http.Error(w, `{"error":"Device not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message":"Push token registered successfully"}`))
}

// SendPushNotification triggers a silent FCM/APNs push notification to wake up an offline device
func SendPushNotification(ctx context.Context, db *pgxpool.Pool, userID string, deviceID int, payloadSummary string) {
	var pushToken, platform string
	err := db.QueryRow(ctx, "SELECT push_token, platform FROM devices WHERE user_id = $1 AND device_id = $2", userID, deviceID).Scan(&pushToken, &platform)
	if err != nil || pushToken == "" {
		return // Device has no registered push token
	}

	// Log push notification trigger (FCM / APNs gateway abstraction)
	log.Printf("[PUSH NOTIFICATION] Waking up offline user %s (device %d, platform: %s) via Token: %s... Payload: %s\n",
		userID, deviceID, platform, pushToken[:min(10, len(pushToken))]+"...", payloadSummary)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
