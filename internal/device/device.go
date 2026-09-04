package device

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"chat-app/internal/auth"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DeviceDTO struct {
	DeviceID int       `json:"device_id"`
	Name     string    `json:"name"`
	Platform string    `json:"platform"`
	LastSeen time.Time `json:"last_seen"`
}

type LinkDeviceRequest struct {
	DeviceName string `json:"device_name"`
	Platform   string `json:"platform"`
}

type DeviceHandler struct {
	db *pgxpool.Pool
}

func NewDeviceHandler(db *pgxpool.Pool) *DeviceHandler {
	return &DeviceHandler{db: db}
}

// ListDevices returns all linked devices of the authenticated user
func (h *DeviceHandler) ListDevices(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserIDFromContext(r.Context())
	if userID == "" {
		http.Error(w, `{"error":"Unauthorized request context"}`, http.StatusUnauthorized)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := h.db.Query(ctx, "SELECT device_id, name, platform, last_seen FROM devices WHERE user_id = $1 ORDER BY device_id ASC", userID)
	if err != nil {
		http.Error(w, `{"error":"Failed to query device list"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var devices []DeviceDTO
	for rows.Next() {
		var d DeviceDTO
		if err := rows.Scan(&d.DeviceID, &d.Name, &d.Platform, &d.LastSeen); err == nil {
			devices = append(devices, d)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user_id": userID,
		"devices": devices,
	})
}

// LinkDevice links a new secondary device (Desktop/Tablet) to the user's account
func (h *DeviceHandler) LinkDevice(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserIDFromContext(r.Context())
	if userID == "" {
		http.Error(w, `{"error":"Unauthorized request context"}`, http.StatusUnauthorized)
		return
	}

	var req LinkDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Calculate next available device_id for this user
	var maxDeviceID int
	_ = h.db.QueryRow(ctx, "SELECT COALESCE(MAX(device_id), 0) FROM devices WHERE user_id = $1", userID).Scan(&maxDeviceID)
	newDeviceID := maxDeviceID + 1

	devName := req.DeviceName
	if devName == "" {
		devName = "Linked Device " + strconv.Itoa(newDeviceID)
	}
	platform := req.Platform
	if platform == "" {
		platform = "secondary"
	}

	query := `
		INSERT INTO devices (user_id, device_id, name, platform)
		VALUES ($1, $2, $3, $4)
	`
	_, err := h.db.Exec(ctx, query, userID, newDeviceID, devName, platform)
	if err != nil {
		http.Error(w, `{"error":"Failed to link new device to account"}`, http.StatusInternalServerError)
		return
	}

	// Generate access token for the newly linked secondary device
	accessToken, err := auth.GenerateToken(userID, newDeviceID, 30*24*time.Hour)
	if err != nil {
		http.Error(w, `{"error":"Failed to generate access token for device"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":      "Device linked successfully",
		"device_id":    newDeviceID,
		"access_token": accessToken,
	})
}

// UnlinkDevice removes/unlinks a secondary device from the user's account
func (h *DeviceHandler) UnlinkDevice(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserIDFromContext(r.Context())
	deviceIDStr := chi.URLParam(r, "device_id")

	if deviceIDStr == "1" {
		http.Error(w, `{"error":"Cannot unlink primary phone device"}`, http.StatusForbidden)
		return
	}

	deviceID, err := strconv.Atoi(deviceIDStr)
	if err != nil {
		http.Error(w, `{"error":"Invalid device_id parameter"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := h.db.Exec(ctx, "DELETE FROM devices WHERE user_id = $1 AND device_id = $2", userID, deviceID)
	if err != nil {
		http.Error(w, `{"error":"Failed to delete device"}`, http.StatusInternalServerError)
		return
	}

	if res.RowsAffected() == 0 {
		http.Error(w, `{"error":"Device not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message":"Device unlinked successfully"}`))
}
