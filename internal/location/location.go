package location

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"chat-app/internal/auth"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ShareLocationRequest struct {
	Latitude        float64 `json:"latitude"`
	Longitude       float64 `json:"longitude"`
	DurationMinutes int     `json:"duration_minutes"` // Default 60 mins if omitted or <= 0
}

type LiveLocationDTO struct {
	UserID    string    `json:"user_id"`
	Latitude  float64   `json:"latitude"`
	Longitude float64   `json:"longitude"`
	ExpiresAt time.Time `json:"expires_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type LocationHandler struct {
	db *pgxpool.Pool
}

func NewLocationHandler(db *pgxpool.Pool) *LocationHandler {
	return &LocationHandler{db: db}
}

// ShareLocation updates or starts live location sharing for the authenticated user
func (h *LocationHandler) ShareLocation(w http.ResponseWriter, r *http.Request) {
	callerID := auth.GetUserIDFromContext(r.Context())
	if callerID == "" {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var req ShareLocationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid payload"}`, http.StatusBadRequest)
		return
	}

	if req.DurationMinutes <= 0 {
		req.DurationMinutes = 60 // default 1 hour
	}

	expiresAt := time.Now().Add(time.Duration(req.DurationMinutes) * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `
		INSERT INTO live_locations (user_id, latitude, longitude, expires_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id)
		DO UPDATE SET latitude = EXCLUDED.latitude, longitude = EXCLUDED.longitude, expires_at = EXCLUDED.expires_at, updated_at = CURRENT_TIMESTAMP
	`
	_, err := h.db.Exec(ctx, query, callerID, req.Latitude, req.Longitude, expiresAt)
	if err != nil {
		http.Error(w, `{"error":"Failed to update live location"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":    "Live location updated successfully",
		"latitude":   req.Latitude,
		"longitude":  req.Longitude,
		"expires_at": expiresAt,
	})
}

// GetLocation retrieves active live location of a target user
func (h *LocationHandler) GetLocation(w http.ResponseWriter, r *http.Request) {
	targetUserID := chi.URLParam(r, "user_id")
	if targetUserID == "" {
		http.Error(w, `{"error":"Missing user_id"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var dto LiveLocationDTO
	query := `
		SELECT user_id, latitude, longitude, expires_at, updated_at
		FROM live_locations
		WHERE user_id = $1 AND expires_at > CURRENT_TIMESTAMP
	`
	err := h.db.QueryRow(ctx, query, targetUserID).Scan(&dto.UserID, &dto.Latitude, &dto.Longitude, &dto.ExpiresAt, &dto.UpdatedAt)
	if err != nil {
		http.Error(w, `{"error":"Live location not available or expired"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dto)
}

// StopSharing stops live location sharing for caller
func (h *LocationHandler) StopSharing(w http.ResponseWriter, r *http.Request) {
	callerID := auth.GetUserIDFromContext(r.Context())
	if callerID == "" {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `DELETE FROM live_locations WHERE user_id = $1`
	_, err := h.db.Exec(ctx, query, callerID)
	if err != nil {
		http.Error(w, `{"error":"Failed to stop location sharing"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message":"Live location sharing stopped"}`))
}
