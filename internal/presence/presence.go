package presence

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PresenceDTO struct {
	UserID   string    `json:"user_id"`
	IsOnline bool      `json:"is_online"`
	LastSeen time.Time `json:"last_seen"`
}

type PresenceHandler struct {
	db *pgxpool.Pool
}

func NewPresenceHandler(db *pgxpool.Pool) *PresenceHandler {
	return &PresenceHandler{db: db}
}

// GetUserPresence retrieves the online/offline presence status and last seen timestamp of a user
func (h *PresenceHandler) GetUserPresence(w http.ResponseWriter, r *http.Request) {
	targetUserID := chi.URLParam(r, "id")
	if targetUserID == "" {
		http.Error(w, `{"error":"Missing user id"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var dto PresenceDTO
	dto.UserID = targetUserID

	query := `SELECT COALESCE(is_online, FALSE), COALESCE(last_seen, CURRENT_TIMESTAMP) FROM users WHERE id = $1`
	err := h.db.QueryRow(ctx, query, targetUserID).Scan(&dto.IsOnline, &dto.LastSeen)
	if err != nil {
		http.Error(w, `{"error":"User not found or failed to query presence"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dto)
}

// SetUserPresence updates DB state when user connects or disconnects
func SetUserPresence(db *pgxpool.Pool, userID string, isOnline bool) {
	if db == nil || userID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `UPDATE users SET is_online = $1, last_seen = CURRENT_TIMESTAMP WHERE id = $2`
	_, _ = db.Exec(ctx, query, isOnline, userID)
}
