package block

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"chat-app/internal/auth"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type BlockRequest struct {
	TargetUserID string `json:"target_user_id"`
	Mode         string `json:"mode"` // "block" or "restrict"
}

type BlockedUserDTO struct {
	BlockedID string    `json:"blocked_id"`
	Mode      string    `json:"mode"`
	CreatedAt time.Time `json:"created_at"`
}

type BlockHandler struct {
	db *pgxpool.Pool
}

func NewBlockHandler(db *pgxpool.Pool) *BlockHandler {
	return &BlockHandler{db: db}
}

// BlockUser blocks or restricts a target user
func (h *BlockHandler) BlockUser(w http.ResponseWriter, r *http.Request) {
	callerID := auth.GetUserIDFromContext(r.Context())
	if callerID == "" {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var req BlockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.TargetUserID == "" {
		http.Error(w, `{"error":"Invalid payload, missing target_user_id"}`, http.StatusBadRequest)
		return
	}

	if req.TargetUserID == callerID {
		http.Error(w, `{"error":"Cannot block yourself"}`, http.StatusBadRequest)
		return
	}

	if req.Mode != "restrict" {
		req.Mode = "block"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `
		INSERT INTO blocked_users (blocker_id, blocked_id, mode)
		VALUES ($1, $2, $3)
		ON CONFLICT (blocker_id, blocked_id)
		DO UPDATE SET mode = EXCLUDED.mode, created_at = CURRENT_TIMESTAMP
	`
	_, err := h.db.Exec(ctx, query, callerID, req.TargetUserID, req.Mode)
	if err != nil {
		http.Error(w, `{"error":"Failed to block user"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":        "User status updated",
		"target_user_id": req.TargetUserID,
		"mode":           req.Mode,
	})
}

// UnblockUser removes a block or restriction from a target user
func (h *BlockHandler) UnblockUser(w http.ResponseWriter, r *http.Request) {
	callerID := auth.GetUserIDFromContext(r.Context())
	targetUserID := chi.URLParam(r, "user_id")

	if callerID == "" || targetUserID == "" {
		http.Error(w, `{"error":"Missing user_id parameter"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `DELETE FROM blocked_users WHERE blocker_id = $1 AND blocked_id = $2`
	_, err := h.db.Exec(ctx, query, callerID, targetUserID)
	if err != nil {
		http.Error(w, `{"error":"Failed to unblock user"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message":"User unblocked successfully"}`))
}

// ListBlockedUsers returns list of users blocked or restricted by the caller
func (h *BlockHandler) ListBlockedUsers(w http.ResponseWriter, r *http.Request) {
	callerID := auth.GetUserIDFromContext(r.Context())
	if callerID == "" {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `SELECT blocked_id, mode, created_at FROM blocked_users WHERE blocker_id = $1 ORDER BY created_at DESC`
	rows, err := h.db.Query(ctx, query, callerID)
	if err != nil {
		http.Error(w, `{"error":"Failed to list blocked users"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var blockedList []BlockedUserDTO
	for rows.Next() {
		var item BlockedUserDTO
		if err := rows.Scan(&item.BlockedID, &item.Mode, &item.CreatedAt); err == nil {
			blockedList = append(blockedList, item)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"blocked_users": blockedList,
	})
}

// IsBlocked checks if recipient has blocked or restricted sender
func IsBlocked(db *pgxpool.Pool, blockerID, senderID string) (isBlocked bool, mode string) {
	if db == nil || blockerID == "" || senderID == "" {
		return false, ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	query := `SELECT mode FROM blocked_users WHERE blocker_id = $1 AND blocked_id = $2`
	err := db.QueryRow(ctx, query, blockerID, senderID).Scan(&mode)
	if err != nil {
		return false, ""
	}
	return true, mode
}
