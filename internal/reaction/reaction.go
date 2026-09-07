package reaction

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"chat-app/internal/auth"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AddReactionRequest struct {
	MessageID string `json:"message_id"`
	Emoji     string `json:"emoji"`
}

type RemoveReactionRequest struct {
	MessageID string `json:"message_id"`
	Emoji     string `json:"emoji"`
}

type ReactionSummaryDTO struct {
	Emoji string   `json:"emoji"`
	Count int      `json:"count"`
	Users []string `json:"users"`
}

type ReactionHandler struct {
	db *pgxpool.Pool
}

func NewReactionHandler(db *pgxpool.Pool) *ReactionHandler {
	return &ReactionHandler{db: db}
}

// AddReaction adds an emoji reaction to a message
func (h *ReactionHandler) AddReaction(w http.ResponseWriter, r *http.Request) {
	callerID := auth.GetUserIDFromContext(r.Context())
	if callerID == "" {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var req AddReactionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.MessageID == "" || req.Emoji == "" {
		http.Error(w, `{"error":"Invalid payload, message_id and emoji required"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `
		INSERT INTO message_reactions (message_id, user_id, emoji)
		VALUES ($1, $2, $3)
		ON CONFLICT (message_id, user_id, emoji)
		DO UPDATE SET created_at = CURRENT_TIMESTAMP
	`
	_, err := h.db.Exec(ctx, query, req.MessageID, callerID, req.Emoji)
	if err != nil {
		http.Error(w, `{"error":"Failed to add reaction"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message_id": req.MessageID,
		"emoji":      req.Emoji,
		"message":    "Reaction added successfully",
	})
}

// RemoveReaction removes an emoji reaction from a message
func (h *ReactionHandler) RemoveReaction(w http.ResponseWriter, r *http.Request) {
	callerID := auth.GetUserIDFromContext(r.Context())
	if callerID == "" {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var req RemoveReactionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.MessageID == "" || req.Emoji == "" {
		http.Error(w, `{"error":"Invalid payload, message_id and emoji required"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `DELETE FROM message_reactions WHERE message_id = $1 AND user_id = $2 AND emoji = $3`
	_, err := h.db.Exec(ctx, query, req.MessageID, callerID, req.Emoji)
	if err != nil {
		http.Error(w, `{"error":"Failed to remove reaction"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message":"Reaction removed successfully"}`))
}

// GetMessageReactions returns aggregated emoji reactions for a target message
func (h *ReactionHandler) GetMessageReactions(w http.ResponseWriter, r *http.Request) {
	messageID := chi.URLParam(r, "message_id")
	if messageID == "" {
		http.Error(w, `{"error":"Missing message_id"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `SELECT emoji, user_id FROM message_reactions WHERE message_id = $1 ORDER BY created_at ASC`
	rows, err := h.db.Query(ctx, query, messageID)
	if err != nil {
		http.Error(w, `{"error":"Failed to query reactions"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	summaryMap := make(map[string][]string)
	for rows.Next() {
		var emoji, uid string
		if err := rows.Scan(&emoji, &uid); err == nil {
			summaryMap[emoji] = append(summaryMap[emoji], uid)
		}
	}

	var summaries []ReactionSummaryDTO
	for emoji, users := range summaryMap {
		summaries = append(summaries, ReactionSummaryDTO{
			Emoji: emoji,
			Count: len(users),
			Users: users,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message_id": messageID,
		"reactions":  summaries,
	})
}
