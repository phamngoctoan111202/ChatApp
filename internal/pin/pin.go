package pin

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"chat-app/internal/auth"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PinRequest struct {
	ChatID    string `json:"chat_id"`
	MessageID string `json:"message_id"`
}

type PinnedMessageDTO struct {
	ID        string    `json:"id"`
	ChatID    string    `json:"chat_id"`
	MessageID string    `json:"message_id"`
	PinnedBy  string    `json:"pinned_by"`
	CreatedAt time.Time `json:"created_at"`
}

type PinHandler struct {
	db *pgxpool.Pool
}

func NewPinHandler(db *pgxpool.Pool) *PinHandler {
	return &PinHandler{db: db}
}

// PinMessage pins a message inside a chat or group
func (h *PinHandler) PinMessage(w http.ResponseWriter, r *http.Request) {
	callerID := auth.GetUserIDFromContext(r.Context())
	if callerID == "" {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var req PinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ChatID == "" || req.MessageID == "" {
		http.Error(w, `{"error":"Invalid payload, chat_id and message_id required"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var pinID string
	query := `
		INSERT INTO pinned_messages (chat_id, message_id, pinned_by)
		VALUES ($1, $2, $3)
		ON CONFLICT (chat_id, message_id)
		DO UPDATE SET created_at = CURRENT_TIMESTAMP
		RETURNING id
	`
	err := h.db.QueryRow(ctx, query, req.ChatID, req.MessageID, callerID).Scan(&pinID)
	if err != nil {
		http.Error(w, `{"error":"Failed to pin message"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"pin_id":     pinID,
		"chat_id":    req.ChatID,
		"message_id": req.MessageID,
		"message":    "Message pinned successfully",
	})
}

// UnpinMessage unpins a message from a chat or group
func (h *PinHandler) UnpinMessage(w http.ResponseWriter, r *http.Request) {
	chatID := chi.URLParam(r, "chat_id")
	messageID := chi.URLParam(r, "message_id")

	if chatID == "" || messageID == "" {
		http.Error(w, `{"error":"Missing chat_id or message_id"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `DELETE FROM pinned_messages WHERE chat_id = $1 AND message_id = $2`
	_, err := h.db.Exec(ctx, query, chatID, messageID)
	if err != nil {
		http.Error(w, `{"error":"Failed to unpin message"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message":"Message unpinned successfully"}`))
}

// GetPinnedMessages returns list of pinned messages for a specific chat
func (h *PinHandler) GetPinnedMessages(w http.ResponseWriter, r *http.Request) {
	chatID := chi.URLParam(r, "chat_id")
	if chatID == "" {
		http.Error(w, `{"error":"Missing chat_id"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `SELECT id, chat_id, message_id, pinned_by, created_at FROM pinned_messages WHERE chat_id = $1 ORDER BY created_at DESC`
	rows, err := h.db.Query(ctx, query, chatID)
	if err != nil {
		http.Error(w, `{"error":"Failed to query pinned messages"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var pins []PinnedMessageDTO
	for rows.Next() {
		var dto PinnedMessageDTO
		if err := rows.Scan(&dto.ID, &dto.ChatID, &dto.MessageID, &dto.PinnedBy, &dto.CreatedAt); err == nil {
			pins = append(pins, dto)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"chat_id": chatID,
		"pins":    pins,
	})
}
