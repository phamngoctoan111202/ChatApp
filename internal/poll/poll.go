package poll

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"chat-app/internal/auth"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type CreatePollRequest struct {
	GroupID            string   `json:"group_id,omitempty"`
	QuestionCiphertext string   `json:"question_ciphertext"`
	Options            []string `json:"options"`
}

type CastVoteRequest struct {
	OptionIndex int `json:"option_index"`
}

type PollDTO struct {
	ID                 string         `json:"id"`
	GroupID            *string        `json:"group_id,omitempty"`
	CreatorID          string         `json:"creator_id"`
	QuestionCiphertext string         `json:"question_ciphertext"`
	Options            []string       `json:"options"`
	VoteCounts         map[int]int    `json:"vote_counts"`
	UserVote           *int           `json:"user_vote,omitempty"`
	CreatedAt          time.Time      `json:"created_at"`
}

type PollHandler struct {
	db *pgxpool.Pool
}

func NewPollHandler(db *pgxpool.Pool) *PollHandler {
	return &PollHandler{db: db}
}

// CreatePoll creates a new group/chat vote poll
func (h *PollHandler) CreatePoll(w http.ResponseWriter, r *http.Request) {
	callerID := auth.GetUserIDFromContext(r.Context())
	if callerID == "" {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var req CreatePollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.QuestionCiphertext == "" || len(req.Options) < 2 {
		http.Error(w, `{"error":"Invalid payload, minimum 2 options required"}`, http.StatusBadRequest)
		return
	}

	optionsJSON, err := json.Marshal(req.Options)
	if err != nil {
		http.Error(w, `{"error":"Failed to process poll options"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var pollID string
	var groupIDParam *string
	if req.GroupID != "" {
		groupIDParam = &req.GroupID
	}

	query := `
		INSERT INTO polls (group_id, creator_id, question_ciphertext, options_json)
		VALUES ($1, $2, $3, $4)
		RETURNING id
	`
	err = h.db.QueryRow(ctx, query, groupIDParam, callerID, req.QuestionCiphertext, optionsJSON).Scan(&pollID)
	if err != nil {
		http.Error(w, `{"error":"Failed to create poll"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"poll_id":  pollID,
		"message":  "Poll created successfully",
	})
}

// CastVote records or updates a user's vote for a poll
func (h *PollHandler) CastVote(w http.ResponseWriter, r *http.Request) {
	callerID := auth.GetUserIDFromContext(r.Context())
	pollID := chi.URLParam(r, "id")

	if callerID == "" || pollID == "" {
		http.Error(w, `{"error":"Missing poll_id or unauthorized"}`, http.StatusBadRequest)
		return
	}

	var req CastVoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.OptionIndex < 0 {
		http.Error(w, `{"error":"Invalid option_index"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `
		INSERT INTO poll_votes (poll_id, user_id, option_index)
		VALUES ($1, $2, $3)
		ON CONFLICT (poll_id, user_id)
		DO UPDATE SET option_index = EXCLUDED.option_index, created_at = CURRENT_TIMESTAMP
	`
	_, err := h.db.Exec(ctx, query, pollID, callerID, req.OptionIndex)
	if err != nil {
		http.Error(w, `{"error":"Failed to record vote"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message":"Vote cast successfully"}`))
}

// GetPoll returns poll details and aggregated vote tallies
func (h *PollHandler) GetPoll(w http.ResponseWriter, r *http.Request) {
	callerID := auth.GetUserIDFromContext(r.Context())
	pollID := chi.URLParam(r, "id")

	if pollID == "" {
		http.Error(w, `{"error":"Missing poll_id"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var dto PollDTO
	var optionsRaw []byte

	query := `SELECT id, group_id, creator_id, question_ciphertext, options_json, created_at FROM polls WHERE id = $1`
	err := h.db.QueryRow(ctx, query, pollID).Scan(&dto.ID, &dto.GroupID, &dto.CreatorID, &dto.QuestionCiphertext, &optionsRaw, &dto.CreatedAt)
	if err != nil {
		http.Error(w, `{"error":"Poll not found"}`, http.StatusNotFound)
		return
	}

	_ = json.Unmarshal(optionsRaw, &dto.Options)
	dto.VoteCounts = make(map[int]int)

	// Fetch vote counts for each option
	rows, err := h.db.Query(ctx, `SELECT option_index, COUNT(*) FROM poll_votes WHERE poll_id = $1 GROUP BY option_index`, pollID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var idx, count int
			if err := rows.Scan(&idx, &count); err == nil {
				dto.VoteCounts[idx] = count
			}
		}
	}

	// Fetch user's own vote if caller is authenticated
	if callerID != "" {
		var userVote int
		err := h.db.QueryRow(ctx, `SELECT option_index FROM poll_votes WHERE poll_id = $1 AND user_id = $2`, pollID, callerID).Scan(&userVote)
		if err == nil {
			dto.UserVote = &userVote
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dto)
}
