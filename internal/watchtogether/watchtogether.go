package watchtogether

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"chat-app/internal/auth"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type WatchSession struct {
	RoomID       string    `json:"room_id"`
	GroupID      string    `json:"group_id,omitempty"`
	HostID       string    `json:"host_id"`
	VideoURL     string    `json:"video_url"`
	PlaybackRate float64   `json:"playback_rate"`
	CurrentTime  float64   `json:"current_time"`
	IsPlaying    bool      `json:"is_playing"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type CreateRoomRequest struct {
	GroupID  string `json:"group_id,omitempty"`
	VideoURL string `json:"video_url"`
}

type SyncStateRequest struct {
	Action       string  `json:"action"` // "play", "pause", "seek", "change_url"
	VideoURL     string  `json:"video_url,omitempty"`
	TimestampSec float64 `json:"timestamp_sec"`
	PlaybackRate float64 `json:"playback_rate,omitempty"`
}

type WatchTogetherHandler struct {
	db       *pgxpool.Pool
	sessions map[string]*WatchSession
	mu       sync.RWMutex
}

func NewWatchTogetherHandler(db *pgxpool.Pool) *WatchTogetherHandler {
	return &WatchTogetherHandler{
		db:       db,
		sessions: make(map[string]*WatchSession),
	}
}

// CreateRoom initializes a new Watch Together room session
func (h *WatchTogetherHandler) CreateRoom(w http.ResponseWriter, r *http.Request) {
	callerID := auth.GetUserIDFromContext(r.Context())
	if callerID == "" {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var req CreateRoomRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.VideoURL == "" {
		http.Error(w, `{"error":"Invalid payload, missing video_url"}`, http.StatusBadRequest)
		return
	}

	roomID := uuid.New().String()
	session := &WatchSession{
		RoomID:       roomID,
		GroupID:      req.GroupID,
		HostID:       callerID,
		VideoURL:     req.VideoURL,
		PlaybackRate: 1.0,
		CurrentTime:  0.0,
		IsPlaying:    true,
		UpdatedAt:    time.Now(),
	}

	h.mu.Lock()
	h.sessions[roomID] = session
	h.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(session)
}

// GetRoomState returns the current playback state of a Watch Together room
func (h *WatchTogetherHandler) GetRoomState(w http.ResponseWriter, r *http.Request) {
	roomID := chi.URLParam(r, "room_id")
	if roomID == "" {
		http.Error(w, `{"error":"Missing room_id"}`, http.StatusBadRequest)
		return
	}

	h.mu.RLock()
	session, exists := h.sessions[roomID]
	h.mu.RUnlock()

	if !exists {
		http.Error(w, `{"error":"Watch Together room not found"}`, http.StatusNotFound)
		return
	}

	// Calculate estimated current playback position if playing
	now := time.Now()
	res := *session
	if res.IsPlaying {
		elapsed := now.Sub(res.UpdatedAt).Seconds() * res.PlaybackRate
		res.CurrentTime += elapsed
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// SyncRoomState updates and syncs current playback state for a room
func (h *WatchTogetherHandler) SyncRoomState(w http.ResponseWriter, r *http.Request) {
	roomID := chi.URLParam(r, "room_id")
	if roomID == "" {
		http.Error(w, `{"error":"Missing room_id"}`, http.StatusBadRequest)
		return
	}

	var req SyncStateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid payload"}`, http.StatusBadRequest)
		return
	}

	h.mu.Lock()
	session, exists := h.sessions[roomID]
	if !exists {
		h.mu.Unlock()
		http.Error(w, `{"error":"Room not found"}`, http.StatusNotFound)
		return
	}

	if req.VideoURL != "" {
		session.VideoURL = req.VideoURL
	}
	if req.PlaybackRate > 0 {
		session.PlaybackRate = req.PlaybackRate
	}

	session.CurrentTime = req.TimestampSec
	session.UpdatedAt = time.Now()

	switch req.Action {
	case "play":
		session.IsPlaying = true
	case "pause":
		session.IsPlaying = false
	case "seek", "change_url":
		// timestamp and video_url updated above
	}
	updatedSession := *session
	h.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updatedSession)
}

// ProcessWatchTogetherWSEvent handles WebSocket "watch_together" event payloads
func ProcessWatchTogetherWSEvent(eventBytes []byte) bool {
	var payload SyncStateRequest
	if err := json.Unmarshal(eventBytes, &payload); err != nil {
		return false
	}
	return true
}
