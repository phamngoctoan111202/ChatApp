package group

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"chat-app/internal/auth"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type CreateGroupRequest struct {
	TitleCiphertext string   `json:"title_ciphertext"`
	AvatarURL       string   `json:"avatar_url"`
	MemberIDs       []string `json:"member_ids"`
}

type AddMemberRequest struct {
	UserIDs []string `json:"user_ids"`
}

type UploadSenderKeyRequest struct {
	SenderKeyBlob string `json:"sender_key_blob"`
}

type GroupDTO struct {
	ID              string    `json:"id"`
	TitleCiphertext string    `json:"title_ciphertext"`
	AvatarURL       string    `json:"avatar_url"`
	CreatorID       string    `json:"creator_id"`
	CreatedAt       time.Time `json:"created_at"`
}

type GroupMemberDTO struct {
	UserID   string    `json:"user_id"`
	Role     string    `json:"role"`
	JoinedAt time.Time `json:"joined_at"`
}

type GroupSenderKeyDTO struct {
	SenderID      string `json:"sender_id"`
	DeviceID      int    `json:"device_id"`
	SenderKeyBlob string `json:"sender_key_blob"`
}

type GroupHandler struct {
	db *pgxpool.Pool
}

func NewGroupHandler(db *pgxpool.Pool) *GroupHandler {
	return &GroupHandler{db: db}
}

// CreateGroup creates a new E2EE group and adds creator & initial members
func (h *GroupHandler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	creatorID := auth.GetUserIDFromContext(r.Context())
	if creatorID == "" {
		http.Error(w, `{"error":"Unauthorized request context"}`, http.StatusUnauthorized)
		return
	}

	var req CreateGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	if req.TitleCiphertext == "" {
		http.Error(w, `{"error":"Missing group title_ciphertext"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx, err := h.db.Begin(ctx)
	if err != nil {
		http.Error(w, `{"error":"Database transaction error"}`, http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(ctx)

	// 1. Create group
	var groupID string
	queryGroup := `
		INSERT INTO groups (title_ciphertext, avatar_url, creator_id)
		VALUES ($1, $2, $3)
		RETURNING id
	`
	err = tx.QueryRow(ctx, queryGroup, req.TitleCiphertext, req.AvatarURL, creatorID).Scan(&groupID)
	if err != nil {
		http.Error(w, `{"error":"Failed to create group"}`, http.StatusInternalServerError)
		return
	}

	// 2. Add Creator as admin
	_, err = tx.Exec(ctx, "INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'admin')", groupID, creatorID)
	if err != nil {
		http.Error(w, `{"error":"Failed to add group admin member"}`, http.StatusInternalServerError)
		return
	}

	// 3. Add initial member IDs
	for _, memberID := range req.MemberIDs {
		if memberID != "" && memberID != creatorID {
			_, _ = tx.Exec(ctx, "INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'member') ON CONFLICT DO NOTHING", groupID, memberID)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		http.Error(w, `{"error":"Failed to commit transaction for creating group"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "Group created successfully",
		"group_id": groupID,
	})
}

// ListUserGroups returns all groups the authenticated user is a member of
func (h *GroupHandler) ListUserGroups(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserIDFromContext(r.Context())
	if userID == "" {
		http.Error(w, `{"error":"Unauthorized request context"}`, http.StatusUnauthorized)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `
		SELECT g.id, g.title_ciphertext, g.avatar_url, g.creator_id, g.created_at
		FROM groups g
		JOIN group_members gm ON g.id = gm.group_id
		WHERE gm.user_id = $1
		ORDER BY g.created_at DESC
	`
	rows, err := h.db.Query(ctx, query, userID)
	if err != nil {
		http.Error(w, `{"error":"Failed to query user groups"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var groups []GroupDTO
	for rows.Next() {
		var g GroupDTO
		if err := rows.Scan(&g.ID, &g.TitleCiphertext, &g.AvatarURL, &g.CreatorID, &g.CreatedAt); err == nil {
			groups = append(groups, g)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"groups": groups,
	})
}

// GetGroupMembers returns members of a group
func (h *GroupHandler) GetGroupMembers(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "id")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `
		SELECT user_id, role, joined_at
		FROM group_members
		WHERE group_id = $1
		ORDER BY joined_at ASC
	`
	rows, err := h.db.Query(ctx, query, groupID)
	if err != nil {
		http.Error(w, `{"error":"Failed to query group members"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var members []GroupMemberDTO
	for rows.Next() {
		var m GroupMemberDTO
		if err := rows.Scan(&m.UserID, &m.Role, &m.JoinedAt); err == nil {
			members = append(members, m)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"group_id": groupID,
		"members":  members,
	})
}

// AddMembers adds new members to an existing group
func (h *GroupHandler) AddMembers(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "id")

	var req AddMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, memberID := range req.UserIDs {
		if memberID != "" {
			_, _ = h.db.Exec(ctx, "INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'member') ON CONFLICT DO NOTHING", groupID, memberID)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message":"Members added successfully"}`))
}

// UploadSenderKey uploads Sender Key Bundle for the authenticated device in a group (Signal Sender Key Protocol)
func (h *GroupHandler) UploadSenderKey(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserIDFromContext(r.Context())
	deviceID := auth.GetDeviceIDFromContext(r.Context())
	groupID := chi.URLParam(r, "id")

	var req UploadSenderKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SenderKeyBlob == "" {
		http.Error(w, `{"error":"Missing sender_key_blob"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `
		INSERT INTO group_sender_keys (group_id, sender_id, device_id, sender_key_blob)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (group_id, sender_id, device_id)
		DO UPDATE SET sender_key_blob = EXCLUDED.sender_key_blob, created_at = CURRENT_TIMESTAMP
	`
	_, err := h.db.Exec(ctx, query, groupID, userID, deviceID, req.SenderKeyBlob)
	if err != nil {
		http.Error(w, `{"error":"Failed to save group sender key bundle"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message":"Group sender key uploaded successfully"}`))
}

// GetSenderKeys retrieves all group members' Sender Key Bundles for a group
func (h *GroupHandler) GetSenderKeys(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "id")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `
		SELECT sender_id, device_id, sender_key_blob
		FROM group_sender_keys
		WHERE group_id = $1
	`
	rows, err := h.db.Query(ctx, query, groupID)
	if err != nil {
		http.Error(w, `{"error":"Failed to query group sender keys"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var keysList []GroupSenderKeyDTO
	for rows.Next() {
		var k GroupSenderKeyDTO
		if err := rows.Scan(&k.SenderID, &k.DeviceID, &k.SenderKeyBlob); err == nil {
			keysList = append(keysList, k)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"group_id":    groupID,
		"sender_keys": keysList,
	})
}

// RemoveMember removes a target member from group (requires caller to be group admin or target removing self)
func (h *GroupHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	callerID := auth.GetUserIDFromContext(r.Context())
	groupID := chi.URLParam(r, "id")
	targetUserID := chi.URLParam(r, "user_id")

	if callerID == "" || groupID == "" || targetUserID == "" {
		http.Error(w, `{"error":"Missing group_id or target user_id"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check caller role in group
	var callerRole string
	err := h.db.QueryRow(ctx, "SELECT role FROM group_members WHERE group_id = $1 AND user_id = $2", groupID, callerID).Scan(&callerRole)
	if err != nil {
		http.Error(w, `{"error":"Caller is not a member of this group"}`, http.StatusForbidden)
		return
	}

	// Only admin or target user leaving self is allowed
	if callerRole != "admin" && callerID != targetUserID {
		http.Error(w, `{"error":"Only group admin can remove other members"}`, http.StatusForbidden)
		return
	}

	tx, err := h.db.Begin(ctx)
	if err != nil {
		http.Error(w, `{"error":"Database transaction error"}`, http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(ctx)

	// Remove from group_members
	_, err = tx.Exec(ctx, "DELETE FROM group_members WHERE group_id = $1 AND user_id = $2", groupID, targetUserID)
	if err != nil {
		http.Error(w, `{"error":"Failed to remove member from group"}`, http.StatusInternalServerError)
		return
	}

	// Remove member's group_sender_keys
	_, _ = tx.Exec(ctx, "DELETE FROM group_sender_keys WHERE group_id = $1 AND sender_id = $2", groupID, targetUserID)

	if err := tx.Commit(ctx); err != nil {
		http.Error(w, `{"error":"Transaction commit error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message":"Member removed from group successfully"}`))
}
