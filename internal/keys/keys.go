package keys

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SignedPrekeyDTO struct {
	KeyID     int    `json:"key_id"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

type OneTimePrekeyDTO struct {
	KeyID     int    `json:"key_id"`
	PublicKey string `json:"public_key"`
}

type UploadKeysRequest struct {
	UserID         string             `json:"user_id"`
	SignedPrekey   SignedPrekeyDTO    `json:"signed_prekey"`
	OneTimePrekeys []OneTimePrekeyDTO `json:"one_time_prekeys"`
}

type PrekeyBundleResponse struct {
	IdentityKey    string            `json:"identity_key"`
	SignedPrekey   SignedPrekeyDTO   `json:"signed_prekey"`
	OneTimePrekey  *OneTimePrekeyDTO `json:"one_time_prekey,omitempty"`
}

type KeysHandler struct {
	db *pgxpool.Pool
}

func NewKeysHandler(db *pgxpool.Pool) *KeysHandler {
	return &KeysHandler{db: db}
}

// UploadKeys updates Signed Prekey and uploads One-Time Prekeys list
func (h *KeysHandler) UploadKeys(w http.ResponseWriter, r *http.Request) {
	var req UploadKeysRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	if req.UserID == "" || req.SignedPrekey.PublicKey == "" || req.SignedPrekey.Signature == "" {
		http.Error(w, `{"error":"Missing required key information"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tx, err := h.db.Begin(ctx)
	if err != nil {
		http.Error(w, `{"error":"Internal server error initializing storage"}`, http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(ctx)

	// 1. Insert/Update Signed Prekey
	querySigned := `
		INSERT INTO signed_prekeys (user_id, key_id, public_key, signature)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id)
		DO UPDATE SET key_id = EXCLUDED.key_id, public_key = EXCLUDED.public_key, signature = EXCLUDED.signature
	`
	_, err = tx.Exec(ctx, querySigned, req.UserID, req.SignedPrekey.KeyID, req.SignedPrekey.PublicKey, req.SignedPrekey.Signature)
	if err != nil {
		http.Error(w, `{"error":"Failed to save Signed Prekey"}`, http.StatusInternalServerError)
		return
	}

	// 2. Insert One-Time Prekeys list
	if len(req.OneTimePrekeys) > 0 {
		queryOPK := `
			INSERT INTO one_time_prekeys (user_id, key_id, public_key)
			VALUES ($1, $2, $3)
			ON CONFLICT (user_id, key_id) DO NOTHING
		`
		for _, opk := range req.OneTimePrekeys {
			_, err = tx.Exec(ctx, queryOPK, req.UserID, opk.KeyID, opk.PublicKey)
			if err != nil {
				http.Error(w, `{"error":"Failed to save One-Time Prekey"}`, http.StatusInternalServerError)
				return
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		http.Error(w, `{"error":"Failed to commit transaction for saving keys"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message":"Keys uploaded successfully"}`))
}

// GetPrekeyBundle returns the recipient's prekey bundle for establishing an E2EE session
func (h *KeysHandler) GetPrekeyBundle(w http.ResponseWriter, r *http.Request) {
	recipientUUID := chi.URLParam(r, "uuid")
	if recipientUUID == "" {
		http.Error(w, `{"error":"Missing recipient UUID"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tx, err := h.db.Begin(ctx)
	if err != nil {
		http.Error(w, `{"error":"Internal server error initializing query"}`, http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(ctx)

	// 1. Get Identity Key
	var identityKey string
	err = tx.QueryRow(ctx, "SELECT identity_key FROM users WHERE id = $1", recipientUUID).Scan(&identityKey)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, `{"error":"User not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"error":"Failed to query user"}`, http.StatusInternalServerError)
		return
	}

	// 2. Get Signed Prekey
	var spk SignedPrekeyDTO
	err = tx.QueryRow(ctx, "SELECT key_id, public_key, signature FROM signed_prekeys WHERE user_id = $1", recipientUUID).Scan(&spk.KeyID, &spk.PublicKey, &spk.Signature)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, `{"error":"Recipient has not uploaded public keys"}`, http.StatusConflict)
			return
		}
		http.Error(w, `{"error":"Failed to query Signed Prekey"}`, http.StatusInternalServerError)
		return
	}

	// 3. Get 1 One-Time Prekey (if available), then delete it for forward secrecy
	var opkID int
	var opk OneTimePrekeyDTO
	hasOPK := true

	err = tx.QueryRow(ctx, `
		SELECT id, key_id, public_key 
		FROM one_time_prekeys 
		WHERE user_id = $1 
		ORDER BY id ASC 
		LIMIT 1
	`, recipientUUID).Scan(&opkID, &opk.KeyID, &opk.PublicKey)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			hasOPK = false
		} else {
			http.Error(w, `{"error":"Failed to query One-Time Prekey"}`, http.StatusInternalServerError)
			return
		}
	}

	if hasOPK {
		// Delete this one-time prekey from DB to ensure forward secrecy
		_, err = tx.Exec(ctx, "DELETE FROM one_time_prekeys WHERE id = $1", opkID)
		if err != nil {
			http.Error(w, `{"error":"Failed to clean up one-time prekey"}`, http.StatusInternalServerError)
			return
		}
	}

	if err := tx.Commit(ctx); err != nil {
		http.Error(w, `{"error":"Failed to commit transaction for getting keys"}`, http.StatusInternalServerError)
		return
	}

	response := PrekeyBundleResponse{
		IdentityKey:  identityKey,
		SignedPrekey: spk,
	}
	if hasOPK {
		response.OneTimePrekey = &opk
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
