package keys

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"chat-app/internal/auth"

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
	IdentityKey    string             `json:"identity_key"`
	SignedPrekey   SignedPrekeyDTO    `json:"signed_pre_key"`
	OneTimePrekeys []OneTimePrekeyDTO `json:"one_time_pre_keys"`
}

type DeviceBundleDTO struct {
	DeviceID      int               `json:"device_id"`
	IdentityKey   string            `json:"identity_key"`
	SignedPrekey  SignedPrekeyDTO   `json:"signed_pre_key"`
	OneTimePrekey *OneTimePrekeyDTO `json:"one_time_pre_key,omitempty"`
}

type KeysHandler struct {
	db *pgxpool.Pool
}

func NewKeysHandler(db *pgxpool.Pool) *KeysHandler {
	return &KeysHandler{db: db}
}

// UploadKeys saves/updates Signed Prekey & One-Time Prekeys for the authenticated device
func (h *KeysHandler) UploadKeys(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserIDFromContext(r.Context())
	deviceID := auth.GetDeviceIDFromContext(r.Context())

	if userID == "" {
		http.Error(w, `{"error":"Unauthorized request context"}`, http.StatusUnauthorized)
		return
	}
	if deviceID <= 0 {
		deviceID = 1
	}

	var req UploadKeysRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	if req.SignedPrekey.PublicKey == "" || req.SignedPrekey.Signature == "" {
		http.Error(w, `{"error":"Missing required Signed Prekey information"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tx, err := h.db.Begin(ctx)
	if err != nil {
		http.Error(w, `{"error":"Internal server error initializing database transaction"}`, http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(ctx)

	// Save Identity Key if provided
	if req.IdentityKey != "" {
		_, _ = tx.Exec(ctx, "UPDATE users SET identity_key = $1 WHERE id = $2", req.IdentityKey, userID)
		queryIdentityKey := `
			INSERT INTO identity_keys (user_id, device_id, identity_key)
			VALUES ($1, $2, $3)
			ON CONFLICT (user_id, device_id)
			DO UPDATE SET identity_key = EXCLUDED.identity_key
		`
		_, _ = tx.Exec(ctx, queryIdentityKey, userID, deviceID, req.IdentityKey)
	}

	// 1. Save/Update Signed Prekey for this (user_id, device_id)
	querySigned := `
		INSERT INTO signed_prekeys (user_id, device_id, key_id, public_key, signature)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (user_id, device_id)
		DO UPDATE SET key_id = EXCLUDED.key_id, public_key = EXCLUDED.public_key, signature = EXCLUDED.signature
	`
	_, err = tx.Exec(ctx, querySigned, userID, deviceID, req.SignedPrekey.KeyID, req.SignedPrekey.PublicKey, req.SignedPrekey.Signature)
	if err != nil {
		http.Error(w, `{"error":"Failed to save Signed Prekey"}`, http.StatusInternalServerError)
		return
	}

	// 2. Save One-Time Prekeys for this (user_id, device_id)
	if len(req.OneTimePrekeys) > 0 {
		queryOPK := `
			INSERT INTO one_time_prekeys (user_id, device_id, key_id, public_key)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (user_id, device_id, key_id) DO NOTHING
		`
		for _, opk := range req.OneTimePrekeys {
			_, _ = tx.Exec(ctx, queryOPK, userID, deviceID, opk.KeyID, opk.PublicKey)
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

// GetUserPrekeyBundles returns prekey bundles for ALL devices of a recipient user (enabling fan-out encryption)
func (h *KeysHandler) GetUserPrekeyBundles(w http.ResponseWriter, r *http.Request) {
	recipientUUID := chi.URLParam(r, "uuid")
	if recipientUUID == "" {
		recipientUUID = chi.URLParam(r, "userId")
	}
	if recipientUUID == "" {
		http.Error(w, `{"error":"Missing recipient UUID"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Get Recipient Identity Key
	var identityKey string
	err := h.db.QueryRow(ctx, "SELECT COALESCE(identity_key, '') FROM users WHERE id = $1", recipientUUID).Scan(&identityKey)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, `{"error":"Recipient user not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"error":"Failed to query recipient user"}`, http.StatusInternalServerError)
		return
	}

	// 2. Get list of active devices for recipient
	devRows, err := h.db.Query(ctx, "SELECT device_id FROM devices WHERE user_id = $1 ORDER BY device_id ASC", recipientUUID)
	if err != nil {
		http.Error(w, `{"error":"Failed to query recipient devices"}`, http.StatusInternalServerError)
		return
	}
	defer devRows.Close()

	var deviceIDs []int
	for devRows.Next() {
		var devID int
		if err := devRows.Scan(&devID); err == nil {
			deviceIDs = append(deviceIDs, devID)
		}
	}
	if len(deviceIDs) == 0 {
		deviceIDs = []int{1}
	}

	var bundles []DeviceBundleDTO
	var primarySignedPrekey *SignedPrekeyDTO
	var primaryOneTimePrekey *OneTimePrekeyDTO

	for _, devID := range deviceIDs {
		devIdentityKey := identityKey
		var ik string
		if errIK := h.db.QueryRow(ctx, "SELECT identity_key FROM identity_keys WHERE user_id = $1 AND device_id = $2", recipientUUID, devID).Scan(&ik); errIK == nil && ik != "" {
			devIdentityKey = ik
		}

		var spk SignedPrekeyDTO
		err := h.db.QueryRow(ctx, "SELECT key_id, public_key, signature FROM signed_prekeys WHERE user_id = $1 AND device_id = $2", recipientUUID, devID).Scan(&spk.KeyID, &spk.PublicKey, &spk.Signature)
		if err != nil {
			continue // Skip devices that haven't uploaded prekeys yet
		}

		bundle := DeviceBundleDTO{
			DeviceID:     devID,
			IdentityKey:  devIdentityKey,
			SignedPrekey: spk,
		}

		// Consume 1 One-Time Prekey if available (and delete it for forward secrecy)
		var opkID, opkKeyID int
		var opkPub string
		err = h.db.QueryRow(ctx, `
			DELETE FROM one_time_prekeys 
			WHERE id = (
				SELECT id FROM one_time_prekeys 
				WHERE user_id = $1 AND device_id = $2 
				ORDER BY id ASC LIMIT 1
			) 
			RETURNING id, key_id, public_key
		`, recipientUUID, devID).Scan(&opkID, &opkKeyID, &opkPub)

		if err == nil {
			bundle.OneTimePrekey = &OneTimePrekeyDTO{
				KeyID:     opkKeyID,
				PublicKey: opkPub,
			}
		}

		if devID == 1 || primarySignedPrekey == nil {
			spkCopy := spk
			primarySignedPrekey = &spkCopy
			if bundle.OneTimePrekey != nil {
				opkCopy := *bundle.OneTimePrekey
				primaryOneTimePrekey = &opkCopy
			}
		}

		bundles = append(bundles, bundle)
	}

	if primarySignedPrekey == nil {
		primarySignedPrekey = &SignedPrekeyDTO{KeyID: 1, PublicKey: identityKey, Signature: ""}
	}

	resp := map[string]interface{}{
		"user_id":          recipientUUID,
		"recipient_id":     recipientUUID,
		"identity_key":     identityKey,
		"signed_pre_key":   primarySignedPrekey,
		"one_time_pre_key": primaryOneTimePrekey,
		"devices":          bundles,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}
