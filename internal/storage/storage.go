package storage

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PutStorageRequest struct {
	Key       string `json:"key"`
	ValueBlob string `json:"value_blob"` // Base64 encoded encrypted value from client
	Version   int    `json:"version"`
}

type GetStorageResponse struct {
	Key       string `json:"key"`
	ValueBlob string `json:"value_blob"`
	Version   int    `json:"version"`
	UpdatedAt int64  `json:"updated_at"`
}

type StorageHandler struct {
	db *pgxpool.Pool
}

func NewStorageHandler(db *pgxpool.Pool) *StorageHandler {
	return &StorageHandler{db: db}
}

// PutKey saves or updates the user's encrypted key-value storage data
func (h *StorageHandler) PutKey(w http.ResponseWriter, r *http.Request) {
	userUUID := r.Header.Get("X-User-UUID")
	if userUUID == "" {
		http.Error(w, `{"error":"Missing X-User-UUID header for authentication"}`, http.StatusUnauthorized)
		return
	}

	var req PutStorageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	if req.Key == "" || req.ValueBlob == "" {
		http.Error(w, `{"error":"Missing Key or Value field"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `
		INSERT INTO encrypted_storage (user_id, key_name, value_blob, version, updated_at)
		VALUES ($1, $2, decode($3, 'base64'), $4, CURRENT_TIMESTAMP)
		ON CONFLICT (user_id, key_name)
		DO UPDATE SET value_blob = EXCLUDED.value_blob, version = EXCLUDED.version, updated_at = CURRENT_TIMESTAMP
	`
	_, err := h.db.Exec(ctx, query, userUUID, req.Key, req.ValueBlob, req.Version)
	if err != nil {
		http.Error(w, `{"error":"Failed to save data into database"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message":"Encrypted data saved successfully"}`))
}

// GetKey returns the encrypted value corresponding to the requested key name
func (h *StorageHandler) GetKey(w http.ResponseWriter, r *http.Request) {
	userUUID := r.Header.Get("X-User-UUID")
	if userUUID == "" {
		http.Error(w, `{"error":"Missing X-User-UUID header for authentication"}`, http.StatusUnauthorized)
		return
	}

	keyName := chi.URLParam(r, "key")
	if keyName == "" {
		http.Error(w, `{"error":"Missing query key name"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var valueBytes []byte
	var version int
	var updatedAt time.Time

	query := `
		SELECT value_blob, version, updated_at 
		FROM encrypted_storage 
		WHERE user_id = $1 AND key_name = $2
	`
	err := h.db.QueryRow(ctx, query, userUUID, keyName).Scan(&valueBytes, &version, &updatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, `{"error":"Key not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"error":"Internal server error querying data"}`, http.StatusInternalServerError)
		return
	}

	response := GetStorageResponse{
		Key:       keyName,
		ValueBlob: string(valueBytes),
		Version:   version,
		UpdatedAt: updatedAt.Unix(),
	}

	var base64Str string
	err = h.db.QueryRow(ctx, "SELECT encode(value_blob, 'base64') FROM encrypted_storage WHERE user_id = $1 AND key_name = $2", userUUID, keyName).Scan(&base64Str)
	if err == nil {
		response.ValueBlob = base64Str
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// DeleteKey deletes a key-value storage pair
func (h *StorageHandler) DeleteKey(w http.ResponseWriter, r *http.Request) {
	userUUID := r.Header.Get("X-User-UUID")
	if userUUID == "" {
		http.Error(w, `{"error":"Missing X-User-UUID header for authentication"}`, http.StatusUnauthorized)
		return
	}

	keyName := chi.URLParam(r, "key")
	if keyName == "" {
		http.Error(w, `{"error":"Missing key name to delete"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := h.db.Exec(ctx, "DELETE FROM encrypted_storage WHERE user_id = $1 AND key_name = $2", userUUID, keyName)
	if err != nil {
		http.Error(w, `{"error":"Internal server error deleting data"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message":"Key deleted successfully"}`))
}
