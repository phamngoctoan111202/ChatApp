package sealed

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"chat-app/internal/auth"
)

// SenderCertificate is issued by the server to authenticated users.
// Clients attach this certificate to Sealed Envelopes so the server can verify authorization without knowing SenderID.
type SenderCertificate struct {
	UserID    string `json:"user_id"`
	DeviceID  int    `json:"device_id"`
	ExpiresAt int64  `json:"expires_at"`
	Signature string `json:"signature"`
}

type SealedHandler struct{}

func NewSealedHandler() *SealedHandler {
	return &SealedHandler{}
}

func getSealedSecret() []byte {
	secret := os.Getenv("SEALED_SECRET")
	if secret == "" {
		secret = "signal-lite-sealed-sender-secret-change-in-prod"
	}
	return []byte(secret)
}

// IssueCertificate creates an Unidentified Delivery Certificate for the authenticated user and device (valid for 7 days)
func IssueCertificate(userID string, deviceID int) (*SenderCertificate, error) {
	exp := time.Now().Add(7 * 24 * time.Hour).Unix()
	rawPayload := fmt.Sprintf("%s:%d:%d", userID, deviceID, exp)

	h := hmac.New(sha256.New, getSealedSecret())
	h.Write([]byte(rawPayload))
	sigB64 := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return &SenderCertificate{
		UserID:    userID,
		DeviceID:  deviceID,
		ExpiresAt: exp,
		Signature: sigB64,
	}, nil
}

// VerifyCertificate checks server signature and expiration of a SenderCertificate
func VerifyCertificate(cert *SenderCertificate) error {
	if cert == nil {
		return errors.New("missing sender certificate")
	}

	if time.Now().Unix() > cert.ExpiresAt {
		return errors.New("sender certificate has expired")
	}

	rawPayload := fmt.Sprintf("%s:%d:%d", cert.UserID, cert.DeviceID, cert.ExpiresAt)
	h := hmac.New(sha256.New, getSealedSecret())
	h.Write([]byte(rawPayload))
	expectedSig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	if !hmac.Equal([]byte(cert.Signature), []byte(expectedSig)) {
		return errors.New("invalid sender certificate signature")
	}

	return nil
}

// GetCertificate HTTP Endpoint: Returns a fresh Sealed Sender Certificate for the authenticated client
func (h *SealedHandler) GetCertificate(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserIDFromContext(r.Context())
	deviceID := auth.GetDeviceIDFromContext(r.Context())

	if userID == "" {
		http.Error(w, `{"error":"Unauthorized request context"}`, http.StatusUnauthorized)
		return
	}

	cert, err := IssueCertificate(userID, deviceID)
	if err != nil {
		http.Error(w, `{"error":"Failed to generate sealed sender certificate"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(cert)
}
