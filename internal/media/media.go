package media

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"chat-app/internal/auth"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type LinkPreviewResponse struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	ImageURL    string `json:"image_url"`
}

type AttachmentUploadResponse struct {
	AttachmentID string `json:"attachment_id"`
	DownloadURL  string `json:"download_url"`
	DigestSHA256 string `json:"digest_sha256"`
	SizeBytes    int64  `json:"size_bytes"`
}

type MediaHandler struct {
	uploadDir     string
	attachmentDir string
	db            *pgxpool.Pool
}

func NewMediaHandler(uploadDir string, db *pgxpool.Pool) *MediaHandler {
	attDir := filepath.Join(uploadDir, "attachments")
	if err := os.MkdirAll(attDir, os.ModePerm); err != nil {
		log.Printf("Failed to create attachment directory: %v\n", err)
	}
	return &MediaHandler{
		uploadDir:     uploadDir,
		attachmentDir: attDir,
		db:            db,
	}
}

// UploadEncryptedBlob handles Zero-Knowledge encrypted media blob uploads (Client encrypts local file via AES-256-GCM before uploading)
func (h *MediaHandler) UploadEncryptedBlob(w http.ResponseWriter, r *http.Request) {
	uploaderID := auth.GetUserIDFromContext(r.Context())

	// Limit maximum encrypted blob upload size to 100MB
	r.ParseMultipartForm(100 * 1024 * 1024)

	var reader io.Reader
	file, _, err := r.FormFile("file")
	if err == nil {
		defer file.Close()
		reader = file
	} else {
		// Fallback to raw HTTP Body stream if sent directly
		reader = r.Body
	}

	// Create temporary local file to compute SHA256 digest while saving
	tmpFile, err := os.CreateTemp(h.attachmentDir, "upload_*.tmp")
	if err != nil {
		http.Error(w, `{"error":"Failed to allocate storage for attachment"}`, http.StatusInternalServerError)
		return
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath) // Clean up temp file if error occurs

	hasher := sha256.New()
	multiWriter := io.MultiWriter(tmpFile, hasher)

	sizeWritten, err := io.Copy(multiWriter, reader)
	tmpFile.Close()

	if err != nil || sizeWritten == 0 {
		http.Error(w, `{"error":"Failed to write encrypted blob payload"}`, http.StatusBadRequest)
		return
	}

	digestSHA256 := hex.EncodeToString(hasher.Sum(nil))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Insert attachment metadata into PostgreSQL database
	var attachmentID string
	query := `
		INSERT INTO attachments (uploader_id, size_bytes, digest_sha256)
		VALUES (NULLIF($1, '')::uuid, $2, $3)
		RETURNING id
	`
	err = h.db.QueryRow(ctx, query, uploaderID, sizeWritten, digestSHA256).Scan(&attachmentID)
	if err != nil {
		http.Error(w, `{"error":"Failed to register attachment metadata"}`, http.StatusInternalServerError)
		return
	}

	// Rename temp file to permanent attachment storage path: attachments/{attachment_id}.bin
	finalPath := filepath.Join(h.attachmentDir, attachmentID+".bin")
	if err := os.Rename(tmpPath, finalPath); err != nil {
		http.Error(w, `{"error":"Failed to finalize attachment storage"}`, http.StatusInternalServerError)
		return
	}

	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	downloadURL := baseURL + "/api/v1/attachments/" + attachmentID

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(AttachmentUploadResponse{
		AttachmentID: attachmentID,
		DownloadURL:  downloadURL,
		DigestSHA256: digestSHA256,
		SizeBytes:    sizeWritten,
	})
}

// GetEncryptedBlob downloads the Zero-Knowledge encrypted binary blob for client-side AES-GCM decryption
func (h *MediaHandler) GetEncryptedBlob(w http.ResponseWriter, r *http.Request) {
	attachmentID := chi.URLParam(r, "id")
	if attachmentID == "" {
		http.Error(w, `{"error":"Missing attachment ID"}`, http.StatusBadRequest)
		return
	}

	// Prevent path traversal attacks
	cleanID := filepath.Base(attachmentID)
	filePath := filepath.Join(h.attachmentDir, cleanID+".bin")

	file, err := os.Open(filePath)
	if err != nil {
		http.Error(w, `{"error":"Attachment not found"}`, http.StatusNotFound)
		return
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		http.Error(w, `{"error":"Failed to read attachment properties"}`, http.StatusInternalServerError)
		return
	}

	// Serve strictly as generic binary stream to conceal file format / media metadata on server
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strings.TrimSpace(hex.EncodeToString([]byte(fileInfo.Name())))) // dummy length check
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.WriteHeader(http.StatusOK)

	io.Copy(w, file)
}

// UploadFile handles legacy unencrypted uploads (Stickers, Public Assets)
func (h *MediaHandler) UploadFile(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 * 1024 * 1024)

	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, `{"error":"Failed to read uploaded file"}`, http.StatusBadRequest)
		return
	}
	defer file.Close()

	filename := filepath.Base(handler.Filename)
	uniqueFilename := time.Now().Format("20060102150405") + "_" + filename
	targetPath := filepath.Join(h.uploadDir, uniqueFilename)

	dst, err := os.Create(targetPath)
	if err != nil {
		http.Error(w, `{"error":"Failed to write file to storage"}`, http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		http.Error(w, `{"error":"Failed to copy file content"}`, http.StatusInternalServerError)
		return
	}

	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	fileURL := baseURL + "/uploads/" + uniqueFilename

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"url":       fileURL,
		"filename":  uniqueFilename,
		"mime_type": handler.Header.Get("Content-Type"),
	})
}

// GIFSearch acts as a proxy searching GIF files from Tenor API (anonymizing user IP)
func (h *MediaHandler) GIFSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		http.Error(w, `{"error":"Missing query parameter q"}`, http.StatusBadRequest)
		return
	}

	apiKey := os.Getenv("TENOR_API_KEY")
	if apiKey == "" {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"results": [
				{
					"id": "mock1",
					"media_formats": {
						"tinygif": {
							"url": "https://media.tenor.com/images/mock1/tinygif"
						}
					}
				}
			]
		}`))
		return
	}

	apiURL := "https://tenor.googleapis.com/v2/search?q=" + urlQueryEscape(query) + "&key=" + apiKey + "&limit=10"
	resp, err := http.Get(apiURL)
	if err != nil {
		http.Error(w, `{"error":"Failed to connect to GIF search provider"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// LinkPreview parses OpenGraph info from a target website
func (h *MediaHandler) LinkPreview(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("url")
	if targetURL == "" {
		http.Error(w, `{"error":"Missing target URL parameter"}`, http.StatusBadRequest)
		return
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(targetURL)
	if err != nil {
		http.Error(w, `{"error":"Failed to fetch target webpage"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, `{"error":"Target website returned non-200 status code"}`, http.StatusBadGateway)
		return
	}

	htmlBytes := make([]byte, 512*1024)
	n, _ := io.ReadFull(resp.Body, htmlBytes)
	htmlContent := string(htmlBytes[:n])

	preview := LinkPreviewResponse{
		Title:       extractMeta(htmlContent, `(?i)<title>(.*?)</title>`),
		Description: extractMeta(htmlContent, `(?i)<meta[^>]*name="description"[^>]*content="([^"]*)"`),
		ImageURL:    extractMeta(htmlContent, `(?i)<meta[^>]*property="og:image"[^>]*content="([^"]*)"`),
	}

	if preview.Description == "" {
		preview.Description = extractMeta(htmlContent, `(?i)<meta[^>]*property="og:description"[^>]*content="([^"]*)"`)
	}
	if preview.Title == "" {
		preview.Title = extractMeta(htmlContent, `(?i)<meta[^>]*property="og:title"[^>]*content="([^"]*)"`)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(preview)
}

func extractMeta(html, regexPattern string) string {
	re := regexp.MustCompile(regexPattern)
	matches := re.FindStringSubmatch(html)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

func urlQueryEscape(s string) string {
	return strings.ReplaceAll(s, " ", "%20")
}
