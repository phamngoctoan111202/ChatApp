package media

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type LinkPreviewResponse struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	ImageURL    string `json:"image_url"`
}

type MediaHandler struct {
	uploadDir string
}

func NewMediaHandler(uploadDir string) *MediaHandler {
	// Create upload folder if not exists
	if err := os.MkdirAll(uploadDir, os.ModePerm); err != nil {
		log.Printf("Failed to create upload directory: %v\n", err)
	}
	return &MediaHandler{uploadDir: uploadDir}
}

// UploadFile handles uploading files (Stickers, Stories) and saves them locally
func (h *MediaHandler) UploadFile(w http.ResponseWriter, r *http.Request) {
	// Limit upload size to 10MB
	r.ParseMultipartForm(10 * 1024 * 1024)

	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, `{"error":"Failed to read uploaded file"}`, http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Prevent path traversal attacks using filepath.Base
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
		// Mock data for test environments if API key is not configured
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

	// Limit reader to 512KB to prevent memory exhaustion
	htmlBytes := make([]byte, 512*1024)
	n, _ := io.ReadFull(resp.Body, htmlBytes)
	htmlContent := string(htmlBytes[:n])

	preview := LinkPreviewResponse{
		Title:       extractMeta(htmlContent, `(?i)<title>(.*?)</title>`),
		Description: extractMeta(htmlContent, `(?i)<meta[^>]*name="description"[^>]*content="([^"]*)"`),
		ImageURL:    extractMeta(htmlContent, `(?i)<meta[^>]*property="og:image"[^>]*content="([^"]*)"`),
	}

	// Fallback meta parsing
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
