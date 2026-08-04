package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"

	"chat-app/db"
	"chat-app/internal/auth"
	"chat-app/internal/keys"
	"chat-app/internal/media"
	"chat-app/internal/message"
	"chat-app/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	dbURL := os.Getenv("DATABASE_URL")
	var dbPool *pgxpool.Pool
	var err error

	if dbURL != "" {
		// Initialize database connection and run migration DDL queries
		dbPool, err = db.InitDB(dbURL)
		if err != nil {
			log.Fatalf("Database initialization failed: %v\n", err)
		}
		defer dbPool.Close()
	} else {
		log.Println("Warning: DATABASE_URL not set. Running in database-less mode.")
	}

	r := chi.NewRouter()

	// Configure standard HTTP middlewares
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Initialize component handlers
	authHandler := auth.NewAuthHandler(dbPool)
	keysHandler := keys.NewKeysHandler(dbPool)
	storageHandler := storage.NewStorageHandler(dbPool)
	mediaHandler := media.NewMediaHandler("./uploads")

	// Initialize WebSocket Hub for real-time messages and WebRTC signaling
	hub := message.NewHub(dbPool)
	go hub.Run()

	// ---- API ROUTE DEFINITIONS ----

	// 1. Healthcheck & Static files
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"healthy","message":"Chat App Backend is running"}`))
	})

	// Route to serve static uploaded files from local uploads folder
	workDir, _ := os.Getwd()
	filesDir := http.Dir(filepath.Join(workDir, "uploads"))
	FileServer(r, "/uploads", filesDir)

	// 2. WebSocket Gateway
	r.Get("/ws", func(w http.ResponseWriter, r *http.Request) {
		message.ServeWS(hub, w, r)
	})

	// Group v1 APIs
	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/auth/register", authHandler.Register)

		r.Put("/keys", keysHandler.UploadKeys)
		r.Get("/keys/{uuid}", keysHandler.GetPrekeyBundle)

		r.Route("/storage", func(r chi.Router) {
			r.Put("/keys", storageHandler.PutKey)
			r.Get("/keys/{key}", storageHandler.GetKey)
			r.Delete("/keys/{key}", storageHandler.DeleteKey)
		})

		r.Route("/media", func(r chi.Router) {
			r.Post("/upload", mediaHandler.UploadFile)
			r.Get("/gif-search", mediaHandler.GIFSearch)
			r.Get("/link-preview", mediaHandler.LinkPreview)
		})
	})

	log.Printf("Server running on http://localhost:%s...\n", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatalf("Server startup failed: %v\n", err)
	}
}

// FileServer configures static file router for go-chi
func FileServer(r chi.Router, path string, root http.FileSystem) {
	if path == "/" {
		panic("FileServer: mounting static folder at root '/' is not supported")
	}

	fs := http.StripPrefix(path, http.FileServer(root))

	r.Get(path, func(w http.ResponseWriter, r *http.Request) {
		fs.ServeHTTP(w, r)
	})

	r.Get(path+"/*", func(w http.ResponseWriter, r *http.Request) {
		fs.ServeHTTP(w, r)
	})
}
