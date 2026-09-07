package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"chat-app/db"
	"chat-app/internal/auth"
	"chat-app/internal/block"
	"chat-app/internal/device"
	"chat-app/internal/ephemeral"
	"chat-app/internal/group"
	"chat-app/internal/keys"
	"chat-app/internal/location"
	"chat-app/internal/media"
	"chat-app/internal/message"
	"chat-app/internal/pin"
	"chat-app/internal/poll"
	"chat-app/internal/presence"
	"chat-app/internal/push"
	"chat-app/internal/reaction"
	"chat-app/internal/redis"
	"chat-app/internal/sealed"
	"chat-app/internal/storage"
	"chat-app/internal/watchtogether"

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

		// Start background Ephemeral Message Cleanup Worker (Purges expired offline messages every 30s)
		go ephemeral.StartWorker(dbPool, 30*time.Second)
	} else {
		log.Println("Warning: DATABASE_URL not set. Running in database-less mode.")
	}

	// Initialize Redis Service for cluster Pub/Sub
	redisSvc := redis.InitRedis()

	r := chi.NewRouter()

	// Configure standard HTTP middlewares
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Initialize component handlers
	authHandler := auth.NewAuthHandler(dbPool)
	deviceHandler := device.NewDeviceHandler(dbPool)
	groupHandler := group.NewGroupHandler(dbPool)
	keysHandler := keys.NewKeysHandler(dbPool)
	pushHandler := push.NewPushHandler(dbPool)
	sealedHandler := sealed.NewSealedHandler()
	storageHandler := storage.NewStorageHandler(dbPool)
	mediaHandler := media.NewMediaHandler("./uploads", dbPool)
	presenceHandler := presence.NewPresenceHandler(dbPool)
	blockHandler := block.NewBlockHandler(dbPool)
	watchTogetherHandler := watchtogether.NewWatchTogetherHandler(dbPool)
	pollHandler := poll.NewPollHandler(dbPool)
	pinHandler := pin.NewPinHandler(dbPool)
	reactionHandler := reaction.NewReactionHandler(dbPool)
	locationHandler := location.NewLocationHandler(dbPool)

	// Initialize WebSocket Hub for real-time messages and WebRTC signaling
	hub := message.NewHub(dbPool, redisSvc)
	go hub.Run()

	// ---- API ROUTE DEFINITIONS ----

	// 1. Healthcheck & Static files
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"healthy","message":"Chat Server is running"}`))
	})

	// Route to serve static uploaded files from local uploads folder
	workDir, _ := os.Getwd()
	filesDir := http.Dir(filepath.Join(workDir, "uploads"))
	FileServer(r, "/uploads", filesDir)

	// Swagger Interactive API Documentation UI Endpoint
	r.Get("/swagger/doc.json", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join(workDir, "docs", "swagger.json"))
	})
	r.Get("/swagger", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/swagger/", http.StatusFound)
	})
	r.Get("/swagger/*", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		swaggerHTML := `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Chat App API Documentation - Swagger UI</title>
  <link rel="stylesheet" type="text/css" href="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.11.0/swagger-ui.min.css" />
  <style>
    html { box-sizing: border-box; overflow-y: scroll; }
    *, *:before, *:after { box-sizing: inherit; }
    body { margin:0; background: #fafafa; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.11.0/swagger-ui-bundle.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.11.0/swagger-ui-standalone-preset.min.js"></script>
  <script>
    window.onload = function() {
      window.ui = SwaggerUIBundle({
        url: "/swagger/doc.json",
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        plugins: [
          SwaggerUIBundle.plugins.DownloadUrl
        ],
        layout: "StandaloneLayout"
      });
    };
  </script>
</body>
</html>`
		w.Write([]byte(swaggerHTML))
	})

	// 2. WebSocket Gateway
	r.Get("/ws", func(w http.ResponseWriter, r *http.Request) {
		message.ServeWS(hub, w, r)
	})

	// Group v1 APIs
	r.Route("/api/v1", func(r chi.Router) {
		// Public Authentication Endpoints
		r.Post("/auth/register", authHandler.Register)
		r.Post("/auth/login", authHandler.Login)
		r.Post("/auth/refresh", authHandler.RefreshToken)

		// Public Prekey Bundle retrieval endpoint for recipient lookup
		r.Get("/keys/user/{uuid}", keysHandler.GetUserPrekeyBundles)

		// Public Encrypted Attachment Download Endpoint
		r.Get("/attachments/{id}", mediaHandler.GetEncryptedBlob)

		// Public Media Proxy Endpoints
		r.Route("/media", func(r chi.Router) {
			r.Post("/upload", mediaHandler.UploadFile)
			r.Get("/gif-search", mediaHandler.GIFSearch)
			r.Get("/link-preview", mediaHandler.LinkPreview)
		})

		// Protected Endpoints (Requires valid JWT Bearer token)
		r.Group(func(r chi.Router) {
			r.Use(auth.AuthMiddleware)

			// Sealed Sender Certificate Endpoint
			r.Get("/sealed/certificate", sealedHandler.GetCertificate)

			// Zero-Knowledge Encrypted Attachment Upload Endpoint
			r.Post("/attachments/upload", mediaHandler.UploadEncryptedBlob)

			// FCM / APNs Push Notification Token Registration
			r.Post("/push/token", pushHandler.RegisterPushToken)

			// Signal Group V2 E2EE & Sender Keys Protocol
			r.Route("/groups", func(r chi.Router) {
				r.Post("/", groupHandler.CreateGroup)
				r.Get("/", groupHandler.ListUserGroups)
				r.Get("/{id}/members", groupHandler.GetGroupMembers)
				r.Post("/{id}/members", groupHandler.AddMembers)
				r.Delete("/{id}/members/{user_id}", groupHandler.RemoveMember)
				r.Put("/{id}/sender-keys", groupHandler.UploadSenderKey)
				r.Get("/{id}/sender-keys", groupHandler.GetSenderKeys)
			})

			// Multi-Device Management
			r.Route("/devices", func(r chi.Router) {
				r.Get("/", deviceHandler.ListDevices)
				r.Post("/link", deviceHandler.LinkDevice)
				r.Delete("/{device_id}", deviceHandler.UnlinkDevice)
			})

			// Prekey upload for authenticated device
			r.Put("/keys", keysHandler.UploadKeys)

			// User Presence & Block / Restrict Service
			r.Route("/users", func(r chi.Router) {
				r.Get("/{id}/presence", presenceHandler.GetUserPresence)
				r.Post("/block", blockHandler.BlockUser)
				r.Delete("/block/{user_id}", blockHandler.UnblockUser)
				r.Get("/blocked", blockHandler.ListBlockedUsers)
			})

			// Encrypted Storage Service
			r.Route("/storage", func(r chi.Router) {
				r.Put("/keys", storageHandler.PutKey)
				r.Get("/keys/{key}", storageHandler.GetKey)
				r.Delete("/keys/{key}", storageHandler.DeleteKey)
			})

			// Watch Together Synchronous Playback Relay
			r.Route("/watch-together", func(r chi.Router) {
				r.Post("/room", watchTogetherHandler.CreateRoom)
				r.Get("/room/{room_id}", watchTogetherHandler.GetRoomState)
				r.Post("/room/{room_id}/sync", watchTogetherHandler.SyncRoomState)
			})

			// Group Polls / Voting Service
			r.Route("/polls", func(r chi.Router) {
				r.Post("/", pollHandler.CreatePoll)
				r.Post("/{id}/vote", pollHandler.CastVote)
				r.Get("/{id}", pollHandler.GetPoll)
			})

			// Pinned Messages Service
			r.Route("/pins", func(r chi.Router) {
				r.Post("/", pinHandler.PinMessage)
				r.Delete("/{chat_id}/{message_id}", pinHandler.UnpinMessage)
				r.Get("/{chat_id}", pinHandler.GetPinnedMessages)
			})

			// Message Emoji Reactions Service
			r.Route("/reactions", func(r chi.Router) {
				r.Post("/", reactionHandler.AddReaction)
				r.Delete("/", reactionHandler.RemoveReaction)
				r.Get("/message/{message_id}", reactionHandler.GetMessageReactions)
			})

			// Live Location Sharing Service
			r.Route("/location", func(r chi.Router) {
				r.Post("/share", locationHandler.ShareLocation)
				r.Get("/user/{user_id}", locationHandler.GetLocation)
				r.Delete("/stop", locationHandler.StopSharing)
			})
		})
	})

	log.Printf("Chat Server running on http://localhost:%s...\n", port)
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
