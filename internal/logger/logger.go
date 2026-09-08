package logger

import (
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
)

var Log *slog.Logger

func InitLogger() {
	env := os.Getenv("ENV")
	var handler slog.Handler

	if env == "production" || env == "prod" {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})
	} else {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})
	}

	Log = slog.New(handler)
	slog.SetDefault(Log)
}

// RequestLogger middleware logs every HTTP request with request ID, duration, status, and source
func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}
		w.Header().Set("X-Request-ID", requestID)

		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		// Determine request source (Swagger UI vs Mobile Client App)
		source := "mobile-app"
		referer := r.Header.Get("Referer")
		userAgent := r.Header.Get("User-Agent")
		if strings.Contains(strings.ToLower(referer), "swagger") || strings.Contains(strings.ToLower(userAgent), "swagger") || strings.HasPrefix(r.URL.Path, "/swagger") {
			source = "swagger-ui"
		}

		next.ServeHTTP(ww, r)

		duration := time.Since(start)
		status := ww.Status()

		fields := []any{
			slog.String("request_id", requestID),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", status),
			slog.Float64("duration_ms", float64(duration.Microseconds())/1000.0),
			slog.String("source", source),
			slog.String("client_ip", r.RemoteAddr),
		}

		if status >= 500 {
			Log.Error("HTTP Server Request Error", fields...)
		} else if status >= 400 {
			Log.Warn("HTTP Client Request Warning", fields...)
		} else {
			Log.Info("HTTP Request Processed", fields...)
		}
	})
}
