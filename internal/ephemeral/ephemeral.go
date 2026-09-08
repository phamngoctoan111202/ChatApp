package ephemeral

import (
	"context"
	"time"

	"chat-app/internal/logger"

	"github.com/jackc/pgx/v5/pgxpool"
)

// StartWorker launches a background worker loop that periodically purges expired ephemeral offline messages
func StartWorker(db *pgxpool.Pool, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	logger.Log.Info("Ephemeral Message Cleanup Worker started", "interval", interval.String())

	for range ticker.C {
		cleanupExpiredMessages(db)
	}
}

func cleanupExpiredMessages(db *pgxpool.Pool) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	query := `
		DELETE FROM offline_messages 
		WHERE ephemeral_ttl_seconds > 0 
		  AND (created_at + (ephemeral_ttl_seconds || ' seconds')::interval) < CURRENT_TIMESTAMP
	`
	res, err := db.Exec(ctx, query)
	if err != nil {
		logger.Log.Error("Error purging expired ephemeral messages", "error", err)
		return
	}

	if res.RowsAffected() > 0 {
		logger.Log.Info("Automatically purged expired ephemeral messages from offline queue", "rows_affected", res.RowsAffected())
	}
}
