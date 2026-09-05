package ephemeral

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// StartWorker launches a background worker loop that periodically purges expired ephemeral offline messages
func StartWorker(db *pgxpool.Pool, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	log.Printf("Ephemeral Message Cleanup Worker started (Interval: %v)\n", interval)

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
		log.Printf("Error purging expired ephemeral messages: %v\n", err)
		return
	}

	if res.RowsAffected() > 0 {
		log.Printf("[EPHEMERAL CLEANUP] Automatically purged %d expired ephemeral messages from offline queue.\n", res.RowsAffected())
	}
}
