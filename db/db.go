package db

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// InitDB connects to the database and runs auto-migrations
func InitDB(databaseURL string) (*pgxpool.Pool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}

	// Ping database connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}

	log.Println("Successfully connected to PostgreSQL database!")

	// Run DDL migrations
	if err := migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}

	return pool, nil
}

func migrate(ctx context.Context, pool *pgxpool.Pool) error {
	queries := []string{
		// 1. Users table
		`CREATE TABLE IF NOT EXISTS users (
			id UUID PRIMARY KEY,
			identity_key TEXT NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);`,

		// 2. Signed Prekey table (Each user has 1 active Signed Prekey at a time)
		`CREATE TABLE IF NOT EXISTS signed_prekeys (
			user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
			key_id INT NOT NULL,
			public_key TEXT NOT NULL,
			signature TEXT NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);`,

		// 3. One-Time Prekeys table (Deleted after consumption for forward secrecy)
		`CREATE TABLE IF NOT EXISTS one_time_prekeys (
			id SERIAL PRIMARY KEY,
			user_id UUID REFERENCES users(id) ON DELETE CASCADE,
			key_id INT NOT NULL,
			public_key TEXT NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			UNIQUE (user_id, key_id)
		);`,

		// 4. Offline messages queue
		`CREATE TABLE IF NOT EXISTS offline_messages (
			id UUID PRIMARY KEY,
			recipient_id UUID REFERENCES users(id) ON DELETE CASCADE,
			sender_id UUID REFERENCES users(id) ON DELETE SET NULL,
			ciphertext TEXT NOT NULL,
			ephemeral_key TEXT,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);`,

		// 5. Encrypted Key-Value store (Storage Service)
		`CREATE TABLE IF NOT EXISTS encrypted_storage (
			user_id UUID REFERENCES users(id) ON DELETE CASCADE,
			key_name VARCHAR(255) NOT NULL,
			value_blob BYTEA NOT NULL,
			version INT NOT NULL DEFAULT 1,
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (user_id, key_name)
		);`,
	}

	for i, q := range queries {
		if _, err := pool.Exec(ctx, q); err != nil {
			log.Printf("Failed to run SQL migration step %d: %v\n", i+1, err)
			return err
		}
	}

	log.Println("Database schemas migrated successfully!")
	return nil
}
