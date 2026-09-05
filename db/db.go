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
		// 1. Users table (Username + Bcrypt Password + Identity Key)
		`CREATE TABLE IF NOT EXISTS users (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			username VARCHAR(64) UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			identity_key TEXT NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);`,

		// 2. Devices table (Multi-device management)
		`CREATE TABLE IF NOT EXISTS devices (
			user_id UUID REFERENCES users(id) ON DELETE CASCADE,
			device_id INT NOT NULL, -- 1: Primary Phone, 2+: Secondary Devices
			name VARCHAR(128) NOT NULL,
			push_token TEXT,
			platform VARCHAR(32) DEFAULT 'unknown',
			last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (user_id, device_id)
		);`,

		// 3. Signed Prekey table (per device_id)
		`CREATE TABLE IF NOT EXISTS signed_prekeys (
			user_id UUID NOT NULL,
			device_id INT NOT NULL,
			key_id INT NOT NULL,
			public_key TEXT NOT NULL,
			signature TEXT NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (user_id, device_id),
			FOREIGN KEY (user_id, device_id) REFERENCES devices(user_id, device_id) ON DELETE CASCADE
		);`,

		// 4. One-Time Prekeys table (per device_id)
		`CREATE TABLE IF NOT EXISTS one_time_prekeys (
			id SERIAL PRIMARY KEY,
			user_id UUID NOT NULL,
			device_id INT NOT NULL,
			key_id INT NOT NULL,
			public_key TEXT NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id, device_id) REFERENCES devices(user_id, device_id) ON DELETE CASCADE,
			UNIQUE (user_id, device_id, key_id)
		);`,

		// 5. Offline messages queue (per recipient device_id)
		`CREATE TABLE IF NOT EXISTS offline_messages (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			recipient_id UUID NOT NULL,
			recipient_device_id INT NOT NULL DEFAULT 1,
			sender_id UUID,
			ciphertext TEXT NOT NULL,
			ephemeral_key TEXT,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (recipient_id, recipient_device_id) REFERENCES devices(user_id, device_id) ON DELETE CASCADE
		);`,

		// 6. Encrypted Key-Value store (Storage Service)
		`CREATE TABLE IF NOT EXISTS encrypted_storage (
			user_id UUID REFERENCES users(id) ON DELETE CASCADE,
			key_name VARCHAR(255) NOT NULL,
			value_blob BYTEA NOT NULL,
			version INT NOT NULL DEFAULT 1,
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (user_id, key_name)
		);`,

		// 7. Encrypted Media Attachments table (Zero-Knowledge Storage)
		`CREATE TABLE IF NOT EXISTS attachments (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			uploader_id UUID REFERENCES users(id) ON DELETE SET NULL,
			size_bytes BIGINT NOT NULL,
			digest_sha256 TEXT NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);`,

		// 8. Groups table (Signal Group V2)
		`CREATE TABLE IF NOT EXISTS groups (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			title_ciphertext TEXT NOT NULL,
			avatar_url TEXT,
			creator_id UUID REFERENCES users(id) ON DELETE SET NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);`,

		// 9. Group Members table
		`CREATE TABLE IF NOT EXISTS group_members (
			group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
			user_id UUID REFERENCES users(id) ON DELETE CASCADE,
			role VARCHAR(32) DEFAULT 'member',
			joined_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (group_id, user_id)
		);`,

		// 10. Group Sender Keys table (Signal Sender Keys Protocol)
		`CREATE TABLE IF NOT EXISTS group_sender_keys (
			group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
			sender_id UUID REFERENCES users(id) ON DELETE CASCADE,
			device_id INT NOT NULL,
			sender_key_blob TEXT NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (group_id, sender_id, device_id)
		);`,
	}

	for i, q := range queries {
		if _, err := pool.Exec(ctx, q); err != nil {
			log.Printf("Failed to run SQL migration step %d: %v\n", i+1, err)
			return err
		}
	}

	log.Println("Database schemas migrated successfully for Multi-Device!")
	return nil
}
