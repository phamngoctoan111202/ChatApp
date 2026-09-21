package db

import (
	"context"
	"log"
	"os"
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
	if os.Getenv("RESET_DB") == "true" || os.Getenv("DROP_DB") == "true" {
		log.Println("RESET_DB environment variable detected! Dropping existing tables for a clean slate reset...")
		dropQuery := `DROP TABLE IF EXISTS live_locations, message_reactions, pinned_messages, poll_votes, polls, blocked_users, group_sender_keys, group_members, groups, attachments, encrypted_storage, offline_messages, one_time_prekeys, signed_prekeys, identity_keys, devices, auth_identities, users CASCADE;`
		if _, err := pool.Exec(ctx, dropQuery); err != nil {
			log.Printf("Warning: Failed to drop legacy tables: %v\n", err)
		} else {
			log.Println("Database reset successful!")
		}
	}

	queries := []string{
		// 1. Users table (Username + Password + Identity Key + Phone Number + Email + Signal PIN)
		`CREATE TABLE IF NOT EXISTS users (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			username VARCHAR(64) UNIQUE,
			password_hash TEXT,
			phone_number VARCHAR(64) UNIQUE,
			email VARCHAR(255) UNIQUE,
			email_verified BOOLEAN DEFAULT FALSE,
			avatar_url TEXT,
			signal_pin_hash TEXT,
			identity_key TEXT,
			is_online BOOLEAN DEFAULT FALSE,
			last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);`,

		// 1b. Additional columns for legacy user schemas
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_number VARCHAR(64) UNIQUE;`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(255) UNIQUE;`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT FALSE;`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT;`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_online BOOLEAN DEFAULT FALSE;`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;`,
		`ALTER TABLE users ALTER COLUMN username DROP NOT NULL;`,
		`ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;`,
		`ALTER TABLE users ALTER COLUMN identity_key DROP NOT NULL;`,

		// 2. Auth Identities table (Maps Google/Apple/Passkey IDs to user_id)
		`CREATE TABLE IF NOT EXISTS auth_identities (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID REFERENCES users(id) ON DELETE CASCADE,
			provider VARCHAR(32) NOT NULL,
			provider_user_id VARCHAR(255) NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			CONSTRAINT unique_provider_user UNIQUE(provider, provider_user_id)
		);`,

		// 3. Devices table (Multi-device management)
		`CREATE TABLE IF NOT EXISTS devices (
			user_id UUID REFERENCES users(id) ON DELETE CASCADE,
			device_id INT NOT NULL,
			device_name VARCHAR(128) NOT NULL DEFAULT 'Primary Device',
			push_token TEXT,
			platform VARCHAR(32) DEFAULT 'primary',
			last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (user_id, device_id)
		);`,
		`ALTER TABLE devices ADD COLUMN IF NOT EXISTS device_name VARCHAR(128) DEFAULT 'Primary Device';`,
		`ALTER TABLE devices ADD COLUMN IF NOT EXISTS name VARCHAR(128) DEFAULT 'Primary Device';`,
		`ALTER TABLE devices ALTER COLUMN name DROP NOT NULL;`,

		// Auto-heal legacy users without a primary device row (device_id = 1)
		`INSERT INTO devices (user_id, device_id, device_name, name, platform, created_at, last_seen)
		 SELECT id, 1, 'Primary Device', 'Primary Device', 'primary', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP FROM users
		 ON CONFLICT (user_id, device_id) DO NOTHING;`,

		// 4. Identity Keys table (Multi-device Identity Keys)
		`CREATE TABLE IF NOT EXISTS identity_keys (
			user_id UUID NOT NULL,
			device_id INT NOT NULL,
			identity_key TEXT NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (user_id, device_id),
			FOREIGN KEY (user_id, device_id) REFERENCES devices(user_id, device_id) ON DELETE CASCADE
		);`,

		// 5. Signed Prekey table (per device_id)
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

		// 6. One-Time Prekeys table (per device_id)
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

		// 7. Offline messages queue (per recipient device_id)
		`CREATE TABLE IF NOT EXISTS offline_messages (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			recipient_id UUID NOT NULL,
			recipient_device_id INT NOT NULL DEFAULT 1,
			sender_id UUID,
			ciphertext TEXT NOT NULL,
			ephemeral_key TEXT,
			ephemeral_ttl_seconds INT DEFAULT 0,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (recipient_id, recipient_device_id) REFERENCES devices(user_id, device_id) ON DELETE CASCADE
		);`,

		// 8. Encrypted Key-Value store (Storage Service)
		`CREATE TABLE IF NOT EXISTS encrypted_storage (
			user_id UUID REFERENCES users(id) ON DELETE CASCADE,
			key_name VARCHAR(255) NOT NULL,
			value_blob BYTEA NOT NULL,
			version INT NOT NULL DEFAULT 1,
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (user_id, key_name)
		);`,

		// 9. Encrypted Media Attachments table (Zero-Knowledge Storage)
		`CREATE TABLE IF NOT EXISTS attachments (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			uploader_id UUID REFERENCES users(id) ON DELETE SET NULL,
			size_bytes BIGINT NOT NULL,
			digest_sha256 TEXT NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);`,

		// 10. Groups table (Signal Group V2)
		`CREATE TABLE IF NOT EXISTS groups (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			title_ciphertext TEXT NOT NULL,
			avatar_url TEXT,
			creator_id UUID REFERENCES users(id) ON DELETE SET NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);`,

		// 11. Group Members table
		`CREATE TABLE IF NOT EXISTS group_members (
			group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
			user_id UUID REFERENCES users(id) ON DELETE CASCADE,
			role VARCHAR(32) DEFAULT 'member',
			joined_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (group_id, user_id)
		);`,

		// 12. Group Sender Keys table (Signal Sender Keys Protocol)
		`CREATE TABLE IF NOT EXISTS group_sender_keys (
			group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
			sender_id UUID REFERENCES users(id) ON DELETE CASCADE,
			device_id INT NOT NULL,
			sender_key_blob TEXT NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (group_id, sender_id, device_id)
		);`,

		// 13. Blocked / Restricted Users table
		`CREATE TABLE IF NOT EXISTS blocked_users (
			blocker_id UUID REFERENCES users(id) ON DELETE CASCADE,
			blocked_id UUID REFERENCES users(id) ON DELETE CASCADE,
			mode VARCHAR(32) DEFAULT 'block',
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (blocker_id, blocked_id)
		);`,

		// 14. Polls table
		`CREATE TABLE IF NOT EXISTS polls (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
			creator_id UUID REFERENCES users(id) ON DELETE CASCADE,
			question_ciphertext TEXT NOT NULL,
			options_json JSONB NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);`,

		// 15. Poll Votes table
		`CREATE TABLE IF NOT EXISTS poll_votes (
			poll_id UUID REFERENCES polls(id) ON DELETE CASCADE,
			user_id UUID REFERENCES users(id) ON DELETE CASCADE,
			option_index INT NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (poll_id, user_id)
		);`,

		// 16. Pinned Messages table
		`CREATE TABLE IF NOT EXISTS pinned_messages (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			chat_id VARCHAR(128) NOT NULL,
			message_id VARCHAR(128) NOT NULL,
			pinned_by UUID REFERENCES users(id) ON DELETE CASCADE,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			CONSTRAINT unique_chat_message_pin UNIQUE(chat_id, message_id)
		);`,

		// 17. Message Emoji Reactions table
		`CREATE TABLE IF NOT EXISTS message_reactions (
			message_id VARCHAR(128) NOT NULL,
			user_id UUID REFERENCES users(id) ON DELETE CASCADE,
			emoji VARCHAR(32) NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (message_id, user_id, emoji)
		);`,

		// 18. Live Location Sharing table
		`CREATE TABLE IF NOT EXISTS live_locations (
			user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
			latitude DOUBLE PRECISION NOT NULL,
			longitude DOUBLE PRECISION NOT NULL,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);`,

		// 19. Performance Indexing for High Scale
		`CREATE INDEX IF NOT EXISTS idx_offline_messages_lookup ON offline_messages(recipient_id, recipient_device_id, created_at ASC);`,
		`CREATE INDEX IF NOT EXISTS idx_one_time_prekeys_lookup ON one_time_prekeys(user_id, device_id);`,
		`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);`,
		`CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone_number);`,
		`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);`,
		`CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id, device_id);`,
		`CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(user_id);`,
	}

	for i, q := range queries {
		if _, err := pool.Exec(ctx, q); err != nil {
			log.Printf("Failed to run SQL migration step %d: %v\n", i+1, err)
			return err
		}
	}

	log.Println("Database schemas and production indexes initialized successfully!")
	return nil
}
