package message

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins in dev environment
	},
}

// WSMessage defines the format of messages sent/received via WebSocket
type WSMessage struct {
	Event       string          `json:"event"`        // "message", "signaling", "ack"
	SenderID    string          `json:"sender_id"`    // Sender UUID
	RecipientID string          `json:"recipient_id"` // Recipient UUID
	Data        json.RawMessage `json:"data"`         // Encrypted payload or sdp/ice candidate data
	Timestamp   int64           `json:"timestamp"`
}

// Client represents an active WebSocket connection
type Client struct {
	UUID string
	Conn *websocket.Conn
	Send chan []byte
	Hub  *Hub
}

// Hub manages all active Clients
type Hub struct {
	clients    map[string]*Client // key: User UUID
	register   chan *Client
	unregister chan *Client
	mutex      sync.RWMutex
	db         *pgxpool.Pool
}

func NewHub(db *pgxpool.Pool) *Hub {
	return &Hub{
		clients:    make(map[string]*Client),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		db:         db,
	}
}

// Run listens for register/unregister events
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mutex.Lock()
			h.clients[client.UUID] = client
			h.mutex.Unlock()
			log.Printf("User %s is online.\n", client.UUID)

			// Deliver pending offline messages
			go h.deliverOfflineMessages(client)

		case client := <-h.unregister:
			h.mutex.Lock()
			if _, ok := h.clients[client.UUID]; ok {
				delete(h.clients, client.UUID)
				close(client.Send)
				log.Printf("User %s is offline.\n", client.UUID)
			}
			h.mutex.Unlock()
		}
	}
}

// RouteMessage routes a message to the active recipient or saves it to the offline queue
func (h *Hub) RouteMessage(msg *WSMessage) {
	h.mutex.RLock()
	client, online := h.clients[msg.RecipientID]
	h.mutex.RUnlock()

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		log.Println("Failed to marshal message:", err)
		return
	}

	if online {
		// Recipient is online -> send message instantly
		select {
		case client.Send <- msgBytes:
			// Send acknowledgment back to the sender
			h.sendACK(msg.SenderID, msg.RecipientID, msg.Event)
		default:
			// Buffer full -> handle as offline
			h.queueOfflineMessage(msg)
		}
	} else {
		// Recipient is offline -> save to DB
		h.queueOfflineMessage(msg)
	}
}

// queueOfflineMessage saves an offline message to PostgreSQL
func (h *Hub) queueOfflineMessage(msg *WSMessage) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var payload struct {
		Ciphertext   string `json:"ciphertext"`
		EphemeralKey string `json:"ephemeral_key"`
	}
	_ = json.Unmarshal(msg.Data, &payload)

	query := `
		INSERT INTO offline_messages (id, recipient_id, sender_id, ciphertext, ephemeral_key)
		VALUES (gen_random_uuid(), $1, $2, $3, $4)
	`
	_, err := h.db.Exec(ctx, query, msg.RecipientID, msg.SenderID, payload.Ciphertext, payload.EphemeralKey)
	if err != nil {
		log.Printf("Failed to save offline message for %s: %v\n", msg.RecipientID, err)
		return
	}
	log.Printf("Saved 1 offline message for %s.\n", msg.RecipientID)
}

// deliverOfflineMessages retrieves offline messages, sends them, and deletes them from DB
func (h *Hub) deliverOfflineMessages(client *Client) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	query := `
		SELECT id, sender_id, ciphertext, ephemeral_key, created_at 
		FROM offline_messages 
		WHERE recipient_id = $1 
		ORDER BY created_at ASC
	`
	rows, err := h.db.Query(ctx, query, client.UUID)
	if err != nil {
		log.Println("Failed to query offline messages:", err)
		return
	}
	defer rows.Close()

	type PendingMessage struct {
		ID           string
		SenderID     *string
		Ciphertext   string
		EphemeralKey *string
		CreatedAt    time.Time
	}

	var pending []PendingMessage
	for rows.Next() {
		var pm PendingMessage
		err := rows.Scan(&pm.ID, &pm.SenderID, &pm.Ciphertext, &pm.EphemeralKey, &pm.CreatedAt)
		if err != nil {
			log.Println("Failed to scan offline message row:", err)
			continue
		}
		pending = append(pending, pm)
	}

	if len(pending) == 0 {
		return
	}

	log.Printf("Delivering %d pending offline messages to user %s...\n", len(pending), client.UUID)

	// Send each message and delete it from database
	for _, pm := range pending {
		sender := ""
		if pm.SenderID != nil {
			sender = *pm.SenderID
		}
		ephemeral := ""
		if pm.EphemeralKey != nil {
			ephemeral = *pm.EphemeralKey
		}

		dataMap := map[string]string{
			"ciphertext":    pm.Ciphertext,
			"ephemeral_key": ephemeral,
		}
		dataBytes, _ := json.Marshal(dataMap)

		wsMsg := WSMessage{
			Event:       "message",
			SenderID:    sender,
			RecipientID: client.UUID,
			Data:        dataBytes,
			Timestamp:   pm.CreatedAt.Unix(),
		}

		msgBytes, _ := json.Marshal(wsMsg)
		client.Send <- msgBytes

		// Delete from offline queue immediately on successful delivery
		_, err = h.db.Exec(ctx, "DELETE FROM offline_messages WHERE id = $1", pm.ID)
		if err != nil {
			log.Printf("Warning: Could not delete message %s after delivery: %v\n", pm.ID, err)
		}
	}
}

// sendACK sends a delivery acknowledgment back to the sender
func (h *Hub) sendACK(senderID, recipientID, originEvent string) {
	h.mutex.RLock()
	client, online := h.clients[senderID]
	h.mutex.RUnlock()

	if !online {
		return
	}

	ackData, _ := json.Marshal(map[string]string{
		"recipient_id": recipientID,
		"origin_event": originEvent,
		"status":       "delivered",
	})

	ackMsg := WSMessage{
		Event:     "ack",
		SenderID:  "server",
		Timestamp: time.Now().Unix(),
		Data:      ackData,
	}

	msgBytes, _ := json.Marshal(ackMsg)
	select {
	case client.Send <- msgBytes:
	default:
	}
}

// ReadPump listens for incoming messages from the client
func (c *Client) ReadPump() {
	defer func() {
		c.Hub.unregister <- c
		c.Conn.Close()
	}()

	c.Conn.SetReadLimit(4096) // 4KB limit to prevent DOS
	c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.Conn.SetPongHandler(func(string) error {
		c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := c.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("Unexpected close connection error for %s: %v\n", c.UUID, err)
			}
			break
		}

		var msg WSMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			log.Println("Invalid WebSocket message format received:", err)
			continue
		}

		msg.SenderID = c.UUID // Prevent client from spoofing sender UUID
		msg.Timestamp = time.Now().Unix()

		// Route message or WebRTC signaling event
		if msg.Event == "message" || msg.Event == "signaling" {
			c.Hub.RouteMessage(&msg)
		}
	}
}

// WritePump pushes data from the Send channel to the client connection
func (c *Client) WritePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.Conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.Send:
			c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.Conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			n := len(c.Send)
			for i := 0; i < n; i++ {
				w.Write([]byte{'\n'})
				w.Write(<-c.Send)
			}

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// ServeWS upgrades HTTP to WebSocket and registers it into the Hub
func ServeWS(hub *Hub, w http.ResponseWriter, r *http.Request) {
	userUUID := r.URL.Query().Get("uuid")
	if userUUID == "" {
		http.Error(w, "Missing UUID query parameter", http.StatusBadRequest)
		return
	}

	// Verify user exists in database before allowing socket connection
	var exists bool
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := hub.db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)", userUUID).Scan(&exists)
	if err != nil || !exists {
		http.Error(w, "Unauthorized: User not found in database", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Failed to upgrade HTTP to WebSocket:", err)
		return
	}

	client := &Client{
		UUID: userUUID,
		Conn: conn,
		Send: make(chan []byte, 256),
		Hub:  hub,
	}

	client.Hub.register <- client

	go client.WritePump()
	go client.ReadPump()
}
