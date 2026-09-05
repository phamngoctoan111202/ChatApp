package message

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"chat-app/internal/auth"
	"chat-app/internal/redis"
	"chat-app/internal/sealed"

	"github.com/gorilla/websocket"
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
	Event             string                    `json:"event"`                         // "message", "signaling", "ack"
	SenderID          string                    `json:"sender_id,omitempty"`           // Sender User UUID (Empty for Sealed Sender)
	SenderDeviceID    int                       `json:"sender_device_id,omitempty"`    // Sender Device ID
	RecipientID       string                    `json:"recipient_id"`                  // Recipient User UUID
	RecipientDeviceID int                       `json:"recipient_device_id,omitempty"` // Specific Recipient Device ID (0 = Fan-out)
	IsSealed          bool                      `json:"is_sealed,omitempty"`           // True if using Sealed Sender protocol
	SealedCertificate *sealed.SenderCertificate `json:"sealed_certificate,omitempty"`  // Unidentified Delivery Certificate
	Data              json.RawMessage           `json:"data"`                          // Encrypted payload
	Timestamp         int64                     `json:"timestamp"`
}

// Client represents an active WebSocket connection
type Client struct {
	UserID   string
	DeviceID int
	Conn     *websocket.Conn
	Send     chan []byte
	Hub      *Hub
}

// Hub manages all active Clients
type Hub struct {
	clients    map[string]map[int]*Client // map[UserID]map[DeviceID]*Client
	register   chan *Client
	unregister chan *Client
	mutex      sync.RWMutex
	db         *pgxpool.Pool
	redis      *redis.RedisService
}

func NewHub(db *pgxpool.Pool, redisSvc *redis.RedisService) *Hub {
	return &Hub{
		clients:    make(map[string]map[int]*Client),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		db:         db,
		redis:      redisSvc,
	}
}

// Run listens for client registration/unregistration events
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mutex.Lock()
			if _, ok := h.clients[client.UserID]; !ok {
				h.clients[client.UserID] = make(map[int]*Client)
			}
			h.clients[client.UserID][client.DeviceID] = client
			h.mutex.Unlock()

			log.Printf("User %s (Device %d) is online via WebSocket.\n", client.UserID, client.DeviceID)

			// Deliver pending offline messages for this device
			go h.deliverOfflineMessages(client)

			// Subscribe to Redis PubSub for this device
			go h.subscribeDeviceRedis(client)

		case client := <-h.unregister:
			h.mutex.Lock()
			if devMap, ok := h.clients[client.UserID]; ok {
				if _, exists := devMap[client.DeviceID]; exists {
					delete(devMap, client.DeviceID)
					close(client.Send)
					log.Printf("User %s (Device %d) disconnected.\n", client.UserID, client.DeviceID)
				}
				if len(devMap) == 0 {
					delete(h.clients, client.UserID)
				}
			}
			h.mutex.Unlock()
		}
	}
}

// subscribeDeviceRedis listens for incoming Redis PubSub messages for client
func (h *Hub) subscribeDeviceRedis(client *Client) {
	if h.redis == nil || h.redis.Client == nil {
		return
	}

	channel := "signal:msg:" + client.UserID + ":" + strconv.Itoa(client.DeviceID)
	pubsub := h.redis.SubscribeChannel(context.Background(), channel)
	if pubsub == nil {
		return
	}
	defer pubsub.Close()

	ch := pubsub.Channel()
	for msg := range ch {
		select {
		case client.Send <- []byte(msg.Payload):
		default:
		}
	}
}

// RouteMessage performs Multi-Device Fan-Out routing to recipient devices AND sender secondary devices
func (h *Hub) RouteMessage(msg *WSMessage) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	senderUserID := msg.SenderID
	senderDevID := msg.SenderDeviceID

	// Handle Sealed Sender Verification (Anonymized Sender Envelope)
	if msg.IsSealed {
		if err := sealed.VerifyCertificate(msg.SealedCertificate); err != nil {
			log.Printf("Sealed Sender rejection: Invalid or expired certificate (%v)\n", err)
			return
		}
		// Extract identity internally for routing, but keep outer envelope SenderID anonymous
		senderUserID = msg.SealedCertificate.UserID
		senderDevID = msg.SealedCertificate.DeviceID
	}

	// 1. Get all active target devices for Recipient
	recipientDevices := h.getUserDeviceIDs(ctx, msg.RecipientID)

	// 2. Get all active target devices for Sender (for syncing sent message to sender's other devices)
	senderDevices := h.getUserDeviceIDs(ctx, senderUserID)

	// Anonymize sender in outer message payload if Sealed Sender is used
	msgToSend := *msg
	if msg.IsSealed {
		msgToSend.SenderID = ""
		msgToSend.SenderDeviceID = 0
	}

	// Route to all recipient devices
	for _, devID := range recipientDevices {
		h.deliverOrQueue(ctx, msg.RecipientID, devID, &msgToSend, senderUserID)
	}

	// Route to sender's secondary devices (excluding current sender device)
	for _, devID := range senderDevices {
		if devID != senderDevID {
			h.deliverOrQueue(ctx, senderUserID, devID, &msgToSend, senderUserID)
		}
	}

	// Send ACK back to sender's origin device
	h.sendACK(senderUserID, senderDevID, msg.RecipientID, msg.Event)
}

func (h *Hub) getUserDeviceIDs(ctx context.Context, userID string) []int {
	rows, err := h.db.Query(ctx, "SELECT device_id FROM devices WHERE user_id = $1", userID)
	if err != nil {
		return []int{1} // Fallback to primary device 1
	}
	defer rows.Close()

	var devIDs []int
	for rows.Next() {
		var devID int
		if err := rows.Scan(&devID); err == nil {
			devIDs = append(devIDs, devID)
		}
	}
	if len(devIDs) == 0 {
		return []int{1}
	}
	return devIDs
}

func (h *Hub) deliverOrQueue(ctx context.Context, targetUserID string, targetDeviceID int, msg *WSMessage, actualSenderID string) {
	msgCopy := *msg
	msgCopy.RecipientID = targetUserID
	msgCopy.RecipientDeviceID = targetDeviceID

	msgBytes, err := json.Marshal(msgCopy)
	if err != nil {
		return
	}

	h.mutex.RLock()
	client, online := h.clients[targetUserID][targetDeviceID]
	h.mutex.RUnlock()

	if online {
		select {
		case client.Send <- msgBytes:
			return
		default:
			// Buffer full -> fallback to offline queue
		}
	}

	// Try Redis PubSub publishing if running in cluster mode
	if h.redis != nil && h.redis.Client != nil {
		channel := "signal:msg:" + targetUserID + ":" + strconv.Itoa(targetDeviceID)
		err := h.redis.PublishMessage(ctx, channel, msgBytes)
		if err == nil {
			return
		}
	}

	// Target device is offline -> queue to PostgreSQL
	h.queueOfflineMessage(ctx, targetUserID, targetDeviceID, &msgCopy, actualSenderID)
}

func (h *Hub) queueOfflineMessage(ctx context.Context, recipientID string, recipientDeviceID int, msg *WSMessage, actualSenderID string) {
	var payload struct {
		Ciphertext   string `json:"ciphertext"`
		EphemeralKey string `json:"ephemeral_key"`
	}
	_ = json.Unmarshal(msg.Data, &payload)

	var dbSenderID *string
	if !msg.IsSealed && actualSenderID != "" {
		dbSenderID = &actualSenderID
	}

	query := `
		INSERT INTO offline_messages (id, recipient_id, recipient_device_id, sender_id, ciphertext, ephemeral_key)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, $5)
	`
	_, err := h.db.Exec(ctx, query, recipientID, recipientDeviceID, dbSenderID, payload.Ciphertext, payload.EphemeralKey)
	if err != nil {
		log.Printf("Failed to save offline message for user %s (device %d): %v\n", recipientID, recipientDeviceID, err)
		return
	}
	log.Printf("Saved 1 offline message for user %s (device %d) [Sealed: %v].\n", recipientID, recipientDeviceID, msg.IsSealed)
}

func (h *Hub) deliverOfflineMessages(client *Client) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	query := `
		SELECT id, sender_id, ciphertext, ephemeral_key, created_at 
		FROM offline_messages 
		WHERE recipient_id = $1 AND recipient_device_id = $2
		ORDER BY created_at ASC
	`
	rows, err := h.db.Query(ctx, query, client.UserID, client.DeviceID)
	if err != nil {
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
		if err := rows.Scan(&pm.ID, &pm.SenderID, &pm.Ciphertext, &pm.EphemeralKey, &pm.CreatedAt); err == nil {
			pending = append(pending, pm)
		}
	}

	if len(pending) == 0 {
		return
	}

	log.Printf("Delivering %d pending offline messages to user %s (device %d)...\n", len(pending), client.UserID, client.DeviceID)

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
			Event:             "message",
			SenderID:          sender,
			RecipientID:       client.UserID,
			RecipientDeviceID: client.DeviceID,
			Data:              dataBytes,
			Timestamp:         pm.CreatedAt.Unix(),
		}

		msgBytes, _ := json.Marshal(wsMsg)
		client.Send <- msgBytes

		_, _ = h.db.Exec(ctx, "DELETE FROM offline_messages WHERE id = $1", pm.ID)
	}
}

func (h *Hub) sendACK(senderID string, senderDeviceID int, recipientID string, originEvent string) {
	h.mutex.RLock()
	client, online := h.clients[senderID][senderDeviceID]
	h.mutex.RUnlock()

	if !online {
		return
	}

	ackData, _ := json.Marshal(map[string]interface{}{
		"recipient_id": recipientID,
		"origin_event": originEvent,
		"status":       "delivered",
	})

	ackMsg := WSMessage{
		Event:             "ack",
		SenderID:          "server",
		RecipientID:       senderID,
		RecipientDeviceID: senderDeviceID,
		Timestamp:         time.Now().Unix(),
		Data:              ackData,
	}

	msgBytes, _ := json.Marshal(ackMsg)
	select {
	case client.Send <- msgBytes:
	default:
	}
}

func (c *Client) ReadPump() {
	defer func() {
		c.Hub.unregister <- c
		c.Conn.Close()
	}()

	c.Conn.SetReadLimit(4096)
	c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.Conn.SetPongHandler(func(string) error {
		c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := c.Conn.ReadMessage()
		if err != nil {
			break
		}

		var msg WSMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			continue
		}

		// Only populate SenderID for non-sealed messages to prevent spoofing
		if !msg.IsSealed {
			msg.SenderID = c.UserID
			msg.SenderDeviceID = c.DeviceID
		}
		msg.Timestamp = time.Now().Unix()

		if msg.Event == "message" || msg.Event == "signaling" {
			c.Hub.RouteMessage(&msg)
		}
	}
}

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

// ServeWS authenticates WebSocket connection via JWT token and registers Client with UserID & DeviceID
func ServeWS(hub *Hub, w http.ResponseWriter, r *http.Request) {
	// Extract JWT token from query parameter ?token=... or Authorization header
	tokenStr := r.URL.Query().Get("token")
	if tokenStr == "" {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenStr = strings.TrimPrefix(authHeader, "Bearer ")
		}
	}

	if tokenStr == "" {
		http.Error(w, "Unauthorized: Missing JWT token parameter or Bearer header", http.StatusUnauthorized)
		return
	}

	claims, err := auth.VerifyToken(tokenStr)
	if err != nil {
		http.Error(w, "Unauthorized: Invalid or expired JWT token", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Failed to upgrade HTTP connection to WebSocket:", err)
		return
	}

	client := &Client{
		UserID:   claims.UserID,
		DeviceID: claims.DeviceID,
		Conn:     conn,
		Send:     make(chan []byte, 256),
		Hub:      hub,
	}

	client.Hub.register <- client

	go client.WritePump()
	go client.ReadPump()
}
