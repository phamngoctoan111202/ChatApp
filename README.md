# Chat App Backend

High-performance, minimal, and secure End-to-End Encryption (E2EE) real-time messaging backend built with Go.

## 🚀 Core Features
1. **E2EE Cryptography Support (Signal Protocol X3DH):** Registration and pre-key bundle management (Identity Key, Signed Prekey, One-Time Prekeys) allowing clients to establish asymmetric encrypted channels securely.
2. **WebSocket Realtime Gateway:** Real-time message routing and WebRTC call signaling proxy (SDP/ICE Candidates) between client peers.
3. **Offline Message Queue:** Temporary message queuing when recipients are offline. Messages are delivered and immediately deleted upon reconnection (Zero-Knowledge delivery).
4. **Encrypted Storage Service:** Encrypted cloud Key-Value storage API for user contacts and device configurations without exposing plain text to the server.
5. **Media & Social Integrations:**
   - Image & Video Upload API (Stickers, Stories).
   - Anonymous GIF search proxy via Tenor API.
   - OpenGraph Link Preview parser.
6. **Anti-Spam & Rate Limiting:** Cloudflare Turnstile verification protecting authentication endpoints against automated bots.

## 🛠️ Tech Stack
* **Language:** Go 1.21+
* **HTTP/Router:** `go-chi/chi/v5`
* **Realtime Network:** `gorilla/websocket`
* **Database Driver:** `jackc/pgx/v5` & GORM (PostgreSQL)
* **Containerization:** Docker & Docker Compose

## 💻 Local Setup & Deployment

### 1. Requirements
* Installed **Docker** and **Docker Compose**.

### 2. Run Locally
Navigate to the repository directory and run Docker Compose:
```bash
docker compose up --build
```
The application will automatically initialize the PostgreSQL database, run SQL schema migrations, and launch the HTTP web server on port `8080`.

### 3. Verification & Health Check
* **API Health Check:**
  ```bash
  curl http://localhost:8080/health
  ```
  Expected Response: `{"status":"ok","timestamp":"..."}`
* **WebSocket Endpoint:** `ws://localhost:8080/ws?uuid=<user_uuid>`
