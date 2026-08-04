# Chat App Backend

Backend dịch vụ nhắn tin thời gian thực hiệu năng cao, tối giản và hỗ trợ mã hóa đầu cuối (End-to-End Encryption - E2EE) bằng ngôn ngữ Go.

## 🚀 Các Tính Năng Cốt Lõi
1. **Mật mã học E2EE (X3DH):** Đăng ký và quản lý Prekey Bundles (Identity Key, Signed Prekey, One-Time Prekeys) hỗ trợ client tự thiết lập kênh mã hóa bất đối xứng.
2. **WebSocket Realtime Gateway:** Định tuyến tin nhắn thời gian thực và chuyển tiếp tín hiệu cuộc gọi WebRTC (SDP/ICE Candidates) giữa các client.
3. **Offline Message Queue:** Lưu trữ tạm thời tin nhắn khi người nhận ngoại tuyến. Đẩy tin nhắn đi và xóa ngay lập tức khi họ kết nối lại (Zero-Knowledge delivery).
4. **Encrypted Storage Service:** API lưu trữ đám mây mã hóa dạng Key-Value (lưu trữ danh bạ, cấu hình thiết bị mà server không thể đọc rõ nội dung).
5. **Media & Social:**
   * API Tải lên hình ảnh/video (Stickers, Stories).
   * Proxy tìm kiếm GIF ẩn danh qua Tenor API.
   * Parse xem trước liên kết (Link Preview OpenGraph).
6. **Anti-Spam & Rate Limit:** Xác thực Cloudflare Turnstile để chống bot đăng ký tài khoản tự động.

## 🛠️ Tech Stack
* **Language:** Go 1.21+
* **HTTP/Router:** `go-chi/chi/v5`
* **Realtime Network:** `gorilla/websocket`
* **Database Driver:** `jackc/pgx/v5` (PostgreSQL)
* **Containerization:** Docker & Docker Compose

## 💻 Hướng Dẫn Khởi Chạy Local

### 1. Yêu Cầu Hệ Thống
* Đã cài đặt **Docker** và **Docker Compose**.

### 2. Khởi chạy dự án
Di chuyển vào thư mục dự án và chạy Docker Compose:
```bash
docker compose up --build
```
Hệ thống sẽ tự động khởi tạo database PostgreSQL, chạy SQL Migrations cấu hình bảng và khởi động web server chạy tại cổng `8080`.

### 3. Kiểm tra hoạt động
* **API Health Check:**
  ```bash
  curl http://localhost:8080/health
  ```
  Trả về: `{"status":"healthy","message":"Chat App Backend is running"}`
* **WebSocket Endpoint:** `ws://localhost:8080/ws?uuid=<user_uuid>`
