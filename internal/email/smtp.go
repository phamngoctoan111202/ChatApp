package email

import (
	"fmt"
	"net/smtp"
	"os"
	"strings"

	"chat-app/internal/logger"
)

// SendEmailOTP sends a 6-digit verification code to the recipient email
func SendEmailOTP(toEmail string, otpCode string) error {
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	smtpUser := os.Getenv("SMTP_USERNAME")
	smtpPass := os.Getenv("SMTP_PASSWORD")
	fromEmail := os.Getenv("SMTP_FROM")

	if smtpPort == "" {
		smtpPort = "587"
	}
	if fromEmail == "" {
		fromEmail = "noreply@chatapp.e2ee"
	}

	// Dev Mode fallback: Print OTP code to server logs if SMTP is not configured
	if smtpHost == "" || smtpUser == "" {
		logger.Log.Info("📧 [DEV MODE EMAIL OTP]", "to", toEmail, "otp_code", otpCode)
		return nil
	}

	subject := "Subject: ChatApp E2EE - Email Verification Code\n"
	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	body := fmt.Sprintf(`
		<!DOCTYPE html>
		<html>
		<head><meta charset="utf-8"></head>
		<body style="font-family: Arial, sans-serif; background-color: #f4f6f8; padding: 20px;">
			<div style="max-width: 500px; margin: 0 auto; background: #ffffff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
				<h2 style="color: #075E54; margin-top: 0;">ChatApp E2EE Verification</h2>
				<p style="color: #333333; size: 14px;">Your 6-digit email verification code is:</p>
				<div style="background: #E8F5E9; padding: 15px; text-align: center; border-radius: 6px; font-size: 28px; font-weight: bold; letter-spacing: 5px; color: #2E7D32;">
					%s
				</div>
				<p style="color: #666666; font-size: 12px; margin-top: 20px;">This code will expire in 5 minutes. If you did not request this code, please ignore this email.</p>
			</div>
		</body>
		</html>
	`, otpCode)

	msg := []byte(subject + mime + body)
	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)

	addr := fmt.Sprintf("%s:%s", smtpHost, smtpPort)
	err := smtp.SendMail(addr, auth, fromEmail, []string{strings.TrimSpace(toEmail)}, msg)
	if err != nil {
		logger.Log.Error("Failed to send SMTP email", "err", err, "to", toEmail)
		return err
	}

	logger.Log.Info("SMTP Email OTP sent successfully", "to", toEmail)
	return nil
}
