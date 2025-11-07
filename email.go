package oneauth

import "log"

// SendEmail interface allows applications to provide their own email sending implementation
type SendEmail interface {
	SendVerificationEmail(to string, verificationLink string) error
	SendPasswordResetEmail(to string, resetLink string) error
}

// ConsoleEmailSender is a development implementation that logs emails to console
type ConsoleEmailSender struct{}

func (c *ConsoleEmailSender) SendVerificationEmail(to string, verificationLink string) error {
	log.Printf("\n=== EMAIL: Verification ===")
	log.Printf("To: %s", to)
	log.Printf("Subject: Verify your email address")
	log.Printf("Body: Please verify your email by clicking: %s", verificationLink)
	log.Printf("===========================\n")
	return nil
}

func (c *ConsoleEmailSender) SendPasswordResetEmail(to string, resetLink string) error {
	log.Printf("\n=== EMAIL: Password Reset ===")
	log.Printf("To: %s", to)
	log.Printf("Subject: Reset your password")
	log.Printf("Body: Reset your password by clicking: %s", resetLink)
	log.Printf("==============================\n")
	return nil
}
