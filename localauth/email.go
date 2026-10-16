package localauth

import "log"

// SendEmail lets applications provide their own email-sending implementation
// for localauth's verification-email and password-reset flows.
type SendEmail interface {
	SendVerificationEmail(to string, verificationLink string) error
	SendPasswordResetEmail(to string, resetLink string) error
}

// AccountExistsEmailSender is an optional extension of SendEmail. When the
// configured EmailSender implements it, a signup with an email that already
// has an account (and RequireEmailVerification on) sends the owner this
// notice instead of telling the requester the email is taken. link points
// at the forgot-password page, for an owner who has lost the password.
// Without it the owner hears nothing, and the requester still learns
// nothing.
type AccountExistsEmailSender interface {
	SendAccountExistsEmail(to string, link string) error
}

// ConsoleEmailSender is a development implementation that logs emails to console.
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
