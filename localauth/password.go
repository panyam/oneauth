package localauth

import "golang.org/x/crypto/bcrypt"

// HashPassword returns a bcrypt hash of password at bcrypt.DefaultCost.
// localauth keeps that form in a local channel's
// Credentials["password_hash"], so an app that writes accounts itself, such
// as an operator's command, stores what CheckPassword and the bundled
// credentials validators read. It returns bcrypt's error for a password
// longer than 72 bytes rather than hashing a truncated one.
func HashPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// CheckPassword reports whether password matches hash, a HashPassword
// result. Pass an empty hash when the account doesn't exist or has no
// password: CheckPassword then compares against a dummy hash and returns
// false, so a missing account takes as long to refuse as a wrong password
// and a caller can't be timed into revealing which accounts exist
// (CWE-208).
func CheckPassword(hash, password string) bool {
	if hash == "" {
		_ = bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(password))
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
