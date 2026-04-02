package utils_test

// Security tests for crypto utility functions. These verify defense against
// weak key generation and misconfiguration.
//
// References:
//   - NIST SP 800-57 (https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final):
//     Minimum 2048-bit RSA keys required through 2030
//   - CWE-326 (https://cwe.mitre.org/data/definitions/326.html):
//     Inadequate Encryption Strength

import (
	"testing"

	"github.com/panyam/oneauth/utils"
	"github.com/stretchr/testify/assert"
)

// TestCrypto_RSAKeySize_TooSmall verifies that GenerateRSAKeyPair rejects
// key sizes below 2048 bits. NIST SP 800-57 requires minimum 2048-bit RSA
// keys. Keys of 512 or 1024 bits can be factored with commodity hardware.
//
// BEFORE FIX: succeeds (generates insecure 1024-bit key)
// AFTER FIX: returns error
//
// See: https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final
// See: https://cwe.mitre.org/data/definitions/326.html
func TestCrypto_RSAKeySize_TooSmall(t *testing.T) {
	weakSizes := []int{512, 1024}
	for _, bits := range weakSizes {
		_, _, err := utils.GenerateRSAKeyPair(bits)
		assert.Error(t, err, "GenerateRSAKeyPair(%d) should reject weak key size", bits)
	}
}

// TestCrypto_RSAKeySize_2048_OK verifies that 2048-bit keys are accepted
// (the minimum allowed).
func TestCrypto_RSAKeySize_2048_OK(t *testing.T) {
	privPEM, pubPEM, err := utils.GenerateRSAKeyPair(2048)
	assert.NoError(t, err)
	assert.NotEmpty(t, privPEM)
	assert.NotEmpty(t, pubPEM)
}

// TestCrypto_RSAKeySize_4096_OK verifies that 4096-bit keys are accepted.
func TestCrypto_RSAKeySize_4096_OK(t *testing.T) {
	privPEM, pubPEM, err := utils.GenerateRSAKeyPair(4096)
	assert.NoError(t, err)
	assert.NotEmpty(t, privPEM)
	assert.NotEmpty(t, pubPEM)
}
