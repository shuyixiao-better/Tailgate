package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// Generate creates a cryptographically random credential. Only its hash is persisted.
func Generate() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate credential: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func Hash(token string) string { h := sha256.Sum256([]byte(token)); return hex.EncodeToString(h[:]) }
func Match(token, hash string) bool {
	expected, err := hex.DecodeString(hash)
	if err != nil || len(expected) != 32 {
		return false
	}
	h := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(h[:], expected) == 1
}
