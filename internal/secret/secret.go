// Package secret protects SSH passwords at rest using the operating system.
package secret

import (
	"encoding/base64"
	"fmt"
)

func (p *Protector) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", fmt.Errorf("encrypt password: password must not be empty")
	}
	blob, err := p.encrypt([]byte(plaintext))
	if err != nil {
		return "", fmt.Errorf("encrypt password: %w", err)
	}
	return base64.StdEncoding.EncodeToString(blob), nil
}

func (p *Protector) Decrypt(encoded string) (string, error) {
	blob, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode encrypted password: invalid base64")
	}
	plaintext, err := p.decrypt(blob)
	if err != nil {
		return "", fmt.Errorf("decrypt password: %w", err)
	}
	defer clear(plaintext)
	return string(plaintext), nil
}
