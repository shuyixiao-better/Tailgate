//go:build !windows

package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

type Protector struct{ aead cipher.AEAD }

// New uses a local owner-only AES-GCM key for development outside Windows.
func New(dataDir string) (*Protector, error) {
	slog.Warn("DPAPI is unavailable on this platform; using a local AES-GCM development key")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("create secret directory: %w", err)
	}
	keyPath := filepath.Join(dataDir, "secret.key")
	_, err := os.Stat(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		key := make([]byte, 32)
		defer clear(key)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("generate development key: %w", err)
		}
		file, err := os.CreateTemp(dataDir, ".tailgate-key-*")
		if err != nil {
			return nil, fmt.Errorf("create development key: %w", err)
		}
		temporary := file.Name()
		defer os.Remove(temporary)
		if err := file.Chmod(0600); err != nil {
			file.Close()
			return nil, fmt.Errorf("protect development key: %w", err)
		}
		if _, err := file.Write(key); err != nil {
			file.Close()
			return nil, fmt.Errorf("write development key: %w", err)
		}
		if err := file.Sync(); err != nil {
			file.Close()
			return nil, fmt.Errorf("sync development key: %w", err)
		}
		if err := file.Close(); err != nil {
			return nil, fmt.Errorf("close development key: %w", err)
		}
		if err := os.Link(temporary, keyPath); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("install development key: %w", err)
		}
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read development key: %w", err)
	}
	defer clear(key)
	info, err := os.Stat(keyPath)
	if err != nil {
		return nil, fmt.Errorf("inspect development key: %w", err)
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("development key permissions must be 0600 or stricter: %s", keyPath)
	}
	if len(key) != 32 {
		return nil, errors.New("development key must contain exactly 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create development cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create development AEAD: %w", err)
	}
	return &Protector{aead: aead}, nil
}

func (p *Protector) encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, p.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate encryption nonce: %w", err)
	}
	return p.aead.Seal(nonce, nonce, plaintext, []byte("Tailgate SSH password v1")), nil
}

func (p *Protector) decrypt(blob []byte) ([]byte, error) {
	if len(blob) < p.aead.NonceSize()+p.aead.Overhead() {
		return nil, errors.New("encrypted development password is too short")
	}
	plaintext, err := p.aead.Open(nil, blob[:p.aead.NonceSize()], blob[p.aead.NonceSize():], []byte("Tailgate SSH password v1"))
	if err != nil {
		return nil, errors.New("encrypted development password authentication failed")
	}
	return plaintext, nil
}
