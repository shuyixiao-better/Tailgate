package secret

import (
	"encoding/base64"
	"testing"
)

func TestPasswordRoundTripAndTampering(t *testing.T) {
	directory := t.TempDir()
	protector, err := New(directory)
	if err != nil {
		t.Fatal(err)
	}
	const password = "sensitive-密码-$value"
	encrypted, err := protector.Encrypt(password)
	if err != nil {
		t.Fatal(err)
	}
	if encrypted == password {
		t.Fatal("password is unprotected")
	}
	other, err := New(directory)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := other.Decrypt(encrypted)
	if err != nil || plaintext != password {
		t.Fatalf("round trip: %v", err)
	}
	blob, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	blob[len(blob)-1] ^= 1
	if _, err := protector.Decrypt(base64.StdEncoding.EncodeToString(blob)); err == nil {
		t.Fatal("accepted tampered ciphertext")
	}
	if _, err := protector.Decrypt("not valid base64!"); err == nil {
		t.Fatal("accepted invalid blob")
	}
}
