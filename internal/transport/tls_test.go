package transport

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"tailgate/internal/config"
	"testing"
)

func TestSelfSignedReusableAndTrusted(t *testing.T) {
	dir := t.TempDir()
	s := config.Default().Server
	s.Listen = "127.0.0.1:8722"
	s.TLS.Enabled = true
	c, e := TLS(dir, s)
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := x509.ParseCertificate(c.Certificates[0].Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "127.0.0.1"}); e != nil {
		t.Fatal(e)
	}
	again, e := TLS(dir, s)
	if e != nil {
		t.Fatal(e)
	}
	if string(again.Certificates[0].Certificate[0]) != string(c.Certificates[0].Certificate[0]) {
		t.Fatal("certificate changed during restart")
	}
	stat, e := os.Stat(filepath.Join(dir, "tls", "server.key"))
	if e != nil || stat.Mode().Perm()&0077 != 0 {
		t.Fatal("private key permissions", e)
	}
}
func TestCustomMissingAndDisabled(t *testing.T) {
	s := config.Default().Server
	if c, e := TLS(t.TempDir(), s); e != nil || c != nil {
		t.Fatal(c, e)
	}
	s.TLS.Enabled = true
	s.TLS.AutoSelfSigned = false
	s.TLS.CertFile = "missing.crt"
	s.TLS.KeyFile = "missing.key"
	if _, e := TLS(t.TempDir(), s); e == nil {
		t.Fatal("missing pair accepted")
	}
}
