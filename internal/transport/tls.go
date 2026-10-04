// Package transport prepares the gateway's optional TLS certificate.
package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"tailgate/internal/config"
	"time"
)

func TLS(dataDir string, settings config.Server) (*tls.Config, error) {
	if !settings.TLS.Enabled {
		return nil, nil
	}
	certPath, keyPath := settings.TLS.CertFile, settings.TLS.KeyFile
	if settings.TLS.AutoSelfSigned {
		certPath = filepath.Join(dataDir, "tls", "server.crt")
		keyPath = filepath.Join(dataDir, "tls", "server.key")
		if _, e := os.Stat(certPath); errors.Is(e, os.ErrNotExist) {
			if e = generate(certPath, keyPath, settings.Listen); e != nil {
				return nil, e
			}
		} else if e != nil {
			return nil, fmt.Errorf("inspect TLS certificate: %w", e)
		}
	} else {
		if !filepath.IsAbs(certPath) {
			certPath = filepath.Join(dataDir, certPath)
		}
		if !filepath.IsAbs(keyPath) {
			keyPath = filepath.Join(dataDir, keyPath)
		}
	}
	pair, e := tls.LoadX509KeyPair(certPath, keyPath)
	if e != nil {
		return nil, fmt.Errorf("load TLS certificate/key: %w", e)
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return nil, fmt.Errorf("parse TLS certificate: %w", e)
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, errors.New("TLS certificate is not currently valid; replace the certificate and trust the replacement on clients")
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}, nil
}
func generate(certPath, keyPath, listen string) error {
	if e := os.MkdirAll(filepath.Dir(certPath), 0700); e != nil {
		return fmt.Errorf("create TLS directory: %w", e)
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return fmt.Errorf("generate TLS key: %w", e)
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return e
	}
	serial.Add(serial, big.NewInt(1))
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Tailgate local gateway"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(3, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	dns := map[string]bool{}
	ips := map[string]bool{}
	add := func(value string) {
		value = strings.Trim(value, "[]")
		if ip := net.ParseIP(value); ip != nil {
			if !ip.IsUnspecified() && !ips[ip.String()] {
				cert.IPAddresses = append(cert.IPAddresses, ip)
				ips[ip.String()] = true
			}
		} else if value != "" && !dns[value] {
			cert.DNSNames = append(cert.DNSNames, value)
			dns[value] = true
		}
	}
	add("localhost")
	add("127.0.0.1")
	add("::1")
	if host, _, e := net.SplitHostPort(listen); e == nil {
		add(host)
	}
	if hostname, e := os.Hostname(); e == nil {
		add(hostname)
	}
	addresses, e := net.InterfaceAddrs()
	if e != nil {
		return fmt.Errorf("enumerate TLS local addresses: %w", e)
	}
	for _, address := range addresses {
		if ipnet, ok := address.(*net.IPNet); ok {
			add(ipnet.IP.String())
		}
	}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		return fmt.Errorf("create self-signed certificate: %w", e)
	}
	encodedKey, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return e
	}
	if e = atomicWrite(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey}), 0600); e != nil {
		return e
	}
	if e = atomicWrite(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
		return e
	}
	return nil
}
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	file, e := os.CreateTemp(filepath.Dir(path), ".tailgate-tls-*")
	if e != nil {
		return e
	}
	defer os.Remove(file.Name())
	if e = file.Chmod(mode); e != nil {
		file.Close()
		return e
	}
	if _, e = file.Write(data); e != nil {
		file.Close()
		return e
	}
	if e = file.Sync(); e != nil {
		file.Close()
		return e
	}
	if e = file.Close(); e != nil {
		return e
	}
	if e = os.Rename(file.Name(), path); e != nil {
		return fmt.Errorf("write TLS artifact: %w", e)
	}
	return nil
}
