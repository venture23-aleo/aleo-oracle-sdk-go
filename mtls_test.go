package aleo_oracle_sdk

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"testing"
	"time"
)

// helper to write temporary cert/key returning their paths
func writeTempCertAndKey(t *testing.T) (string, string) {
	t.Helper()

	// generate key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed generating key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sdk-mtls-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed creating cert: %v", err)
	}

	certFile, err := os.CreateTemp(t.TempDir(), "client-cert-*.pem")
	if err != nil {
		t.Fatalf("failed creating cert temp file: %v", err)
	}
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		t.Fatalf("failed encoding cert: %v", err)
	}
	certFile.Close()

	keyFile, err := os.CreateTemp(t.TempDir(), "client-key-*.pem")
	if err != nil {
		t.Fatalf("failed creating key temp file: %v", err)
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		t.Fatalf("failed encoding key: %v", err)
	}
	keyFile.Close()

	return certFile.Name(), keyFile.Name()
}

func TestMTLSConfigApplied(t *testing.T) {
	certPath, keyPath := writeTempCertAndKey(t)

	cfg := &ClientConfig{MtlsConfig: &MTLSConfig{ClientCertPath: certPath, ClientKeyPath: keyPath}}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("failed creating client with mtls: %v", err)
	}

	tr, ok := client.transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is not *http.Transport")
	}
	if tr.TLSClientConfig == nil || len(tr.TLSClientConfig.Certificates) == 0 {
		t.Fatalf("expected client certificate to be loaded into TLS config")
	}
}
