package aleo_oracle_sdk

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
)

// MTLSConfig contains configuration required to enable mutual TLS for requests
// performed by the SDK. All fields are optional except the client certificate
// and key paths which must both be provided to enable mTLS.
//
// If CaCertPath is provided, it is appended to the system cert pool and used
// as the RootCAs for the HTTP client's TLS configuration. If not provided the
// system roots are used.
//
// If ServerNameOverride is provided it is set as tls.Config.ServerName. If not
// provided, SNI is still configured dynamically per request based on backend
// address (see request.go). ServerNameOverride is useful when the certificate
// the server presents contains a CN/SAN that differs from the backend Address
// value configured in CustomBackendConfig.
type MTLSConfig struct {
	// Path to the PEM encoded client certificate.
	ClientCertPath string
	// Path to the PEM encoded private key that matches ClientCertPath.
	ClientKeyPath string
	// Optional path to a PEM encoded CA certificate bundle to trust in
	// addition to the system pool.
	CaCertPath string
	// Optional server name override for SNI / certificate verification.
	ServerNameOverride string
	// If true, skips server certificate verification. Strongly discouraged
	// outside of testing.
	InsecureSkipVerify bool
}

// applyToTransport mutates (a clone of) the provided *http.Transport to include
// the mTLS settings. It returns a new transport instance
func (c *MTLSConfig) applyToTransport(t http.RoundTripper) (http.RoundTripper, error) {
	if c == nil {
		return t, nil
	}

	ht, ok := t.(*http.Transport)
	if !ok {
		return nil, errors.New("mtls: provided transport is not *http.Transport")
	}

	if c.ClientCertPath == "" || c.ClientKeyPath == "" {
		return nil, errors.New("mtls: both ClientCertPath and ClientKeyPath must be provided")
	}

	cloned := ht.Clone()
	if cloned.TLSClientConfig == nil {
		cloned.TLSClientConfig = &tls.Config{}
	}

	cert, err := tls.LoadX509KeyPair(c.ClientCertPath, c.ClientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("mtls: failed loading client certificate: %w", err)
	}
	cloned.TLSClientConfig.Certificates = append(cloned.TLSClientConfig.Certificates, cert)

	if c.CaCertPath != "" {
		caData, err := os.ReadFile(c.CaCertPath)
		if err != nil {
			return nil, fmt.Errorf("mtls: failed reading CA cert: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if ok := pool.AppendCertsFromPEM(caData); !ok {
			return nil, errors.New("mtls: failed appending CA certificate")
		}
		cloned.TLSClientConfig.RootCAs = pool
	}

	if c.ServerNameOverride != "" {
		cloned.TLSClientConfig.ServerName = c.ServerNameOverride
	}

	cloned.TLSClientConfig.InsecureSkipVerify = c.InsecureSkipVerify

	return cloned, nil
}
