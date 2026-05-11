package transport

import (
	"crypto/tls"
	"fmt"
	"net"
)

// ServerTLSConfig returns a TLS config for namd-server.
//
// certFile — path to the certificate PEM file (from Let's Encrypt / certbot)
// keyFile  — path to the private key PEM file
//
// In production these live at:
//
//	/etc/letsencrypt/live/namd.online/fullchain.pem
//	/etc/letsencrypt/live/namd.online/privkey.pem
func ServerTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("tls: cannot load certificate from %s / %s: %w", certFile, keyFile, err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},

		// TLS 1.2 minimum — 1.0 and 1.1 have known vulnerabilities.
		MinVersion: tls.VersionTLS12,

		// Only strong cipher suites.
		// ECDHE = Elliptic Curve Diffie-Hellman Ephemeral.
		// "Ephemeral" means a new key is generated per session.
		// This gives FORWARD SECRECY — if today's key is stolen,
		// yesterday's sessions cannot be decrypted.
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}, nil
}

// ClientTLSConfig returns a TLS config for the namd client.
//
// skipVerify — true only in development with self-signed certs.
//
//	NEVER true in production — it defeats TLS entirely.
//	When false, Go verifies the server cert against
//	trusted certificate authorities automatically.
func ClientTLSConfig(skipVerify bool) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: skipVerify, //nolint:gosec
		MinVersion:         tls.VersionTLS12,
	}
}

// ListenTLS opens a TLS-wrapped TCP listener.
// Replaces net.Listen — every accepted connection is already encrypted.
//
// addr     — ":9000"
// certFile — certificate PEM path
// keyFile  — private key PEM path
func ListenTLS(addr, certFile, keyFile string) (net.Listener, error) {
	cfg, err := ServerTLSConfig(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	// tls.Listen wraps net.Listen — all connections it returns are TLS.
	// The TLS handshake happens automatically on each Accept().
	ln, err := tls.Listen("tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("tls: cannot listen on %s: %w", addr, err)
	}

	return ln, nil
}

// DialTLS opens a TLS-encrypted outbound TCP connection.
// Used by the namd client to connect to the server.
//
// addr       — "namd.online:9000"
// skipVerify — false in production, true in local dev
func DialTLS(addr string, skipVerify bool) (net.Conn, error) {
	cfg := ClientTLSConfig(skipVerify)

	// tls.Dial connects and does the TLS handshake in one call.
	// Returns a *tls.Conn which satisfies net.Conn.
	// Everything we write to it is encrypted automatically.
	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("tls: cannot connect to %s: %w", addr, err)
	}

	return conn, nil
}
