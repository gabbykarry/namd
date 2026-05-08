// Package transport handles the low-level TCP + yamux wiring.
// It owns the connection setup on both sides — server and client.
// Higher-level packages receive a *tunnel.Session and never touch net.Conn directly.
package transport

import (
	"fmt"
	"net"

	"github.com/gabbykarry/namd/internal/tunnel"
)

// WrapServerSide wraps an accepted TCP connection (on the VPS) into a yamux session.
//
// Called by the namd server after Accept() on :9000.
// The VPS side is the yamux CLIENT — it opens streams, one per public request.
//
// name  — the tunnel name read from the HELLO handshake before calling this
// conn  — the raw TCP conn from listener.Accept()
func WrapServerSide(name string, conn net.Conn) (*tunnel.Session, error) {
	// isServer=false → this side is the yamux client (opens streams)
	session, err := tunnel.NewSession(name, conn, false)
	if err != nil {
		return nil, fmt.Errorf("transport: failed to create yamux client session for %q: %w", name, err)
	}
	return session, nil
}

// WrapClientSide wraps an outbound TCP connection (on the laptop) into a yamux session.
//
// Called by the namd client after Dial() to the VPS :9000.
// The laptop side is the yamux SERVER — it accepts streams.
//
// name  — the tunnel name (from --name flag)
// conn  — the raw TCP conn from net.Dial()
func WrapClientSide(name string, conn net.Conn) (*tunnel.Session, error) {
	// isServer=true → this side is the yamux server (accepts streams)
	session, err := tunnel.NewSession(name, conn, true)
	if err != nil {
		return nil, fmt.Errorf("transport: failed to create yamux server session for %q: %w", name, err)
	}
	return session, nil
}
