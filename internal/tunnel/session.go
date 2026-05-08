package tunnel

import (
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

// Session represents one active tunnel.
//
// Phase 3 change: instead of storing a raw net.Conn and fighting over
// who reads it, we store a *yamux.Session.
//
// A yamux.Session wraps the underlying TCP conn and manages multiplexing.
// It exposes two operations:
//   - Open()   → opens a new logical stream (used by the server per request)
//   - Accept() → waits for the remote side to open a stream (used by the client)
//
// Each stream satisfies net.Conn — it has Read, Write, Close.
// Streams are fully independent — one stream blocking never affects another.
//
// The raw net.Conn still exists underneath yamux — we just never touch it
// directly after handing it to yamux. yamux owns it from that point.
type Session struct {
	Name        string
	Mux         *yamux.Session // the yamux session wrapping the TCP conn
	ConnectedAt time.Time
}

// NewSession wraps a raw net.Conn in a yamux session.
//
// isServer determines which side of yamux this is.
// yamux requires one side to be "server" and one to be "client".
// This has nothing to do with namd server/client — it is just yamux's
// internal framing convention. One side must be the yamux server.
//
// In namd:
//
//	namd client (developer laptop) → isServer = true  (yamux server)
//	namd server (VPS)              → isServer = false (yamux client)
//
// Why this way around? Because:
//   - yamux server = the side that ACCEPTS incoming streams
//   - yamux client = the side that OPENS new streams
//   - namd client accepts streams (waits for requests to arrive)
//   - namd server opens streams (one per public request)
func NewSession(name string, conn net.Conn, isServer bool) (*Session, error) {
	var mux *yamux.Session
	var err error

	if isServer {
		// yamux.Server wraps conn as the accepting side.
		// nil config = use yamux defaults (keepalive, window size, etc.)
		mux, err = yamux.Server(conn, nil)
	} else {
		// yamux.Client wraps conn as the stream-opening side.
		mux, err = yamux.Client(conn, nil)
	}

	if err != nil {
		return nil, err
	}

	return &Session{
		Name:        name,
		Mux:         mux,
		ConnectedAt: time.Now(),
	}, nil
}

// OpenStream opens a new logical stream within this session.
// Called by the namd server (VPS) for each incoming public request.
// Returns a net.Conn-like stream — pipe traffic through it directly.
func (s *Session) OpenStream() (net.Conn, error) {
	return s.Mux.Open()
}

// AcceptStream waits for the remote side to open a stream.
// Called by the namd client (laptop) in a loop — one goroutine per stream.
// Blocks until a stream arrives, then returns it as a net.Conn.
func (s *Session) AcceptStream() (net.Conn, error) {
	return s.Mux.Accept()
}

// Close shuts down the yamux session and the underlying TCP conn.
func (s *Session) Close() error {
	return s.Mux.Close()
}

// IsClosed returns true if the yamux session has been closed.
// Used to detect when the client has disconnected.
func (s *Session) IsClosed() bool {
	return s.Mux.IsClosed()
}
