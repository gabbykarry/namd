package handoff

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

// HandoffRequest is what the sender sends to the namd server
// to initiate a handoff to a peer.
type HandoffRequest struct {
	// From is the sender's tunnel name.
	From string

	// To is the peer's @handle (without @).
	To string

	// Subdomain is the subdomain being handed off.
	Subdomain string

	// MaxDuration is how long the handoff should last.
	MaxDuration time.Duration

	// ServerAddr is the namd server address to coordinate through.
	ServerAddr string
}

// Sender manages the sender side of a handoff.
// Gabriel creates a Sender, calls Initiate(), waits for acceptance,
// then the handoff is live.
type Sender struct {
	req    HandoffRequest
	secret string // server shared secret for token signing
}

// NewSender creates a Sender for the given handoff request.
func NewSender(req HandoffRequest, secret string) *Sender {
	return &Sender{req: req, secret: secret}
}

// Initiate sends a handoff request to the namd server and waits for the peer to accept.
//
// Flow:
//  1. Connect to namd server control port (:9001 — separate from tunnel port)
//  2. Send HANDOFF_REQUEST to <peer>
//  3. Server forwards request to peer
//  4. Peer accepts or rejects
//  5. Server issues token and sends it back
//  6. We confirm — our tunnel is removed, peer's tunnel takes over
//
// Returns the issued token if accepted, error if rejected or timed out.
func (s *Sender) Initiate() (*Token, error) {
	log.Printf("[handoff] requesting handoff to @%s", s.req.To)
	log.Printf("[handoff] this will transfer %s.namd.online to @%s for up to %s",
		s.req.Subdomain, s.req.To, s.req.MaxDuration)

	// Connect to the server's handoff coordination port.
	// We use a separate port (:9001) so handoff traffic does not
	// interfere with the normal tunnel connection on :9000.
	// serverAddr is already tunnel.namd.online:9000.
	// Replace with broker.namd.online:9001 for the handoff broker.
	serverAddr := s.req.ServerAddr
	controlAddr := strings.Replace(serverAddr, ":9000", ":9001", 1)
	controlAddr = strings.Replace(controlAddr, "tunnel.namd.online", "broker.namd.online", 1)
	if strings.Contains(controlAddr, "namd.online") && !strings.Contains(controlAddr, "broker.") {
		controlAddr = strings.Replace(controlAddr, "namd.online", "broker.namd.online", 1)
	}
	conn, err := net.DialTimeout("tcp", controlAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("handoff: cannot connect to server: %w", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Identify ourselves and declare handoff intent.
	// Protocol:
	//   sender → server: "HANDOFF_INIT gabriel tunde gabriel 60m"
	//   server → receiver: "HANDOFF_REQUEST gabriel gabriel.namd.online 60m <token>"
	//   receiver → server: "HANDOFF_ACCEPT <token_id>"
	//   server → sender: "HANDOFF_CONFIRMED <encoded_token>"
	fmt.Fprintf(conn, "HANDOFF_INIT %s %s %s %s\n",
		s.req.From,
		s.req.To,
		s.req.Subdomain,
		s.req.MaxDuration,
	)

	// Wait for server response — may take a while if peer is slow to accept.
	// We give it 5 minutes — if peer does not respond, time out.
	conn.SetDeadline(time.Now().Add(5 * time.Minute))

	response, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("handoff: error waiting for response: %w", err)
	}
	response = strings.TrimSpace(response)

	if strings.HasPrefix(response, "ERROR") {
		return nil, fmt.Errorf("handoff failed: %s", response)
	}

	if strings.HasPrefix(response, "PEER_OFFLINE") {
		return nil, fmt.Errorf("handoff: @%s is not online — they must run `namd start` first", s.req.To)
	}

	if strings.HasPrefix(response, "REJECTED") {
		return nil, fmt.Errorf("handoff: @%s rejected the request", s.req.To)
	}

	if !strings.HasPrefix(response, "CONFIRMED ") {
		return nil, fmt.Errorf("handoff: unexpected server response: %q", response)
	}

	// Decode the token from the confirmed response.
	encodedToken := strings.TrimPrefix(response, "CONFIRMED ")
	token, err := DecodeToken(encodedToken)
	if err != nil {
		return nil, fmt.Errorf("handoff: invalid token from server: %w", err)
	}

	log.Printf("[handoff] ✓ accepted by @%s", s.req.To)
	log.Printf("[handoff]   token expires: %s (%s remaining)",
		token.ExpiresAt.Format("15:04:05"),
		token.TimeRemaining().Round(time.Minute),
	)
	log.Printf("[handoff]   %s.namd.online now routes to @%s", s.req.Subdomain, s.req.To)
	log.Printf("[handoff]   you can safely close your laptop")

	return token, nil
}

// Cancel sends a cancellation to the server, ending the handoff early.
// The peer's sandbox is killed and the subdomain routing is removed.
func Cancel(serverAddr, from, subdomain string) error {
	controlAddr := strings.Replace(serverAddr, ":9000", ":9001", 1)
	conn, err := net.DialTimeout("tcp", controlAddr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("handoff cancel: cannot connect: %w", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "HANDOFF_CANCEL %s %s\n", from, subdomain)

	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("handoff cancel: no response: %w", err)
	}

	response = strings.TrimSpace(response)
	if response != "CANCELLED" {
		return fmt.Errorf("handoff cancel: unexpected response: %q", response)
	}

	log.Printf("[handoff] cancelled — %s.namd.online routing removed", subdomain)
	return nil
}
