package auth

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

// PeerInfo holds what we know about a peer on the namd network.
// Retrieved from the server when you do `namd handoff @tunde` —
// we verify @tunde exists and is online before sending the request.
type PeerInfo struct {
	Name      string    `json:"name"`
	Online    bool      `json:"online"`
	LastSeen  time.Time `json:"last_seen"`
	PublicKey string    `json:"public_key,omitempty"`
}

// LookupPeer asks the namd server if a peer exists and is online.
// Called by the handoff sender before initiating a handoff.
//
// serverAddr — the namd server e.g. "localhost:9000"
// peerName   — the peer's handle without @ e.g. "tunde"
//
// Returns PeerInfo and nil if found.
// Returns nil and error if peer does not exist or server is unreachable.
func LookupPeer(serverAddr, peerName string) (*PeerInfo, error) {
	// Connect to the server's query port.
	queryAddr := strings.Replace(serverAddr, ":9000", ":9002", 1)
	if strings.Contains(queryAddr, "namd.online") {
		queryAddr = strings.Replace(queryAddr, "namd.online", "registry.namd.online", 1)
	}

	conn, err := net.DialTimeout("tcp", queryAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("auth: cannot reach server: %w", err)
	}
	defer conn.Close()

	// Send peer lookup request.
	// Protocol: "PEER_LOOKUP <name>\n"
	fmt.Fprintf(conn, "PEER_LOOKUP %s\n", peerName)

	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("auth: no response from server: %w", err)
	}

	response = strings.TrimSpace(response)

	// Server responds:
	//   "PEER_FOUND tunde online"    → peer exists and is connected
	//   "PEER_FOUND tunde offline"   → peer exists but not connected
	//   "PEER_NOT_FOUND"             → no account with this name
	if response == "PEER_NOT_FOUND" {
		return nil, fmt.Errorf("@%s is not registered on this server", peerName)
	}

	parts := strings.Fields(response)
	if len(parts) < 3 || parts[0] != "PEER_FOUND" {
		return nil, fmt.Errorf("auth: unexpected server response: %q", response)
	}

	info := &PeerInfo{
		Name:   parts[1],
		Online: parts[2] == "online",
	}

	return info, nil
}

// ValidateTrustedPeer checks if a peer handle is in the trusted peers list
// and is registered on the server.
//
// This is called before initiating a handoff — two checks:
//  1. Is the peer in your namd.yml trusted_peers? (local check)
//  2. Is the peer registered on the server? (network check)
//
// Both must pass. This prevents:
//   - Sending handoffs to random people not in your trust list
//   - Sending handoffs to non-existent accounts
func ValidateTrustedPeer(serverAddr, peerName string, trustedPeers []string) (*PeerInfo, error) {
	// Local check — is this peer in the trusted list?
	trusted := false
	for _, p := range trustedPeers {
		// trusted_peers entries have @ prefix: "@tunde"
		// Strip it for comparison.
		clean := strings.TrimPrefix(p, "@")
		if clean == peerName {
			trusted = true
			break
		}
	}

	if !trusted {
		return nil, fmt.Errorf(
			"@%s is not in your trusted_peers list — add them to namd.yml first",
			peerName,
		)
	}

	// Network check — does this peer exist on the server?
	info, err := LookupPeer(serverAddr, peerName)
	if err != nil {
		return nil, err
	}

	if !info.Online {
		return nil, fmt.Errorf(
			"@%s is registered but not currently online — they need to run `namd start`",
			peerName,
		)
	}

	return info, nil
}
