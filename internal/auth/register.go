package auth

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/gabbykarry/namd/pkg/logger"
)

// RegisterRequest is what the client sends to the server to register.
type RegisterRequest struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Token string `json:"token"` // client-generated token — server stores its hash
}

// RegisterResponse is what the server sends back.
type RegisterResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Name    string `json:"name"`
}

// Register creates a new account on the namd server.
//
// Flow:
//  1. Generate a random token locally
//  2. Connect to server registration port (:9002)
//  3. Send name + email + token
//  4. Server validates: name not taken, email format valid
//  5. Server stores: name → hash(token)  (never the token itself)
//  6. Server responds: success or error
//  7. We save credentials locally to ~/.namd/credentials
//
// The server stores hash(token), not the token.
// Why? If the server database is breached, attackers get hashes,
// not tokens. They cannot use a hash to authenticate.
// Only the client has the real token.
func Register(serverAddr, name, email string) (*Credentials, error) {
	log := logger.New("auth")

	// Generate the client token.
	token, err := GenerateToken()
	if err != nil {
		return nil, err
	}

	// Connect to the registration port.
	// We use a separate port (:9002) so registration traffic
	// does not mix with tunnel traffic on :9000.
	// Use registry.namd.online for registration to bypass Cloudflare.
	regAddr := strings.Replace(serverAddr, ":9000", ":9002", 1)
	if strings.Contains(regAddr, "namd.online") {
		regAddr = strings.Replace(regAddr, "namd.online", "registry.namd.online", 1)
	}

	log.Info("registering", logger.Fields{
		"name":   name,
		"server": regAddr,
	})

	conn, err := net.DialTimeout("tcp", regAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("auth: cannot connect to server for registration: %w", err)
	}
	defer conn.Close()

	// Send registration request as JSON.
	req := RegisterRequest{
		Name:  name,
		Email: email,
		Token: token,
	}

	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("auth: cannot encode registration request: %w", err)
	}

	// Write the JSON followed by a newline — server reads line by line.
	fmt.Fprintf(conn, "%s\n", string(data))

	// Read the response.
	reader := bufio.NewReader(conn)
	respLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("auth: error reading registration response: %w", err)
	}

	var resp RegisterResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(respLine)), &resp); err != nil {
		return nil, fmt.Errorf("auth: invalid server response: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("auth: registration failed: %s", resp.Message)
	}

	// Save credentials locally.
	creds := &Credentials{
		Name:      name,
		Token:     token,
		ServerURL: serverAddr,
		IssuedAt:  time.Now(),
	}

	if err := SaveCredentials(creds); err != nil {
		return nil, err
	}

	log.Audit("registered", logger.Fields{
		"name":   name,
		"server": serverAddr,
	})

	return creds, nil
}
