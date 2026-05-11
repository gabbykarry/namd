// Package auth handles client identity, registration, and token verification.
// Every namd client has a unique identity stored in ~/.namd/credentials.
// The server verifies this identity on every tunnel connection.
package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Credentials holds the client's identity and auth token.
// Stored in ~/.namd/credentials as JSON.
// This file is the only thing that proves who you are to the namd server.
//
// Think of it like ~/.ssh/id_rsa — keep it secret, keep it safe.
// If lost: run `namd auth register` again to get a new token.
// If stolen: run `namd auth revoke` to invalidate it on the server.
type Credentials struct {
	// Name is the developer's identity on the namd network.
	// Becomes the subdomain: gabriel → gabriel.namd.online
	Name string `json:"name"`

	// Token is the secret that proves this client owns the name.
	// 32 bytes of crypto/rand encoded as 64 hex characters.
	// The server stores a hash of this — never the token itself.
	Token string `json:"token"`

	// ServerURL is the namd server this token was issued by.
	// A token from namd.online does not work on a different server.
	ServerURL string `json:"server_url"`

	// IssuedAt records when this credential was created.
	IssuedAt time.Time `json:"issued_at"`

	// ExpiresAt is when the token expires.
	// Zero value = never expires.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// IsExpired returns true if the credentials have expired.
func (c *Credentials) IsExpired() bool {
	if c.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*c.ExpiresAt)
}

// credentialsPath returns the path to the credentials file.
// ~/.namd/credentials
func credentialsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("auth: cannot find home directory: %w", err)
	}
	return filepath.Join(home, ".namd", "credentials"), nil
}

// SaveCredentials writes credentials to ~/.namd/credentials.
//
// File permissions: 0600 — readable only by the owner.
// This is the same convention as ~/.ssh/id_rsa.
// If the file is world-readable, other users on the same machine
// could steal your token. 0600 prevents this.
//
// os.MkdirAll creates ~/.namd/ if it does not exist.
func SaveCredentials(creds *Credentials) error {
	path, err := credentialsPath()
	if err != nil {
		return err
	}

	// Create ~/.namd/ directory.
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("auth: cannot create credentials directory: %w", err)
	}

	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("auth: cannot serialise credentials: %w", err)
	}

	// os.WriteFile with 0600 — owner read/write only.
	// 0600 in octal:
	//   6 = owner: read + write
	//   0 = group: no permissions
	//   0 = others: no permissions
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("auth: cannot write credentials to %s: %w", path, err)
	}

	return nil
}

// LoadCredentials reads credentials from ~/.namd/credentials.
// Returns ErrNotRegistered if the file does not exist.
func LoadCredentials() (*Credentials, error) {
	path, err := credentialsPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, ErrNotRegistered
	}
	if err != nil {
		return nil, fmt.Errorf("auth: cannot read credentials from %s: %w", path, err)
	}

	var creds Credentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("auth: credentials file is corrupted — run `namd auth register`: %w", err)
	}

	return &creds, nil
}

// GenerateToken creates a cryptographically secure random token.
// 32 bytes of entropy from crypto/rand — 256 bits.
// Encoded as 64 hex characters for readability and safe storage.
//
// Why crypto/rand and not math/rand?
// math/rand is deterministic — given the same seed, same output.
// crypto/rand reads from the OS entropy source (/dev/urandom on Linux,
// CryptGenRandom on Windows). Truly unpredictable.
// For security tokens: always crypto/rand.
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: cannot generate token: %w", err)
	}
	// hex.EncodeToString converts bytes to lowercase hex string.
	// 32 bytes → 64 hex characters.
	return hex.EncodeToString(b), nil
}

// ErrNotRegistered is returned when no credentials file exists.
// The user needs to run `namd auth register` first.
var ErrNotRegistered = fmt.Errorf("not registered — run: namd auth register")
