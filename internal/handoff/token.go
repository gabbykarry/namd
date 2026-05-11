// Package handoff implements the live server handoff feature.
// A developer can transfer their running tunnel to a trusted peer's machine
// when their battery or connection is failing.
package handoff

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// Token is a signed, short-lived authorization for a handoff.
// The sender creates it. The receiver verifies it before accepting.
//
// Why sign it?
// The token travels over the network from server to receiver.
// If unsigned, anyone who intercepts it could replay it or forge one.
// The HMAC signature proves it was created by the server with the shared secret.
// Without the secret, a forged token fails verification.
type Token struct {
	// ID is a random unique identifier for this handoff.
	ID string `json:"id"`

	// From is the sender's identity name e.g. "gabriel"
	From string `json:"from"`

	// To is the receiver's identity name e.g. "tunde"
	To string `json:"to"`

	// Subdomain is the public subdomain being handed off.
	// "gabriel" means gabriel.namd.online routes to tunde after handoff.
	Subdomain string `json:"subdomain"`

	// ExpiresAt is when this token becomes invalid.
	// The sandbox is killed at this time regardless.
	ExpiresAt time.Time `json:"expires_at"`

	// Signature is the HMAC-SHA256 of the token fields.
	// Computed over ID+From+To+Subdomain+ExpiresAt.
	// Verified before any handoff action is taken.
	Signature string `json:"signature"`
}

// NewToken creates and signs a handoff token.
//
// from       — sender's name e.g. "gabriel"
// to         — receiver's name e.g. "tunde"
// subdomain  — the subdomain being handed off
// duration   — how long the handoff lasts e.g. 60 * time.Minute
// secret     — shared server secret for signing
func NewToken(from, to, subdomain string, duration time.Duration, secret string) (*Token, error) {
	// Generate a random token ID.
	// crypto/rand is cryptographically secure — unpredictable.
	// We use this (not math/rand) because tokens need to be unguessable.
	rawID := make([]byte, 16)
	if _, err := rand.Read(rawID); err != nil {
		return nil, fmt.Errorf("token: cannot generate random ID: %w", err)
	}

	// base64.URLEncoding encodes bytes to URL-safe base64 string.
	// "URL-safe" means + and / are replaced with - and _ so the token
	// can be used in URLs without percent-encoding.
	id := base64.URLEncoding.EncodeToString(rawID)

	t := &Token{
		ID:        id,
		From:      from,
		To:        to,
		Subdomain: subdomain,
		ExpiresAt: time.Now().Add(duration),
	}

	// Sign the token.
	sig, err := sign(t, secret)
	if err != nil {
		return nil, err
	}
	t.Signature = sig

	return t, nil
}

// Verify checks that the token is valid:
//  1. Signature matches (was created with the correct secret)
//  2. Token has not expired
//  3. The receiver matches the expected peer
//
// Returns nil if valid. Returns a descriptive error if invalid.
func (t *Token) Verify(secret, expectedReceiver string) error {
	// Check expiry first — cheapest check.
	if time.Now().After(t.ExpiresAt) {
		return fmt.Errorf("handoff token expired at %s", t.ExpiresAt.Format(time.RFC3339))
	}

	// Check receiver matches.
	if t.To != expectedReceiver {
		return fmt.Errorf("handoff token is for %q not %q", t.To, expectedReceiver)
	}

	// Verify signature — recompute and compare.
	expected, err := sign(t, secret)
	if err != nil {
		return fmt.Errorf("token: signature computation failed: %w", err)
	}

	// Constant-time comparison — prevents timing attacks.
	// Same pattern as webhook signature verification.
	if !hmac.Equal([]byte(expected), []byte(t.Signature)) {
		return fmt.Errorf("handoff token signature invalid — possible forgery")
	}

	return nil
}

// Encode serialises the token to a JSON string for transmission.
// The server sends this to the receiver over the tunnel connection.
func (t *Token) Encode() (string, error) {
	data, err := json.Marshal(t)
	if err != nil {
		return "", fmt.Errorf("token: encode failed: %w", err)
	}
	// base64 encode the JSON so it is safe to send as a single line.
	return base64.URLEncoding.EncodeToString(data), nil
}

// DecodeToken deserialises a token from its encoded string form.
func DecodeToken(encoded string) (*Token, error) {
	data, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("token: decode failed: %w", err)
	}

	var t Token
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("token: invalid JSON: %w", err)
	}
	return &t, nil
}

// sign computes HMAC-SHA256 over the token fields.
// The signature covers all meaningful fields — changing any field
// after signing invalidates the signature.
func sign(t *Token, secret string) (string, error) {
	// Build the message to sign by concatenating all fields.
	// Using a separator (|) prevents ambiguous concatenations.
	// e.g. From="ab", To="c" and From="a", To="bc" would otherwise
	// produce the same message "abc" without a separator.
	message := fmt.Sprintf("%s|%s|%s|%s|%s",
		t.ID,
		t.From,
		t.To,
		t.Subdomain,
		t.ExpiresAt.UTC().Format(time.RFC3339),
	)

	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))
	sig := h.Sum(nil)

	return base64.URLEncoding.EncodeToString(sig), nil
}

// IsExpired returns true if this token has passed its ExpiresAt time.
func (t *Token) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// TimeRemaining returns how long until this token expires.
// Returns 0 if already expired.
func (t *Token) TimeRemaining() time.Duration {
	remaining := time.Until(t.ExpiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}
