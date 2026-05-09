package adapters

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/gabbykarry/namd/internal/webhook"
)

// PaystackAdapter verifies and normalises Paystack webhook events.
//
// Paystack signs webhooks with HMAC-SHA512.
// The signature is sent in the X-Paystack-Signature header.
// You verify it by computing HMAC-SHA512(secret, body) and comparing.
//
// Paystack docs: https://paystack.com/docs/payments/webhooks/
type PaystackAdapter struct{}

func (a *PaystackAdapter) Name() string { return "paystack" }

// Verify checks the X-Paystack-Signature header.
//
// How HMAC works:
//
//	HMAC(key, message) = hash(key XOR opad || hash(key XOR ipad || message))
//	In practice: hmac.New(sha512.New, secret) then h.Write(body) then h.Sum(nil)
//
// Paystack sends: X-Paystack-Signature: <hex-encoded HMAC-SHA512 of body>
// We compute the same hash and compare — if equal, the request is genuine.
//
// NEVER compare signatures with == — use hmac.Equal.
// hmac.Equal does a constant-time comparison to prevent timing attacks.
// A timing attack: attacker tries every possible signature and measures
// response time to guess when they have matching bytes. Constant-time
// comparison makes all comparisons take the same time — attack impossible.
func (a *PaystackAdapter) Verify(r *http.Request, secret string) error {
	signature := r.Header.Get("X-Paystack-Signature")
	if signature == "" {
		return fmt.Errorf("paystack: missing X-Paystack-Signature header")
	}

	// Read the body — we need the raw bytes to compute the HMAC.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("paystack: error reading body for verification: %w", err)
	}

	// Compute HMAC-SHA512 of the body using the secret as key.
	// hmac.New(hashFunc, key) creates a new HMAC hash.
	// h.Write(data) feeds data into the hash.
	// h.Sum(nil) finalises and returns the hash bytes.
	h := hmac.New(sha512.New, []byte(secret))
	h.Write(body)
	expected := h.Sum(nil)

	// Decode the hex signature from the header into bytes.
	// hex.DecodeString("abcd...") → []byte{0xab, 0xcd, ...}
	received, err := hex.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("paystack: invalid signature format: %w", err)
	}

	// Constant-time comparison — prevents timing attacks.
	if !hmac.Equal(expected, received) {
		return fmt.Errorf("paystack: signature mismatch — request may be spoofed")
	}

	return nil
}

// Normalize parses Paystack's event JSON and maps it to an Event.
//
// Paystack event payload shape:
//
//	{
//	  "event": "charge.success",
//	  "data": {
//	    "id": 12345,
//	    "reference": "abc123",
//	    ...
//	  }
//	}
func (a *PaystackAdapter) Normalize(r *http.Request) (*webhook.Event, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("paystack: error reading body: %w", err)
	}

	// Parse only the fields we need — using an anonymous struct.
	// We do not parse the full Paystack payload — that is the local app's job.
	// We only need enough to build a meaningful Event for logging/storage.
	var payload struct {
		Event string `json:"event"` // "charge.success"
	}

	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("paystack: invalid JSON payload: %w", err)
	}

	return &webhook.Event{
		Provider: "paystack",
		Type:     payload.Event, // "charge.success", "transfer.success", etc.
	}, nil
}
