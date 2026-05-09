package adapters

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gabbykarry/namd/internal/webhook"
)

// GitHubAdapter verifies and normalises GitHub webhook events.
//
// GitHub signs webhooks with HMAC-SHA256 (not SHA512 like Paystack).
// The signature is in the X-Hub-Signature-256 header, prefixed with "sha256=".
//
// GitHub docs: https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
type GitHubAdapter struct{}

func (a *GitHubAdapter) Name() string { return "github" }

func (a *GitHubAdapter) Verify(r *http.Request, secret string) error {
	if secret == "" {
		return nil // no secret configured — skip
	}

	signature := r.Header.Get("X-Hub-Signature-256")
	if signature == "" {
		return fmt.Errorf("github: missing X-Hub-Signature-256 header")
	}

	// GitHub sends: "sha256=<hex>" — strip the "sha256=" prefix.
	// strings.CutPrefix returns (after, true) if prefix found, (original, false) if not.
	hexSig, found := strings.CutPrefix(signature, "sha256=")
	if !found {
		return fmt.Errorf("github: unexpected signature format: %q", signature)
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("github: error reading body: %w", err)
	}

	// HMAC-SHA256 this time (GitHub uses SHA256, Paystack uses SHA512).
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(body)
	expected := h.Sum(nil)

	received, err := hex.DecodeString(hexSig)
	if err != nil {
		return fmt.Errorf("github: invalid signature hex: %w", err)
	}

	if !hmac.Equal(expected, received) {
		return fmt.Errorf("github: signature mismatch")
	}

	return nil
}

// Normalize parses GitHub webhook events.
// GitHub sends the event type in the X-GitHub-Event header, not the body.
//
// GitHub payload shape varies by event type — we only extract the action.
//
//	push event:         { "ref": "refs/heads/main", ... }
//	pull_request event: { "action": "opened", "pull_request": {...} }
func (a *GitHubAdapter) Normalize(r *http.Request) (*webhook.Event, error) {
	// GitHub event type comes from the header, not the body.
	githubEvent := r.Header.Get("X-GitHub-Event")
	if githubEvent == "" {
		githubEvent = "unknown"
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("github: error reading body: %w", err)
	}

	// Try to extract the action for more specific event typing.
	// "pull_request.opened" is more useful than just "pull_request".
	var payload struct {
		Action string `json:"action"`
	}
	eventType := githubEvent
	if err := json.Unmarshal(body, &payload); err == nil && payload.Action != "" {
		eventType = githubEvent + "." + payload.Action
	}

	return &webhook.Event{
		Provider: "github",
		Type:     eventType,
	}, nil
}
