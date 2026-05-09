// Package adapters contains concrete Adapter implementations.
// Each file is one provider. Adding a new provider = adding one file here
// + one line in registry.go. Nothing else changes.
package adapters

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/gabbykarry/namd/internal/webhook"
)

// GenericAdapter relays webhooks from any provider with no signature verification.
// Use adapter: "generic" in namd.yml for providers not yet supported,
// or for internal webhooks where you control both sides.
//
// This is also the reference implementation — the simplest possible adapter.
// Every other adapter builds on this pattern.
type GenericAdapter struct{}

// Name returns the adapter identifier used in namd.yml.
func (a *GenericAdapter) Name() string { return "generic" }

// Verify always returns nil — generic adapter does not validate signatures.
// This means any request reaching this path will be forwarded.
// Only use generic for internal tools or providers you trust fully.
func (a *GenericAdapter) Verify(r *http.Request, secret string) error {
	return nil
}

// Normalize extracts a minimal Event from the request.
// We attempt to parse the body as JSON to find an event type.
// If that fails, we use "unknown" — the raw bytes are still stored.
func (a *GenericAdapter) Normalize(r *http.Request) (*webhook.Event, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return &webhook.Event{
			Provider: "generic",
			Type:     "unknown",
		}, nil
	}

	// Try to extract an event type from common JSON fields.
	// Different providers use different field names:
	//   Paystack:     { "event": "charge.success" }
	//   Flutterwave:  { "event": "charge.completed" }
	//   GitHub:       X-GitHub-Event header
	//   Stripe:       { "type": "payment_intent.succeeded" }
	var payload map[string]interface{}
	eventType := "unknown"

	if err := json.Unmarshal(body, &payload); err == nil {
		// Try common field names in order of preference.
		for _, field := range []string{"event", "type", "event_type", "action"} {
			if v, ok := payload[field]; ok {
				if s, ok := v.(string); ok {
					eventType = s
					break
				}
			}
		}
	}

	return &webhook.Event{
		Provider: "generic",
		Type:     eventType,
	}, nil
}
