package adapters

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/gabbykarry/namd/internal/webhook"
)

// FlutterwaveAdapter verifies and normalises Flutterwave webhook events.
//
// Flutterwave uses a simpler verification than Paystack:
// They send a "verif-hash" header containing a plain secret string.
// You compare it directly to your secret hash configured in the dashboard.
//
// This is less secure than HMAC (no body signing) but it is what Flutterwave uses.
// Flutterwave docs: https://developer.flutterwave.com/docs/integration-guides/webhooks/
type FlutterwaveAdapter struct{}

func (a *FlutterwaveAdapter) Name() string { return "flutterwave" }

// Verify checks the verif-hash header against the configured secret.
// Flutterwave sends: verif-hash: <your-secret-hash>
// You set this secret in the Flutterwave dashboard under Webhooks.
func (a *FlutterwaveAdapter) Verify(r *http.Request, secret string) error {
	if secret == "" {
		// No secret configured — skip verification.
		// Log a warning so the developer knows they should set one.
		fmt.Println("[webhook] warning: flutterwave secret not set — skipping verification")
		return nil
	}

	hash := r.Header.Get("verif-hash")
	if hash == "" {
		return fmt.Errorf("flutterwave: missing verif-hash header")
	}

	// Direct string comparison — not HMAC, not constant-time.
	// Flutterwave's design, not ours. Safe enough for a dev tool.
	if hash != secret {
		return fmt.Errorf("flutterwave: verif-hash mismatch")
	}

	return nil
}

// Normalize parses Flutterwave's event JSON.
//
// Flutterwave event payload shape:
//
//	{
//	  "event": "charge.completed",
//	  "data": {
//	    "id": 12345,
//	    "tx_ref": "abc123",
//	    "status": "successful",
//	    ...
//	  }
//	}
func (a *FlutterwaveAdapter) Normalize(r *http.Request) (*webhook.Event, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("flutterwave: error reading body: %w", err)
	}

	var payload struct {
		Event string `json:"event"` // "charge.completed"
	}

	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("flutterwave: invalid JSON: %w", err)
	}

	return &webhook.Event{
		Provider: "flutterwave",
		Type:     payload.Event,
	}, nil
}
