// Package webhook implements the generic webhook relay engine.
// It intercepts HTTP requests on configured paths, verifies signatures
// via provider-specific adapters, stores events, and forwards to local apps.
//
// To add a new webhook provider (e.g. Stripe, Interswitch):
//  1. Create internal/webhook/adapters/stripe.go
//  2. Implement the Adapter interface
//  3. Register in internal/webhook/adapters/registry.go
//  4. Open a PR — no other files need to change
package webhook

import (
	"net/http"
	"time"
)

// Adapter is the interface every webhook provider must implement.
//
// This is Go's interface pattern at its clearest:
// The engine knows NOTHING about Paystack or Flutterwave.
// It only knows: "I have something that satisfies Adapter."
// It calls Verify() and Normalize() — the adapter does the rest.
//
// An interface in Go is satisfied IMPLICITLY.
// There is no "implements Adapter" keyword.
// If a type has all the methods with the right signatures — it satisfies it.
// The compiler checks this at compile time, not runtime.
type Adapter interface {
	// Name returns the adapter's identifier.
	// This is what users write in namd.yml: adapter: "paystack"
	// The registry maps this string to the concrete adapter type.
	Name() string

	// Verify checks the webhook signature.
	// Providers sign their webhook payloads with a secret so you can
	// confirm the request actually came from them, not a spoofed source.
	//
	// r      — the incoming HTTP request (headers + body)
	// secret — the webhook secret from namd.yml or environment variable
	//
	// Returns nil if the signature is valid.
	// Returns an error if invalid or missing.
	//
	// Generic adapter always returns nil (no signature to check).
	Verify(r *http.Request, secret string) error

	// Normalize converts the raw request into a standard Event.
	// Every provider sends different JSON shapes — we normalise them
	// into a common Event struct so the engine and store work uniformly.
	//
	// r — the incoming HTTP request (headers already read, body available)
	//
	// Returns the Event and nil on success.
	// Returns nil and an error if the body cannot be parsed.
	Normalize(r *http.Request) (*Event, error)
}

// Event is the normalised representation of any webhook event.
// Regardless of provider, all events become an Event before storage.
//
// This is the core of the generic engine — one shape for everything.
// The dashboard, the replay system, the store — all work with Event.
type Event struct {
	// ID is a unique identifier for this event.
	// We generate this — providers may or may not include their own ID.
	ID string `json:"id"`

	// Provider is the adapter name: "paystack", "flutterwave", "github", "generic"
	Provider string `json:"provider"`

	// Type is the event type string from the provider.
	// Paystack: "charge.success", "transfer.success"
	// Flutterwave: "charge.completed"
	// GitHub: "push", "pull_request"
	// Generic: "unknown"
	Type string `json:"type"`

	// Raw is the original request body — the exact bytes Paystack/Flutterwave sent.
	// We store this so replay sends the IDENTICAL payload your app will receive.
	// json:"-" means this field is excluded from JSON marshalling.
	// We store Raw separately as a raw file, not inside the JSON metadata.
	Raw []byte `json:"-"`

	// Headers is a snapshot of the request headers.
	// Useful for replay — some apps validate headers too.
	Headers map[string]string `json:"headers"`

	// ReceivedAt is when namd received this event.
	ReceivedAt time.Time `json:"received_at"`

	// ForwardedAt is when namd forwarded it to the local app.
	// Nil if the local app was down and the event is pending replay.
	ForwardedAt *time.Time `json:"forwarded_at,omitempty"`

	// StatusCode is the HTTP status the local app returned.
	// 0 if the local app was unreachable.
	StatusCode int `json:"status_code,omitempty"`
}
