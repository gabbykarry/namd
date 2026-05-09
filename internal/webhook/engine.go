package webhook

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"time"
)

// RelayConfig is the config for one webhook relay rule.
// Populated from namd.yml by the config package.
type RelayConfig struct {
	Name    string // "payments"
	Path    string // "/webhooks/payment"
	Adapter string // "paystack"
	Secret  string // HMAC secret for signature verification
	Store   bool   // persist events to disk
	Replay  bool   // allow replay via CLI
}

// Engine is the core webhook relay.
// It intercepts HTTP requests on configured paths,
// verifies signatures, stores events, and forwards to local apps.
//
// The engine is provider-agnostic — it only talks to Adapter.
// It does not know about Paystack or Flutterwave specifically.
type Engine struct {
	store    *Store
	adapters map[string]Adapter // "paystack" → PaystackAdapter{}
	relays   []RelayConfig
	localURL string // e.g. "http://localhost:3000"
}

// NewEngine creates a webhook relay engine.
//
// adapters  — the registry of available adapters
// store     — where to persist events (may be nil if store: false for all relays)
// relays    — the relay rules from namd.yml
// localURL  — base URL of the local app e.g. "http://localhost:3000"
func NewEngine(
	adapters map[string]Adapter,
	store *Store,
	relays []RelayConfig,
	localURL string,
) *Engine {
	return &Engine{
		store:    store,
		adapters: adapters,
		relays:   relays,
		localURL: localURL,
	}
}

// Match returns the RelayConfig for a given URL path, if any.
// Called by the proxy layer — if a request path matches a relay rule,
// the engine handles it instead of the normal tunnel forwarding.
//
// Returns the config and true if matched.
// Returns zero value and false if no relay matches this path.
func (e *Engine) Match(path string) (RelayConfig, bool) {
	for _, r := range e.relays {
		if r.Path == path {
			return r, true
		}
	}
	return RelayConfig{}, false
}

// Handle intercepts one webhook request.
// Called by the proxy when a request matches a relay rule.
//
// r      — the original incoming HTTP request
// relay  — the matching relay config
//
// Flow:
//  1. Read the raw body
//  2. Find the adapter for this relay
//  3. Verify the signature
//  4. Normalize to an Event
//  5. Store the event (if relay.Store is true)
//  6. Forward to the local app
//  7. Mark forwarded in store
//  8. Return the local app's response to the caller
func (e *Engine) Handle(w http.ResponseWriter, r *http.Request, relay RelayConfig) {
	// ── Read the raw body ─────────────────────────────────────────────────────
	// We read the entire body upfront so we can:
	//   a) Pass it to the adapter for signature verification
	//   b) Store it raw for replay
	//   c) Forward it to the local app
	//
	// io.ReadAll reads until EOF — safe for webhook payloads (typically < 1MB).
	// After ReadAll, r.Body is drained — we replace it below so adapters
	// that also read the body still work.
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("[webhook] error reading body for %s: %v", relay.Name, err)
		http.Error(w, "error reading request body", http.StatusBadRequest)
		return
	}
	r.Body.Close()

	// Replace r.Body with a fresh reader so the adapter can read it again.
	// bytes.NewReader creates an io.Reader from a []byte.
	// io.NopCloser wraps it with a no-op Close() so it satisfies io.ReadCloser.
	// This is a common Go pattern: "restore a consumed body."
	r.Body = io.NopCloser(bytes.NewReader(raw))

	// ── Find the adapter ──────────────────────────────────────────────────────
	adapter, ok := e.adapters[relay.Adapter]
	if !ok {
		log.Printf("[webhook] unknown adapter %q for relay %s", relay.Adapter, relay.Name)
		// Fall back to generic — no signature verification, just relay.
		adapter = e.adapters["generic"]
	}

	// ── Verify signature ──────────────────────────────────────────────────────
	// Restore body again before calling Verify — adapter may read it.
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if err := adapter.Verify(r, relay.Secret); err != nil {
		log.Printf("[webhook] signature verification failed for %s: %v", relay.Name, err)
		// 401 Unauthorized — the signature is wrong.
		// Do NOT forward to local app — could be a spoofed request.
		http.Error(w, "webhook signature verification failed", http.StatusUnauthorized)
		return
	}

	// ── Normalize to Event ────────────────────────────────────────────────────
	r.Body = io.NopCloser(bytes.NewReader(raw))
	event, err := adapter.Normalize(r)
	if err != nil {
		log.Printf("[webhook] normalize error for %s: %v", relay.Name, err)
		event = &Event{
			ID:         generateID(),
			Provider:   relay.Adapter,
			Type:       "unknown",
			ReceivedAt: time.Now(),
		}
	}

	// Attach raw bytes and headers to the event.
	event.Raw = raw
	event.Headers = flattenHeaders(r.Header)
	if event.ID == "" {
		event.ID = generateID()
	}
	if event.ReceivedAt.IsZero() {
		event.ReceivedAt = time.Now()
	}

	log.Printf("[webhook] %s event received: provider=%s type=%s id=%s",
		relay.Name, event.Provider, event.Type, event.ID)

	// ── Store the event ───────────────────────────────────────────────────────
	// We store BEFORE forwarding — this guarantees persistence even if
	// the local app is down or crashes while processing.
	if relay.Store && e.store != nil {
		if err := e.store.Save(relay.Name, event); err != nil {
			// Log but don't fail — storage error should not block delivery.
			log.Printf("[webhook] store error for %s: %v", relay.Name, err)
		}
	}

	// ── Forward to local app ──────────────────────────────────────────────────
	statusCode := e.forward(raw, r, relay, event)

	// ── Mark forwarded ────────────────────────────────────────────────────────
	if relay.Store && e.store != nil && statusCode > 0 {
		if err := e.store.MarkForwarded(relay.Name, event.ID, statusCode); err != nil {
			log.Printf("[webhook] mark forwarded error: %v", err)
		}
	}

	// Acknowledge to the provider — Paystack/Flutterwave expect a 200.
	// We always return 200 to the provider as long as we received the event,
	// regardless of what the local app returned.
	// If the local app fails, the event is stored and can be replayed.
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"received","event_id":%q}`, event.ID)
}

// forward sends the raw webhook payload to the local app and returns the status code.
// Returns 0 if the local app is unreachable.
func (e *Engine) forward(raw []byte, original *http.Request, relay RelayConfig, event *Event) int {
	targetURL := e.localURL + original.URL.Path

	// Build a new HTTP request to the local app.
	// We send the ORIGINAL raw payload — not the normalised event.
	// The local app should receive exactly what Paystack sent.
	req, err := http.NewRequest(original.Method, targetURL, bytes.NewReader(raw))
	if err != nil {
		log.Printf("[webhook] error building local request: %v", err)
		return 0
	}

	// Copy the original headers to the local request.
	// This includes signature headers — the local app may want to verify too.
	for key, values := range original.Header {
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}

	// Add namd-specific headers so the local app knows this is a relayed event.
	req.Header.Set("X-Namd-Event-ID", event.ID)
	req.Header.Set("X-Namd-Provider", event.Provider)
	req.Header.Set("X-Namd-Event-Type", event.Type)

	// http.DefaultClient is Go's built-in HTTP client.
	// 10 second timeout — webhook handlers should respond quickly.
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[webhook] local app unreachable for %s: %v — event stored for replay", relay.Name, err)
		return 0
	}
	defer resp.Body.Close()

	log.Printf("[webhook] forwarded %s event %s → local app returned %d", relay.Name, event.ID, resp.StatusCode)
	return resp.StatusCode
}

// Replay resends stored events for a relay to the local app.
// Called via CLI: namd webhook replay payments
func (e *Engine) Replay(relayName string) error {
	if e.store == nil {
		return fmt.Errorf("store is disabled for relay %q", relayName)
	}

	events, err := e.store.List(relayName)
	if err != nil {
		return fmt.Errorf("replay: cannot list events: %w", err)
	}

	// Find relay config.
	var relay RelayConfig
	for _, r := range e.relays {
		if r.Name == relayName {
			relay = r
			break
		}
	}
	if relay.Name == "" {
		return fmt.Errorf("relay %q not found in config", relayName)
	}

	log.Printf("[webhook] replaying %d events for %s", len(events), relayName)

	for _, event := range events {
		// Reconstruct a minimal http.Request for forward().
		req, _ := http.NewRequest("POST", relay.Path, nil)
		statusCode := e.forward(event.Raw, req, relay, event)
		log.Printf("[webhook] replayed event %s → %d", event.ID, statusCode)
	}

	return nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// generateID creates a short random ID for an event.
// Format: 8 random hex characters e.g. "a3f2c891"
// Not cryptographically unique — good enough for event IDs in a dev tool.
func generateID() string {
	return fmt.Sprintf("%08x", rand.Uint32())
}

// flattenHeaders converts http.Header (map[string][]string) to map[string]string.
// Multiple values for the same header are joined with ", ".
// This is what we store in the Event — simpler to serialise and display.
func flattenHeaders(h http.Header) map[string]string {
	flat := make(map[string]string, len(h))
	for key, values := range h {
		if len(values) == 1 {
			flat[key] = values[0]
		} else {
			for i, v := range values {
				if i == 0 {
					flat[key] = v
				} else {
					flat[key] += ", " + v
				}
			}
		}
	}
	return flat
}
