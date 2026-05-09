package webhook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Store persists webhook events to disk and loads them back for replay.
//
// Directory layout:
//
//	~/.namd/webhooks/
//	  payments/              ← one directory per relay name
//	    2026-01-15T14:30:00-abc123.json   ← event metadata
//	    2026-01-15T14:30:00-abc123.raw    ← original payload bytes
//	  github-events/
//	    ...
//
// Why separate .json and .raw files?
// The metadata (json) contains structured info — easy to parse and list.
// The raw payload stays as exact bytes — replay sends it unchanged.
// Mixing them would require custom serialisation.
type Store struct {
	mu      sync.Mutex
	baseDir string // e.g. ~/.namd/webhooks
}

// NewStore creates a Store rooted at baseDir.
// Creates the directory if it does not exist.
func NewStore(baseDir string) (*Store, error) {
	// os.MkdirAll creates the directory and all parents.
	// 0755 = owner can read/write/execute, others can read/execute.
	// Like mkdir -p in bash.
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("webhook store: cannot create dir %s: %w", baseDir, err)
	}
	return &Store{baseDir: baseDir}, nil
}

// Save writes an event to disk under relayName/.
// Called immediately when a webhook arrives, before forwarding.
// This ensures we never lose an event even if the local app is down.
//
// relayName — the name from namd.yml e.g. "payments"
// event     — the normalised Event from the adapter
func (s *Store) Save(relayName string, event *Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Create relay-specific subdirectory.
	dir := filepath.Join(s.baseDir, relayName)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("webhook store: cannot create relay dir: %w", err)
	}

	// Build the base filename from timestamp + event ID.
	// timestamp makes events sortable chronologically.
	// event.ID disambiguates events arriving at the same second.
	ts := event.ReceivedAt.Format("2006-01-02T15-04-05")
	base := filepath.Join(dir, fmt.Sprintf("%s-%s", ts, event.ID))

	// Write the raw payload first.
	// If we crash between writing raw and json, we have the payload
	// and can reconstruct metadata. The reverse is not true.
	if len(event.Raw) > 0 {
		if err := os.WriteFile(base+".raw", event.Raw, 0644); err != nil {
			return fmt.Errorf("webhook store: cannot write raw payload: %w", err)
		}
	}

	// Serialise event metadata to JSON.
	// json.MarshalIndent produces pretty-printed JSON for readability.
	// The Raw field is excluded (json:"-") — it is already in the .raw file.
	data, err := json.MarshalIndent(event, "", "  ")
	if err != nil {
		return fmt.Errorf("webhook store: cannot marshal event: %w", err)
	}

	if err := os.WriteFile(base+".json", data, 0644); err != nil {
		return fmt.Errorf("webhook store: cannot write event metadata: %w", err)
	}

	return nil
}

// List returns all stored events for a relay, newest first.
// Used by the dashboard and the replay command.
func (s *Store) List(relayName string) ([]*Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	dir := filepath.Join(s.baseDir, relayName)

	// filepath.Glob returns all files matching a pattern.
	// "*.json" matches all metadata files in the relay directory.
	pattern := filepath.Join(dir, "*.json")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("webhook store: glob error: %w", err)
	}

	events := make([]*Event, 0, len(files))
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue // skip unreadable files — log in production
		}

		var event Event
		if err := json.Unmarshal(data, &event); err != nil {
			continue // skip corrupt files
		}

		// Load the raw payload back in.
		rawFile := f[:len(f)-5] + ".raw" // replace .json with .raw
		raw, err := os.ReadFile(rawFile)
		if err == nil {
			event.Raw = raw
		}

		events = append(events, &event)
	}

	// Reverse so newest is first.
	// The filenames are timestamp-sorted so reversing gives newest-first.
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}

	return events, nil
}

// MarkForwarded updates the event metadata on disk to record
// that the event was successfully forwarded to the local app.
func (s *Store) MarkForwarded(relayName, eventID string, statusCode int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dir := filepath.Join(s.baseDir, relayName)
	pattern := filepath.Join(dir, fmt.Sprintf("*-%s.json", eventID))
	files, err := filepath.Glob(pattern)
	if err != nil || len(files) == 0 {
		return fmt.Errorf("webhook store: event %s not found", eventID)
	}

	data, err := os.ReadFile(files[0])
	if err != nil {
		return err
	}

	var event Event
	if err := json.Unmarshal(data, &event); err != nil {
		return err
	}

	now := time.Now()
	event.ForwardedAt = &now
	event.StatusCode = statusCode

	updated, err := json.MarshalIndent(event, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(files[0], updated, 0644)
}
