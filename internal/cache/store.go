// Package cache implements the offline-first response cache.
// When your internet drops, namd serves cached responses for
// configured target URLs so your local app keeps working.
package cache

import (
	"log"
	"sync"
	"time"
)

// Entry is one cached HTTP response.
// We store the raw response bytes — the exact bytes the server sent.
// This includes status line, headers, and body.
// We replay these bytes directly to the caller when serving from cache.
type Entry struct {
	// Body is the full raw HTTP response bytes.
	// "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{...}"
	Body []byte

	// ExpiresAt is when this entry becomes stale.
	// After this time, the next request goes to the real server.
	ExpiresAt time.Time

	// CachedAt records when we stored this response.
	// Shown in the dashboard — "cached 3m ago"
	CachedAt time.Time

	// URL is the full request URL — for display in dashboard.
	URL string
}

// IsExpired returns true if this entry is past its TTL.
func (e *Entry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// Store is an in-memory cache of HTTP responses.
//
// sync.Map vs map + RWMutex:
//
//	We use sync.Map here because:
//	- Reads are much more frequent than writes (typical cache workload)
//	- sync.Map is optimised for this exact pattern — concurrent reads
//	- No boilerplate: no mu.Lock(), no defer mu.Unlock()
//
//	When to use map + RWMutex instead:
//	- When you need to iterate over all keys atomically
//	- When writes and reads are equally frequent
//	- When you need atomic read-modify-write operations
//
// sync.Map stores interface{} (any) values — we cast to *Entry on retrieval.
type Store struct {
	entries sync.Map
	ttl     time.Duration
}

// NewStore creates a cache store with the given TTL.
// ttl — how long each cached response stays fresh e.g. 5 * time.Minute
func NewStore(ttl time.Duration) *Store {
	s := &Store{ttl: ttl}

	// Start background cleanup goroutine.
	// Expired entries do not automatically disappear from sync.Map —
	// we need to periodically sweep and delete them.
	// Without this, the cache grows forever — a memory leak.
	go s.cleanup()

	return s
}

// Get retrieves a cached response for the given cache key.
// Returns the entry and true if found and not expired.
// Returns nil and false if not found or expired.
//
// The cache key is built from the request — see cacheKey() in proxy.go.
func (s *Store) Get(key string) (*Entry, bool) {
	// sync.Map.Load returns (value interface{}, ok bool)
	// We type-assert the value to *Entry.
	val, ok := s.entries.Load(key)
	if !ok {
		return nil, false // not in cache
	}

	// Type assertion: val.(type) checks and converts interface{} to concrete type.
	// The second return value is whether the assertion succeeded.
	// It will always succeed here since we only store *Entry values.
	entry, ok := val.(*Entry)
	if !ok {
		return nil, false
	}

	if entry.IsExpired() {
		// Delete expired entry — do not serve stale data.
		s.entries.Delete(key)
		return nil, false
	}

	return entry, true
}

// Set stores a response in the cache.
// key   — the cache key (built from request URL + method)
// body  — the full raw HTTP response bytes
// url   — the original request URL (for display)
func (s *Store) Set(key, url string, body []byte) {
	now := time.Now()
	entry := &Entry{
		Body:      body,
		ExpiresAt: now.Add(s.ttl),
		CachedAt:  now,
		URL:       url,
	}
	// sync.Map.Store sets key → value.
	// Thread-safe — no lock needed.
	s.entries.Store(key, entry)
}

// Flush removes all entries from the cache.
// Called when the user explicitly clears the cache.
func (s *Store) Flush() {
	// sync.Map.Range iterates over all key-value pairs.
	// We delete each one inside the range callback.
	// The callback returns true to continue iteration, false to stop.
	s.entries.Range(func(key, _ interface{}) bool {
		s.entries.Delete(key)
		return true // continue
	})
}

// Stats returns the number of entries in the cache.
// Used by the dashboard.
func (s *Store) Stats() (total, expired int) {
	s.entries.Range(func(_, val interface{}) bool {
		total++
		if entry, ok := val.(*Entry); ok && entry.IsExpired() {
			expired++
		}
		return true
	})
	return total, expired
}

// cleanup runs forever, sweeping expired entries every minute.
// Runs in its own goroutine — started in NewStore().
func (s *Store) cleanup() {
	// time.NewTicker fires every minute.
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		var deleted int
		s.entries.Range(func(key, val interface{}) bool {
			if entry, ok := val.(*Entry); ok && entry.IsExpired() {
				s.entries.Delete(key)
				deleted++
			}
			return true
		})
		if deleted > 0 {
			log.Printf("[cache] swept %d expired entries", deleted)
			_ = deleted // suppress unused variable warning in quiet mode
		}
	}
}
