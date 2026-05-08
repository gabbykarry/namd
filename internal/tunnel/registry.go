package tunnel

import "sync"

// Registry is a thread-safe store of active tunnel Sessions.
//
// The server holds ONE registry. Every time a namd client connects
// and identifies itself, a Session is added here.
// Every time a browser request comes in for "gabriel.namd.africa",
// the server looks up "gabriel" in here to find the right connection.
//
// WHY thread-safe?
// The server handles many connections SIMULTANEOUSLY using goroutines.
// Multiple goroutines might call Add, Get, or Remove at the same time.
// Without protection, two goroutines writing to the same map at the
// same time causes a DATA RACE — Go detects this with -race flag
// and it can corrupt memory or crash.
//
// sync.RWMutex is the solution:
//   - RLock/RUnlock — multiple goroutines can READ simultaneously
//   - Lock/Unlock   — only ONE goroutine can WRITE, blocks all readers
//
// This is the standard Go pattern for concurrent map access.
// You will use this pattern constantly in Go server code.
type Registry struct {
	// mu is the mutex that protects sessions.
	// Convention: name it mu, put it directly above what it protects.
	// Unexported — only this package touches it.
	mu sync.RWMutex

	// sessions maps tunnel name → active Session.
	// "gabriel" → &Session{Name: "gabriel", Conn: ...}
	// map is Go's built-in hash map. map[K]V where K=key type, V=value type.
	// Maps must be initialized before use — we do this in NewRegistry().
	sessions map[string]*Session
}

// NewRegistry creates a ready-to-use Registry.
//
// Why not let callers do `Registry{}` directly?
// Because map[string]*Session needs to be initialized with make().
// An uninitialized map is nil — writing to a nil map panics.
// The constructor guarantees the map is always ready.
//
// make(map[K]V) allocates and initializes an empty map.
// This is different from new() — make is for maps, slices, channels.
func NewRegistry() *Registry {
	return &Registry{
		sessions: make(map[string]*Session),
	}
}

// Add registers a new tunnel session.
//
// Returns ErrAlreadyExists if the name is taken.
// The old client must disconnect first before the name can be reused.
//
// Lock() acquires exclusive write access.
// defer mu.Unlock() releases it when Add() returns.
//
// defer is a statement that schedules a function call to run
// when the surrounding function returns — regardless of whether
// it returns normally or via an error.
// This guarantees the mutex is always unlocked even if we return early.
// Forgetting to unlock a mutex causes a deadlock — the program hangs forever.
// defer makes it impossible to forget.
func (r *Registry) Add(s *Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.sessions[s.Name]; exists {
		return ErrAlreadyExists
	}

	r.sessions[s.Name] = s
	return nil
}

// Get retrieves a session by tunnel name.
//
// Returns the session and true if found.
// Returns nil and false if not found.
//
// This is the Go comma-ok idiom for map lookups:
//
//	value, ok := someMap[key]
//	if !ok { // key not in map }
//
// RLock() acquires shared read access.
// Multiple goroutines can RLock simultaneously.
// RLock blocks if any goroutine holds a write Lock().
func (r *Registry) Get(name string) (*Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	s, ok := r.sessions[name]
	return s, ok
}

// Remove deletes a session from the registry.
// Called when a client disconnects.
// Does nothing if the name does not exist — not an error.
//
// delete() is Go's built-in for removing a map entry.
// Safe to call on a non-existent key — no panic, no error.
func (r *Registry) Remove(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.sessions, name)
}

// List returns a snapshot of all active session names.
//
// We return a []string copy — not a reference to the internal map.
// WHY a copy?
// If we returned a reference to sessions, the caller could iterate
// it without holding the mutex — a data race.
// A copy is safe because the caller gets a frozen snapshot.
//
// make([]string, 0, len(r.sessions)) creates a string slice:
//
//	0        = initial length (empty)
//	len(...) = initial capacity (pre-allocated to avoid resizing)
//
// This is a performance pattern — allocate the right size upfront.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.sessions))
	for name := range r.sessions {
		names = append(names, name)
	}
	return names
}
