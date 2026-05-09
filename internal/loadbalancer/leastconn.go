package loadbalancer

import (
	"fmt"
	"sync"
)

// LeastConn routes each new request to the target with the fewest
// active connections at that moment.
//
// When do you use this instead of round robin?
// Round robin assumes all requests take the same time.
// In practice some requests are fast (GET /) and some are slow (file upload).
// With round robin, the slow request holds a target while fast ones pile up.
// LeastConn naturally routes new requests away from busy targets.
//
// Example:
//
//	target[0]: 5 active connections  ← skip
//	target[1]: 1 active connection   ← pick this one
//	target[2]: 3 active connections  ← skip
type LeastConn struct {
	targets []*Target
	mu      sync.RWMutex
}

func NewLeastConn(targets []*Target) *LeastConn {
	return &LeastConn{targets: targets}
}

// Next scans all healthy targets and picks the one with the lowest
// active connection count.
//
// Linear scan is O(n) — fine for the small number of targets in namd.
// Production load balancers use a heap for O(log n) — not needed here.
func (l *LeastConn) Next() (string, error) {
	l.mu.RLock()
	healthy := healthyTargets(l.targets)
	l.mu.RUnlock()

	if len(healthy) == 0 {
		return "", fmt.Errorf("least_conn: no healthy targets available")
	}

	// Find the target with the minimum active connections.
	// Start with the first healthy target as the candidate.
	best := healthy[0]
	for _, t := range healthy[1:] {
		if t.ActiveConns() < best.ActiveConns() {
			best = t
		}
	}

	// Increment connection count BEFORE returning.
	// The caller is about to open a connection to this target.
	// We must count it immediately or the next call to Next() would
	// not see it and might pick the same target twice.
	//
	// The caller MUST call best.DecrConns() when the request finishes.
	// In handleStream, we wrap this with defer.
	best.IncrConns()
	return best.Addr, nil
}

func (l *LeastConn) MarkHealthy(addr string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, t := range l.targets {
		if t.Addr == addr {
			t.healthy.Store(true)
			return
		}
	}
}

func (l *LeastConn) MarkUnhealthy(addr string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, t := range l.targets {
		if t.Addr == addr {
			t.healthy.Store(false)
			return
		}
	}
}

func (l *LeastConn) Targets() []*Target {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]*Target, len(l.targets))
	copy(out, l.targets)
	return out
}
