package loadbalancer

import (
	"fmt"
	"sync"
	"sync/atomic"
)

// RoundRobin distributes requests evenly across all healthy targets
// by rotating through them in order.
//
// request 1 → target[0]
// request 2 → target[1]
// request 3 → target[2]
// request 4 → target[0]  ← wraps around
//
// The rotation is tracked with an atomic counter.
// counter % len(healthyTargets) gives the index — wraps naturally.
//
// Example with 3 targets:
//
//	counter=0: 0%3=0 → target[0]
//	counter=1: 1%3=1 → target[1]
//	counter=2: 2%3=2 → target[2]
//	counter=3: 3%3=0 → target[0] ← back to start
type RoundRobin struct {
	targets []*Target
	counter atomic.Uint64 // increments with every request
	mu      sync.RWMutex  // protects targets slice from concurrent modification
}

// NewRoundRobin creates a round robin balancer with the given targets.
func NewRoundRobin(targets []*Target) *RoundRobin {
	return &RoundRobin{targets: targets}
}

// Next returns the next healthy target in rotation.
//
// We get healthy targets first, then apply modulo.
// We do NOT apply modulo to the full targets slice —
// an unhealthy target in the middle would still get picked.
func (r *RoundRobin) Next() (string, error) {
	r.mu.RLock()
	healthy := healthyTargets(r.targets)
	r.mu.RUnlock()

	if len(healthy) == 0 {
		return "", fmt.Errorf("round_robin: no healthy targets available")
	}

	// atomic.Uint64.Add returns the NEW value after adding.
	// We subtract 1 to get the value before the add — that is our index.
	// This is thread-safe: even if 1000 goroutines call Next() simultaneously,
	// each gets a unique counter value because Add is atomic.
	n := r.counter.Add(1) - 1

	// Modulo gives us the index into the healthy slice.
	// uint64 modulo int requires a cast — len() returns int in Go.
	idx := int(n) % len(healthy)
	return healthy[idx].Addr, nil
}

func (r *RoundRobin) MarkHealthy(addr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.targets {
		if t.Addr == addr {
			t.healthy.Store(true)
			return
		}
	}
}

func (r *RoundRobin) MarkUnhealthy(addr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.targets {
		if t.Addr == addr {
			t.healthy.Store(false)
			return
		}
	}
}

func (r *RoundRobin) Targets() []*Target {
	r.mu.RLock()
	defer r.mu.RUnlock()
	// Return a copy so callers cannot modify our slice.
	out := make([]*Target, len(r.targets))
	copy(out, r.targets)
	return out
}

// healthyTargets returns only the healthy targets from a slice.
// This is a package-level helper used by all three strategies.
// It does NOT lock — callers must hold the appropriate lock.
func healthyTargets(targets []*Target) []*Target {
	out := make([]*Target, 0, len(targets))
	for _, t := range targets {
		if t.IsHealthy() {
			out = append(out, t)
		}
	}
	return out
}
