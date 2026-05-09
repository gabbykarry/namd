package loadbalancer

import (
	"fmt"
	"math/rand"
	"sync"
)

// Random picks a healthy target at random for each request.
//
// When to use random vs round_robin?
// They perform identically on average over many requests.
// Random avoids the "thundering herd" problem where all clients
// are in sync and hit the same target at the same time.
// For most uses, round_robin is fine. Random is an option.
type Random struct {
	targets []*Target
	mu      sync.RWMutex
}

func NewRandom(targets []*Target) *Random {
	return &Random{targets: targets}
}

func (r *Random) Next() (string, error) {
	r.mu.RLock()
	healthy := healthyTargets(r.targets)
	r.mu.RUnlock()

	if len(healthy) == 0 {
		return "", fmt.Errorf("random: no healthy targets available")
	}

	// rand.Intn(n) returns a random int in [0, n).
	// Not cryptographically random — we do not need that for load balancing.
	// math/rand is fast and sufficient.
	idx := rand.Intn(len(healthy))
	return healthy[idx].Addr, nil
}

func (r *Random) MarkHealthy(addr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.targets {
		if t.Addr == addr {
			t.healthy.Store(true)
			return
		}
	}
}

func (r *Random) MarkUnhealthy(addr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.targets {
		if t.Addr == addr {
			t.healthy.Store(false)
			return
		}
	}
}

func (r *Random) Targets() []*Target {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Target, len(r.targets))
	copy(out, r.targets)
	return out
}
