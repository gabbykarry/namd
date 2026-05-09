// Package loadbalancer distributes incoming tunnel requests across
// multiple local backend targets.
//
// It plugs into the namd client — instead of always dialling localhost:3000,
// the client asks the balancer for the next target.
//
// Configuration in namd.yml:
//
//	load_balancer:
//	  api:
//	    strategy: round_robin
//	    targets:
//	      - addr: "3000"
//	      - addr: "3001"
//	    health_check:
//	      path: /health
//	      interval: 10s
package loadbalancer

import (
	"fmt"
	"sync/atomic"
)

// Balancer is the interface every load balancing strategy implements.
// The client calls Next() to get the address to dial for the next request.
//
// Same pattern as webhook.Adapter — one interface, swappable strategies.
// The client code never changes when we add a new strategy.
type Balancer interface {
	// Next returns the address of the next target to use.
	// Returns an error if no healthy targets are available.
	Next() (string, error)

	// MarkHealthy marks a target as healthy (back in rotation).
	// Called by the health checker when a target recovers.
	MarkHealthy(addr string)

	// MarkUnhealthy removes a target from rotation.
	// Called by the health checker when a target fails.
	MarkUnhealthy(addr string)

	// Targets returns all targets (healthy and unhealthy).
	// Used by the health checker to know what to probe.
	Targets() []*Target
}

// Target represents one backend address the balancer can route to.
//
// addr    — "localhost:3000" or just "3000"
// healthy — whether this target is currently in rotation
// conns   — number of active connections (used by LeastConn strategy)
//
// atomic.Int64 for conns — we increment/decrement this from multiple
// goroutines simultaneously (one per request). Using atomic means we
// do not need a mutex just for this one counter.
//
// atomic.Int64 is a struct with methods: Add, Load, Store, Swap.
// It is safe for concurrent use without any locking.
// The CPU handles the atomicity at the hardware level.
type Target struct {
	Addr    string
	healthy atomic.Bool  // atomic bool — true = in rotation
	conns   atomic.Int64 // active connection count
}

// NewTarget creates a target and marks it healthy by default.
// addr — "3000" or "localhost:3000"
func NewTarget(addr string) *Target {
	t := &Target{Addr: normaliseAddr(addr)}
	t.healthy.Store(true) // starts healthy
	return t
}

// IsHealthy returns whether this target is currently in rotation.
func (t *Target) IsHealthy() bool {
	return t.healthy.Load()
}

// ActiveConns returns the number of active connections to this target.
func (t *Target) ActiveConns() int64 {
	return t.conns.Load()
}

// IncrConns increments the active connection count.
// Called when a new request starts routing to this target.
func (t *Target) IncrConns() {
	t.conns.Add(1)
}

// DecrConns decrements the active connection count.
// Called when a request to this target completes.
func (t *Target) DecrConns() {
	t.conns.Add(-1)
}

// normaliseAddr ensures the address has a host prefix.
// "3000" → "localhost:3000"
// "localhost:3000" → unchanged
// "127.0.0.1:3000" → unchanged
func normaliseAddr(addr string) string {
	// If it contains a colon, it already has host:port format.
	for _, c := range addr {
		if c == ':' {
			return addr
		}
	}
	return fmt.Sprintf("localhost:%s", addr)
}

// New creates a Balancer for the given strategy name and list of addresses.
// strategy — "round_robin", "least_conn", "random"
// addrs    — list of target addresses from namd.yml
//
// Returns an error if the strategy is unknown or no addresses provided.
func New(strategy string, addrs []string) (Balancer, error) {
	if len(addrs) == 0 {
		return nil, fmt.Errorf("loadbalancer: no targets provided")
	}

	targets := make([]*Target, len(addrs))
	for i, addr := range addrs {
		targets[i] = NewTarget(addr)
	}

	switch strategy {
	case "round_robin", "":
		return NewRoundRobin(targets), nil
	case "least_conn":
		return NewLeastConn(targets), nil
	case "random":
		return NewRandom(targets), nil
	default:
		return nil, fmt.Errorf("loadbalancer: unknown strategy %q", strategy)
	}
}

// NewPassthrough creates a single-target balancer that always returns the same addr.
// Used when no load_balancer config is set — equivalent to the old `local` string.
func NewPassthrough(addr string) Balancer {
	return NewRoundRobin([]*Target{NewTarget(addr)})
}
