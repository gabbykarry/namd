package loadbalancer

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

// HealthChecker probes all targets in a Balancer on a regular interval.
// Dead targets are marked unhealthy and removed from rotation.
// Recovered targets are marked healthy and returned to rotation.
//
// This runs in its own goroutine — start it with go checker.Start().
type HealthChecker struct {
	balancer Balancer
	path     string        // HTTP path to probe e.g. "/health"
	interval time.Duration // how often to probe e.g. 10s
	client   *http.Client  // HTTP client with short timeout
}

// NewHealthChecker creates a checker for the given balancer.
//
// path     — the HTTP path that returns 200 when the target is healthy
// interval — how often to probe all targets
func NewHealthChecker(balancer Balancer, path string, interval time.Duration) *HealthChecker {
	if path == "" {
		path = "/health" // sensible default
	}

	return &HealthChecker{
		balancer: balancer,
		path:     path,
		interval: interval,
		// Short timeout — if the target does not respond in 3 seconds, it is unhealthy.
		// We do not want health checks to pile up waiting for slow targets.
		client: &http.Client{Timeout: 3 * time.Second},
	}
}

// Start begins the health check loop.
// Runs forever — call in a goroutine: go checker.Start()
//
// time.NewTicker(d) creates a Ticker that fires every d duration.
// ticker.C is a channel that receives the current time at each tick.
// We range over it — each receive blocks until the next tick.
func (h *HealthChecker) Start() {
	log.Printf("[healthcheck] starting — interval=%s path=%s", h.interval, h.path)

	// Run one check immediately before the first tick.
	// Without this, targets would not be checked until interval elapses.
	h.checkAll()

	ticker := time.NewTicker(h.interval)
	defer ticker.Stop() // always stop the ticker to avoid goroutine leak

	for range ticker.C {
		h.checkAll()
	}
}

// checkAll probes every target in the balancer once.
func (h *HealthChecker) checkAll() {
	for _, target := range h.balancer.Targets() {
		// Check each target in its own goroutine so checks run in parallel.
		// If we had 10 targets each taking 3s to time out, sequential
		// checking would take 30s per interval. Parallel takes 3s.
		go h.checkOne(target)
	}
}

// checkOne probes a single target and updates its health status.
func (h *HealthChecker) checkOne(target *Target) {
	url := fmt.Sprintf("http://%s%s", target.Addr, h.path)

	resp, err := h.client.Get(url)
	if err != nil {
		// Cannot reach target — mark unhealthy if it was healthy.
		if target.IsHealthy() {
			h.balancer.MarkUnhealthy(target.Addr)
			log.Printf("[healthcheck] %s is DOWN — removed from rotation", target.Addr)
		}
		return
	}
	defer resp.Body.Close()

	// A healthy target returns 2xx on the health check path.
	// Anything else (500, 404) is treated as unhealthy.
	// We are strict — a 404 means the app does not have a /health endpoint,
	// which is a misconfiguration, not a healthy target.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if !target.IsHealthy() {
			h.balancer.MarkHealthy(target.Addr)
			log.Printf("[healthcheck] %s is UP — returned to rotation", target.Addr)
		}
	} else {
		if target.IsHealthy() {
			h.balancer.MarkUnhealthy(target.Addr)
			log.Printf("[healthcheck] %s returned %d — removed from rotation", target.Addr, resp.StatusCode)
		}
	}
}
