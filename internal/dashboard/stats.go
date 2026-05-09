package dashboard

import (
	"sync"
	"time"
)

// RequestLog is one HTTP request that flowed through the tunnel.
// We store the last N of these and show them in the dashboard.
type RequestLog struct {
	Method     string        // GET, POST, PUT etc.
	Path       string        // /api/users, /webhooks/payment etc.
	StatusCode int           // 200, 404, 502 etc.
	Duration   time.Duration // how long the local app took to respond
	Timestamp  time.Time     // when the request arrived
	TunnelName string        // which tunnel handled it
}

// TunnelStat holds live stats for one active tunnel.
type TunnelStat struct {
	Name        string    // "gabriel"
	PublicURL   string    // "gabriel.namd.africa"
	ConnectedAt time.Time // when the tunnel was established
	Requests    int64     // total requests served
	BytesIn     int64     // total bytes received from internet
	BytesOut    int64     // total bytes sent to internet
}

// Stats is the central store that both the tunnel code and the dashboard read/write.
//
// It is shared across goroutines — the stream handler writes to it,
// the dashboard HTTP handler reads from it. We protect it with a RWMutex.
//
// Design: one Stats instance lives for the lifetime of the namd client process.
// We pass *Stats to both the tunnel handler and the dashboard server.
// They never own it — they just read or write through the provided pointer.
type Stats struct {
	mu sync.RWMutex

	// Tunnel holds the current tunnel info.
	// We only support one tunnel per client binary right now.
	// Phase 7 (multi-tunnel) will change this to a map.
	Tunnel *TunnelStat

	// Requests is a ring buffer of recent requests.
	// We keep the last 100. Older ones are dropped.
	// A ring buffer avoids unbounded memory growth.
	Requests []RequestLog
	maxLogs  int
}

// NewStats creates a ready-to-use Stats store.
func NewStats() *Stats {
	return &Stats{
		maxLogs:  100,
		Requests: make([]RequestLog, 0, 100),
	}
}

// SetTunnel records that a tunnel is now active.
// Called once when the tunnel connects successfully.
func (s *Stats) SetTunnel(name, publicURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Tunnel = &TunnelStat{
		Name:        name,
		PublicURL:   publicURL,
		ConnectedAt: time.Now(),
	}
}

// ClearTunnel marks the tunnel as disconnected.
// Called when the yamux session closes.
func (s *Stats) ClearTunnel() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Tunnel = nil
}

// RecordRequest adds a completed request to the log.
// Called by the stream handler after each request completes.
//
// If we have hit maxLogs, we drop the oldest entry.
// append() adds to the end — we remove from the front.
// This gives us a FIFO queue of the most recent requests.
func (s *Stats) RecordRequest(log RequestLog) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Update tunnel counters if tunnel is active.
	if s.Tunnel != nil && log.TunnelName == s.Tunnel.Name {
		s.Tunnel.Requests++
		s.Tunnel.BytesOut += int64(log.StatusCode) // placeholder — real bytes tracked in Phase 6
	}

	// Append to front so newest appears first in the dashboard.
	// We prepend by creating a new slice: [newLog, ...existing]
	// Then cap at maxLogs.
	s.Requests = append([]RequestLog{log}, s.Requests...)
	if len(s.Requests) > s.maxLogs {
		// Drop the oldest (last element).
		// s.Requests[:maxLogs] keeps only the first maxLogs elements.
		s.Requests = s.Requests[:s.maxLogs]
	}
}

// Snapshot returns a point-in-time copy of all stats.
// Called by the dashboard handler before rendering the template.
//
// WHY a copy?
// The dashboard handler reads stats while the tunnel goroutine may be writing.
// If we returned references, the template could read partial/inconsistent data.
// A copy under RLock gives the template a consistent frozen snapshot.
func (s *Stats) Snapshot() (tunnel *TunnelStat, requests []RequestLog) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Copy the tunnel stat if it exists.
	if s.Tunnel != nil {
		copy := *s.Tunnel // dereference pointer = copy the struct value
		tunnel = &copy
	}

	// Copy the request slice.
	// make + copy is idiomatic Go for slice copying.
	requests = make([]RequestLog, len(s.Requests))
	copy(requests, s.Requests)

	return tunnel, requests
}
