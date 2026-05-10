package dashboard

import (
	"sync"
	"time"
)

// RequestLog is one HTTP request that flowed through the tunnel.
type RequestLog struct {
	Method     string
	Path       string
	StatusCode int
	Duration   time.Duration
	Timestamp  time.Time
	TunnelName string
}

// WebhookEvent is one intercepted webhook event.
type WebhookEvent struct {
	ID         string
	RelayName  string
	Provider   string
	EventType  string
	ReceivedAt time.Time
	StatusCode int // 0 = not yet forwarded
	Replayed   bool
	RawJSON    string // pretty-printed payload for inspector
}

// HandoffInfo describes an active or pending handoff.
type HandoffInfo struct {
	ID        string
	From      string
	To        string
	Subdomain string
	Status    string // "pending", "active", "cancelled", "expired"
	StartedAt time.Time
	ExpiresAt time.Time
}

// TunnelStat holds live stats for one active tunnel.
type TunnelStat struct {
	Name        string
	PublicURL   string
	ConnectedAt time.Time
	Requests    int64
	BytesIn     int64
	BytesOut    int64
}

// Stats is the central store shared between tunnel code and dashboard.
type Stats struct {
	mu sync.RWMutex

	Tunnel   *TunnelStat
	Requests []RequestLog
	Webhooks []WebhookEvent
	Handoffs []HandoffInfo
	maxLogs  int

	// subscribers holds WebSocket connections waiting for push updates.
	// When anything changes, we notify all subscribers.
	subscribers []chan struct{}
}

func NewStats() *Stats {
	return &Stats{
		maxLogs:  100,
		Requests: make([]RequestLog, 0, 100),
		Webhooks: make([]WebhookEvent, 0, 100),
		Handoffs: make([]HandoffInfo, 0, 20),
	}
}

func (s *Stats) SetTunnel(name, publicURL string) {
	s.mu.Lock()
	s.Tunnel = &TunnelStat{
		Name:        name,
		PublicURL:   publicURL,
		ConnectedAt: time.Now(),
	}
	s.mu.Unlock()
	s.notify()
}

func (s *Stats) ClearTunnel() {
	s.mu.Lock()
	s.Tunnel = nil
	s.mu.Unlock()
	s.notify()
}

func (s *Stats) RecordRequest(log RequestLog) {
	s.mu.Lock()
	if s.Tunnel != nil && log.TunnelName == s.Tunnel.Name {
		s.Tunnel.Requests++
	}
	s.Requests = append([]RequestLog{log}, s.Requests...)
	if len(s.Requests) > s.maxLogs {
		s.Requests = s.Requests[:s.maxLogs]
	}
	s.mu.Unlock()
	s.notify()
}

func (s *Stats) RecordWebhook(event WebhookEvent) {
	s.mu.Lock()
	s.Webhooks = append([]WebhookEvent{event}, s.Webhooks...)
	if len(s.Webhooks) > s.maxLogs {
		s.Webhooks = s.Webhooks[:s.maxLogs]
	}
	s.mu.Unlock()
	s.notify()
}

func (s *Stats) RecordHandoff(h HandoffInfo) {
	s.mu.Lock()
	// Update existing or append new.
	found := false
	for i, existing := range s.Handoffs {
		if existing.ID == h.ID {
			s.Handoffs[i] = h
			found = true
			break
		}
	}
	if !found {
		s.Handoffs = append([]HandoffInfo{h}, s.Handoffs...)
		if len(s.Handoffs) > 20 {
			s.Handoffs = s.Handoffs[:20]
		}
	}
	s.mu.Unlock()
	s.notify()
}

// Subscribe returns a channel that receives a signal whenever stats change.
// Used by the WebSocket handler to push updates to the browser.
func (s *Stats) Subscribe() chan struct{} {
	ch := make(chan struct{}, 1)
	s.mu.Lock()
	s.subscribers = append(s.subscribers, ch)
	s.mu.Unlock()
	return ch
}

// Unsubscribe removes a subscriber channel.
func (s *Stats) Unsubscribe(ch chan struct{}) {
	s.mu.Lock()
	for i, sub := range s.subscribers {
		if sub == ch {
			s.subscribers = append(s.subscribers[:i], s.subscribers[i+1:]...)
			break
		}
	}
	s.mu.Unlock()
}

// notify signals all subscribers that stats have changed.
// Non-blocking — if subscriber is not listening, skip it.
func (s *Stats) notify() {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, ch := range s.subscribers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// Snapshot returns a consistent copy of all stats.
type Snapshot struct {
	Tunnel   *TunnelStat
	Requests []RequestLog
	Webhooks []WebhookEvent
	Handoffs []HandoffInfo
}

func (s *Stats) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	snap := Snapshot{
		Requests: make([]RequestLog, len(s.Requests)),
		Webhooks: make([]WebhookEvent, len(s.Webhooks)),
		Handoffs: make([]HandoffInfo, len(s.Handoffs)),
	}

	if s.Tunnel != nil {
		t := *s.Tunnel
		snap.Tunnel = &t
	}

	copy(snap.Requests, s.Requests)
	copy(snap.Webhooks, s.Webhooks)
	copy(snap.Handoffs, s.Handoffs)

	return snap
}
