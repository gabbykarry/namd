package admin

import (
	"fmt"
	"sync"
	"time"
)

// ServerStore implements the Store interface.
// It wraps the auth.AccountStore and tunnel.Registry
// to provide the admin panel with read/write access.
//
// We use a simple in-memory audit log — last 500 events.
// In production this would write to a file or database.
type ServerStore struct {
	mu       sync.RWMutex
	accounts map[string]*AdminAccount
	tunnels  map[string]*AdminTunnel
	audit    []AuditEntry
	maxAudit int
}

// AdminAccount is the full account record the admin store holds.
type AdminAccount struct {
	Name       string
	Email      string
	TokenHash  string
	CreatedAt  time.Time
	LastSeenAt time.Time
	Banned     bool
}

// AdminTunnel is a live tunnel record.
type AdminTunnel struct {
	Name        string
	PublicURL   string
	ClientIP    string
	ConnectedAt time.Time
	Requests    int64
	// Disconnect is called to force-close this tunnel.
	Disconnect func()
}

func NewServerStore() *ServerStore {
	return &ServerStore{
		accounts: make(map[string]*AdminAccount),
		tunnels:  make(map[string]*AdminTunnel),
		maxAudit: 500,
	}
}

// RegisterAccount adds or updates an account in the admin store.
// Called by the server's registration handler alongside auth.AccountStore.
func (s *ServerStore) RegisterAccount(name, email, tokenHash string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accounts[name] = &AdminAccount{
		Name:      name,
		Email:     email,
		TokenHash: tokenHash,
		CreatedAt: time.Now(),
	}
}

// UpdateLastSeen records when an account last authenticated.
func (s *ServerStore) UpdateLastSeen(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if acc, ok := s.accounts[name]; ok {
		acc.LastSeenAt = time.Now()
	}
}

// AddTunnel records a new active tunnel.
func (s *ServerStore) AddTunnel(name, publicURL, clientIP string, disconnect func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tunnels[name] = &AdminTunnel{
		Name:        name,
		PublicURL:   publicURL,
		ClientIP:    clientIP,
		ConnectedAt: time.Now(),
		Disconnect:  disconnect,
	}
}

// RemoveTunnel removes a tunnel when it disconnects.
func (s *ServerStore) RemoveTunnel(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tunnels, name)
}

// IncrRequests increments the request counter for a tunnel.
func (s *ServerStore) IncrRequests(tunnelName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.tunnels[tunnelName]; ok {
		t.Requests++
	}
}

// AddAuditEvent records a security event.
// Called from the auth package's logger.
func (s *ServerStore) AddAuditEvent(event, name, ip, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := AuditEntry{
		Time:   time.Now(),
		Event:  event,
		Name:   name,
		IP:     ip,
		Reason: reason,
	}
	// Prepend — newest first.
	s.audit = append([]AuditEntry{entry}, s.audit...)
	if len(s.audit) > s.maxAudit {
		s.audit = s.audit[:s.maxAudit]
	}
}

// ── Store interface implementation ────────────────────────────────────────────

func (s *ServerStore) Accounts() []AccountInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]AccountInfo, 0, len(s.accounts))
	for _, a := range s.accounts {
		result = append(result, AccountInfo{
			Name:       a.Name,
			Email:      a.Email,
			CreatedAt:  a.CreatedAt,
			LastSeenAt: a.LastSeenAt,
			Banned:     a.Banned,
		})
	}
	return result
}

func (s *ServerStore) ActiveTunnels() []TunnelInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]TunnelInfo, 0, len(s.tunnels))
	for _, t := range s.tunnels {
		result = append(result, TunnelInfo{
			Name:        t.Name,
			PublicURL:   t.PublicURL,
			ClientIP:    t.ClientIP,
			ConnectedAt: t.ConnectedAt,
			Requests:    t.Requests,
		})
	}
	return result
}

func (s *ServerStore) RecentAuditLog(n int) []AuditEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if n > len(s.audit) {
		n = len(s.audit)
	}
	result := make([]AuditEntry, n)
	copy(result, s.audit[:n])
	return result
}

func (s *ServerStore) BanAccount(name, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	acc, ok := s.accounts[name]
	if !ok {
		return fmt.Errorf("account @%s not found", name)
	}
	acc.Banned = true
	s.audit = append([]AuditEntry{{
		Time:   time.Now(),
		Event:  "account_banned",
		Name:   name,
		Reason: reason,
	}}, s.audit...)
	return nil
}

func (s *ServerStore) UnbanAccount(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	acc, ok := s.accounts[name]
	if !ok {
		return fmt.Errorf("account @%s not found", name)
	}
	acc.Banned = false
	s.audit = append([]AuditEntry{{
		Time:  time.Now(),
		Event: "account_unbanned",
		Name:  name,
	}}, s.audit...)
	return nil
}

func (s *ServerStore) DisconnectTunnel(name string) error {
	s.mu.Lock()
	t, ok := s.tunnels[name]
	s.mu.Unlock()

	if !ok {
		return fmt.Errorf("tunnel @%s not found or not active", name)
	}

	// Call the disconnect function stored when the tunnel registered.
	if t.Disconnect != nil {
		t.Disconnect()
	}

	s.AddAuditEvent("tunnel_force_disconnected", name, "", "admin action")
	return nil
}

// IsBanned checks if an account is banned.
// Called by the auth layer before registering a tunnel.
func (s *ServerStore) IsBanned(name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if acc, ok := s.accounts[name]; ok {
		return acc.Banned
	}
	return false
}
