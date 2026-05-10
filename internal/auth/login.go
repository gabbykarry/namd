package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gabbykarry/namd/pkg/logger"
)

// AccountStore holds registered accounts on the server.
// In production this would be a database (SQLite or Postgres).
// For now it is an in-memory map — persisted to a JSON file on disk.
//
// Map key: account name e.g. "gabriel"
// Map value: Account struct with the token hash
type AccountStore struct {
	mu       sync.RWMutex
	accounts map[string]*Account
	log      *logger.Logger
}

// Account is one registered developer on the namd server.
type Account struct {
	Name       string    `json:"name"`
	Email      string    `json:"email"`
	TokenHash  string    `json:"token_hash"` // sha256(token) — NOT the token itself
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	Banned     bool      `json:"banned"` // can be set to block an account
}

// accountsFilePath returns the path where accounts are persisted.
// On the server this is /home/namd/.namd/accounts.json
// (the namd system user's home directory).
func accountsFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/namd-accounts.json"
	}
	return filepath.Join(home, ".namd", "accounts.json")
}

// NewAccountStore creates an account store and loads any previously
// persisted accounts from disk. On a fresh server the file does not
// exist yet — that is fine, we start with an empty store.
func NewAccountStore() *AccountStore {
	s := &AccountStore{
		accounts: make(map[string]*Account),
		log:      logger.New("auth"),
	}
	// Load persisted accounts — ignore error on fresh server.
	_ = s.load()
	return s
}

// save writes all accounts to disk as JSON.
// Must be called WITHOUT holding the mutex — it acquires its own read lock.
// Calling this while holding a write lock causes a deadlock.
func (s *AccountStore) save() error {
	// Snapshot under read lock — fast.
	s.mu.RLock()
	data, err := json.MarshalIndent(s.accounts, "", "  ")
	s.mu.RUnlock()

	if err != nil {
		return err
	}

	path := accountsFilePath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// load reads accounts from disk into memory.
// Called once at startup.
func (s *AccountStore) load() error {
	path := accountsFilePath()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil // fresh server — no accounts yet
	}
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return json.Unmarshal(data, &s.accounts)
}

// Register adds a new account.
// Called by the server's registration handler.
// Returns an error if the name is already taken.
func (s *AccountStore) Register(name, email, token string) error {
	s.mu.Lock()

	if _, exists := s.accounts[name]; exists {
		s.mu.Unlock()
		return fmt.Errorf("name %q is already registered", name)
	}

	hash := hashToken(token)
	s.accounts[name] = &Account{
		Name:      name,
		Email:     email,
		TokenHash: hash,
		CreatedAt: time.Now(),
	}

	// Release lock BEFORE calling save().
	// save() acquires its own read lock — calling it while holding
	// the write lock causes a deadlock (write lock blocks read lock).
	s.mu.Unlock()

	// Persist to disk so this account survives a server restart.
	if err := s.save(); err != nil {
		s.log.Warn("accounts_save_failed", logger.Fields{"err": err.Error()})
	}

	s.log.Audit("account_created", logger.Fields{
		"name":  name,
		"email": email,
	})

	return nil
}

// Verify checks if a token is valid for the given name.
// Called by the server on every tunnel connection.
//
// Returns nil if valid. Returns a descriptive error if not.
//
// Security properties:
//  1. We hash the provided token and compare hashes — never compare raw tokens
//  2. We use subtle.ConstantTimeCompare — prevents timing attacks
//  3. We check the Banned flag — allows revoking accounts
//  4. All failures are logged with the client IP for abuse detection
func (s *AccountStore) Verify(name, token, clientIP string) error {
	s.mu.RLock()
	account, exists := s.accounts[name]
	s.mu.RUnlock()

	if !exists {
		s.log.Audit("auth_failed", logger.Fields{
			"name":   name,
			"ip":     clientIP,
			"reason": "account_not_found",
		})
		// Return a generic error — do not reveal whether the account exists.
		// "account not found" tells an attacker which names are NOT registered,
		// helping them enumerate valid names. Generic error prevents this.
		return fmt.Errorf("invalid credentials")
	}

	if account.Banned {
		s.log.Audit("auth_failed", logger.Fields{
			"name":   name,
			"ip":     clientIP,
			"reason": "account_banned",
		})
		return fmt.Errorf("account is suspended")
	}

	// Hash the provided token and compare with stored hash.
	provided := hashToken(token)

	// subtle.ConstantTimeCompare compares two byte slices in constant time.
	// Regular string comparison (==) short-circuits on the first mismatch.
	// This means comparing "aaaa" vs "aaab" takes slightly longer than
	// comparing "aaaa" vs "baaa" because the first differs earlier.
	// An attacker can measure these tiny time differences to guess tokens
	// byte by byte — this is a timing attack.
	// ConstantTimeCompare always takes the same time regardless of
	// where the mismatch is — timing attack impossible.
	if subtle.ConstantTimeCompare([]byte(provided), []byte(account.TokenHash)) != 1 {
		s.log.Audit("auth_failed", logger.Fields{
			"name":   name,
			"ip":     clientIP,
			"reason": "invalid_token",
		})
		return fmt.Errorf("invalid credentials")
	}

	// Update last seen timestamp.
	s.mu.Lock()
	account.LastSeenAt = time.Now()
	s.mu.Unlock()

	s.log.Info("auth_ok", logger.Fields{
		"name": name,
		"ip":   clientIP,
	})

	return nil
}

// Ban blocks an account from connecting.
// Used when abuse is detected.
func (s *AccountStore) Ban(name, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	account, exists := s.accounts[name]
	if !exists {
		return fmt.Errorf("account %q not found", name)
	}

	account.Banned = true
	s.log.Audit("account_banned", logger.Fields{
		"name":   name,
		"reason": reason,
	})
	return nil
}

// hashToken computes sha256 of a token and returns the hex string.
// This is a one-way function — cannot recover the token from the hash.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// ── Client-side verification helper ──────────────────────────────────────────

// LoadAndVerifyCredentials loads credentials and checks they are not expired.
// Call this at the start of `namd start` to fail fast if not registered.
func LoadAndVerifyCredentials() (*Credentials, error) {
	creds, err := LoadCredentials()
	if err != nil {
		return nil, err
	}

	if creds.IsExpired() {
		return nil, fmt.Errorf("credentials expired — run: namd auth register")
	}

	return creds, nil
}
