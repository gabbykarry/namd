package firewall

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gabbykarry/namd/pkg/logger"
)

// Engine holds all firewall rules and enforces them.
// One Engine per namd-server instance.
// Rules are loaded from namd.yml at startup.
type Engine struct {
	rules   map[string]*Rule // tunnel name → rule
	limiter *rateLimiter
	log     *logger.Logger
}

// NewEngine creates a firewall engine from parsed rules.
func NewEngine(rules map[string]*Rule) *Engine {
	return &Engine{
		rules:   rules,
		limiter: newRateLimiter(),
		log:     logger.New("firewall"),
	}
}

// Check evaluates all firewall rules for a request.
//
// tunnelName — which tunnel this request is targeting
// remoteAddr — client's "ip:port" string from conn.RemoteAddr()
//
// Returns nil if the request is allowed.
// Returns an error describing the block reason if denied.
//
// This is called in handlePublicConn on the server — before
// the request reaches the yamux stream or the tunnel client.
func (e *Engine) Check(tunnelName, remoteAddr string) error {
	rule, ok := e.rules[tunnelName]
	if !ok {
		// No rule for this tunnel — allow everything.
		return nil
	}

	// Parse the client IP.
	ip, err := ExtractIP(remoteAddr)
	if err != nil {
		// Cannot parse IP — allow it. Do not block on parse errors.
		e.log.Warn("ip_parse_failed", logger.Fields{
			"tunnel": tunnelName,
			"addr":   remoteAddr,
			"err":    err.Error(),
		})
		return nil
	}

	// ── Step 1: Deny list ─────────────────────────────────────────────────────
	// Deny is checked FIRST — before allow.
	// This means deny always wins, even if the IP is also in the allow list.
	// "allow all except these specific IPs" is the most common pattern.
	if len(rule.DenyCIDRs) > 0 && MatchesAny(ip, rule.DenyCIDRs) {
		e.log.Audit("blocked_deny", logger.Fields{
			"tunnel": tunnelName,
			"ip":     ip.String(),
		})
		return fmt.Errorf("your IP %s is blocked", ip.String())
	}

	// ── Step 2: Allow list ────────────────────────────────────────────────────
	// Only enforced if the allow list is non-empty.
	// Empty allow list = allow everyone (open tunnel).
	// Non-empty allow list = only listed IPs can connect.
	if len(rule.AllowCIDRs) > 0 && !MatchesAny(ip, rule.AllowCIDRs) {
		e.log.Audit("blocked_allow", logger.Fields{
			"tunnel": tunnelName,
			"ip":     ip.String(),
		})
		return fmt.Errorf("your IP %s is not in the allowed list", ip.String())
	}

	// ── Step 3: Rate limit ────────────────────────────────────────────────────
	if rule.RateLimit != nil {
		key := tunnelName + ":" + ip.String() // one counter per tunnel+IP combo
		if exceeded := e.limiter.check(key, rule.RateLimit); exceeded {
			e.log.Audit("rate_limited", logger.Fields{
				"tunnel":   tunnelName,
				"ip":       ip.String(),
				"limit":    rule.RateLimit.Requests,
				"window_s": rule.RateLimit.WindowSeconds,
			})
			return fmt.Errorf("rate limit exceeded: max %d requests per %ds",
				rule.RateLimit.Requests, rule.RateLimit.WindowSeconds)
		}
	}

	return nil // all checks passed
}

// BuildRules constructs firewall Rules from namd.yml config.
// Called during server startup.
//
// cfgFirewall — the firewall map from config.Config.Firewall
// Returns a map of tunnel name → Rule ready for NewEngine().
func BuildRules(cfgFirewall map[string]FirewallConfig) map[string]*Rule {
	rules := make(map[string]*Rule, len(cfgFirewall))
	log := logger.New("firewall")

	for tunnelName, fw := range cfgFirewall {
		rule := &Rule{TunnelName: tunnelName}

		// Parse allow CIDRs.
		if len(fw.Allow) > 0 {
			parsed, invalid := ParseCIDRs(fw.Allow)
			rule.AllowCIDRs = parsed
			for _, inv := range invalid {
				log.Warn("invalid_cidr", logger.Fields{
					"tunnel": tunnelName,
					"cidr":   inv,
					"list":   "allow",
				})
			}
		}

		// Parse deny CIDRs.
		if len(fw.Deny) > 0 {
			parsed, invalid := ParseCIDRs(fw.Deny)
			rule.DenyCIDRs = parsed
			for _, inv := range invalid {
				log.Warn("invalid_cidr", logger.Fields{
					"tunnel": tunnelName,
					"cidr":   inv,
					"list":   "deny",
				})
			}
		}

		// Parse rate limit.
		if fw.RateLimit.Requests > 0 && fw.RateLimit.WindowSeconds > 0 {
			rule.RateLimit = &RateLimitRule{
				Requests:      fw.RateLimit.Requests,
				WindowSeconds: fw.RateLimit.WindowSeconds,
			}
		}

		rules[tunnelName] = rule
		log.Info("rule_loaded", logger.Fields{
			"tunnel":    tunnelName,
			"allow":     len(rule.AllowCIDRs),
			"deny":      len(rule.DenyCIDRs),
			"ratelimit": rule.RateLimit != nil,
		})
	}

	return rules
}

// FirewallConfig is the config shape received from namd.yml.
// Mirrors config.Firewall — duplicated here to avoid circular imports.
type FirewallConfig struct {
	Allow     []string
	Deny      []string
	RateLimit RateLimitConfig
}

type RateLimitConfig struct {
	Requests      int
	WindowSeconds int64
}

// ── Rate limiter ──────────────────────────────────────────────────────────────

// rateLimiter tracks request counts per key using a sliding window.
//
// Sliding window algorithm:
//
//	We divide time into 1-second buckets.
//	Each key has a map of bucket → count.
//	To check the limit: sum counts in the last WindowSeconds buckets.
//	If sum >= Requests → rate limited.
//
// Why sliding window instead of fixed window?
// Fixed window: reset counter at the top of every minute.
//
//	Allows burst: 100 requests at 0:59, then 100 more at 1:00.
//	That is 200 requests in 2 seconds — not what "100/minute" means.
//
// Sliding window: look at the last 60 seconds from NOW.
//
//	Always exactly the last 60 seconds — no burst at reset boundaries.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]map[int64]int // key → (unix_second → count)
}

func newRateLimiter() *rateLimiter {
	rl := &rateLimiter{
		buckets: make(map[string]map[int64]int),
	}
	// Clean up old buckets every minute to prevent memory leak.
	go rl.cleanup()
	return rl
}

// check increments the counter for key and returns true if the limit is exceeded.
func (rl *rateLimiter) check(key string, rule *RateLimitRule) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now().Unix() // current unix timestamp in seconds

	// Ensure the bucket map exists for this key.
	if rl.buckets[key] == nil {
		rl.buckets[key] = make(map[int64]int)
	}

	// Increment current second's bucket.
	rl.buckets[key][now]++

	// Count total requests in the sliding window.
	windowStart := now - rule.WindowSeconds
	total := 0
	for second, count := range rl.buckets[key] {
		if second > windowStart {
			total += count
		}
	}

	return total > rule.Requests
}

// cleanup removes buckets older than 1 hour every minute.
// Without this, the buckets map grows forever — one entry per IP per second.
func (rl *rateLimiter) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		cutoff := time.Now().Unix() - 3600 // keep last hour
		for key, buckets := range rl.buckets {
			for second := range buckets {
				if second < cutoff {
					delete(buckets, second)
				}
			}
			// Remove the key entirely if all its buckets are gone.
			if len(buckets) == 0 {
				delete(rl.buckets, key)
			}
		}
		rl.mu.Unlock()
	}
}

// IPString formats a net.IP for logging.
func IPString(ip net.IP) string {
	if ip == nil {
		return "unknown"
	}
	return ip.String()
}
