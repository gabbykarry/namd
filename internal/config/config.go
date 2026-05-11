// Package config owns everything related to namd.yml.
// No other package reads the file directly — they all receive a *Config.
// This is a clean architecture boundary: file I/O stays here, logic stays elsewhere.
package config

// Config is the root struct.
// It maps 1:1 with the top-level keys in namd.yml.
//
// Every field has a struct tag: `yaml:"key_name"`
// The yaml library reads this tag to know which YAML key
// maps to which Go field. Without the tag, the library
// tries to match by lowercasing the field name — we always
// use explicit tags so there is zero ambiguity.
//
// A struct tag looks like: `yaml:"version"`
// It sits between backticks after the field type.
// It is NOT a string — it is metadata the compiler reads.
type Config struct {
	Version   string              `yaml:"version"`
	Identity  IdentityConfig      `yaml:"identity"`
	Server    ServerConfig        `yaml:"server"`
	Domain    DomainConfig        `yaml:"domain"`
	Tunnels   map[string]Tunnel   `yaml:"tunnels"`
	Firewall  map[string]Firewall `yaml:"firewall"`
	LB        map[string]LB       `yaml:"load_balancer"`
	Webhooks  WebhookConfig       `yaml:"webhooks"`
	Cache     CacheConfig         `yaml:"cache"`
	Handoff   HandoffConfig       `yaml:"handoff"`
	Mesh      MeshConfig          `yaml:"mesh"`
	Dashboard DashboardConfig     `yaml:"dashboard"`
}

// ─────────────────────────────────────────────
// IDENTITY
// ─────────────────────────────────────────────

// IdentityConfig is who this namd instance is on the network.
// Name becomes your handle — @gabriel on the peer system.
// Region tells the server which edge node to prefer.
// af-west = Lagos. af-east = Nairobi. af-south = Cape Town.
type IdentityConfig struct {
	Name   string `yaml:"name"`
	Region string `yaml:"region"`
}

// ─────────────────────────────────────────────
// SERVER
// ─────────────────────────────────────────────

// ServerConfig tells the client which namd server to connect to.
// If empty, falls back to NAMD_SERVER env var, then localhost:9000.
type ServerConfig struct {
	// Addr is the server address e.g. "namd.online:9000"
	Addr string `yaml:"addr"`
}

// ─────────────────────────────────────────────
// DOMAIN
// ─────────────────────────────────────────────

// DomainConfig controls how your tunnel is reached from the internet.
// There are three paths a user can take:
//
//  1. Custom domain  — user owns gabrielbuilds.dev, namd provisions SSL for it.
//     User adds the domain in the web UI or here in the yml.
//     We verify ownership via DNS TXT record then get a cert.
//
//  2. namd subdomain — user gets gabriel.namd.online automatically.
//     Wildcard SSL (*.namd.online) already covers this.
//     Nothing extra needed — just set Subdomain field.
//
//  3. Fallback pool  — if nothing is set, we loop through FallbackPool,
//     test each domain, and use the first one that works.
//     User sees a working URL — never sees this complexity.
//
// Only one of Custom or Subdomain should be set.
// If both are set, Custom takes priority. Validator enforces this.
type DomainConfig struct {
	// Custom is a domain the user owns e.g. "gabrielbuilds.dev"
	// Leave empty if you don't have one.
	// When set, namd will:
	//   1. Ask user to add a DNS TXT record to prove ownership
	//   2. Provision a Let's Encrypt certificate for it
	//   3. Route all traffic hitting that domain to this tunnel
	Custom string `yaml:"custom"`

	// Subdomain is the user's prefix on our managed domain.
	// "gabriel" → "gabriel.namd.online"
	// If namd.online is unavailable, we walk the FallbackPool.
	Subdomain string `yaml:"subdomain"`

	// SSL controls how TLS certificates are handled.
	SSL SSLConfig `yaml:"ssl"`

	// FallbackPool is the ordered list of domains namd tries
	// when no custom domain is set. We test each one —
	// DNS reachable? Wildcard works? Cert obtainable?
	// First one that passes all checks wins.
	// We ship sane defaults. User only sets this to override order.
	FallbackPool []string `yaml:"fallback_pool"`
}

// SSLConfig controls TLS certificate behaviour.
//
// Provider options:
//
//	"letsencrypt" — automatic, free, renews itself. Default. Use this.
//	"self_signed" — for local LAN testing. Browsers will warn. Not for production.
//	"none"        — plain HTTP. Only for internal-only tools behind a VPN.
//
// Email is required by Let's Encrypt so they can warn you 30 days before
// cert expiry if AutoRenew somehow fails. We never use it for marketing.
//
// AutoRenew — Let's Encrypt certs expire every 90 days.
// true = namd renews at 30 days before expiry. You never touch it again.
// false = you manage renewal yourself. Not recommended.
type SSLConfig struct {
	Provider  string `yaml:"provider"`
	Email     string `yaml:"email"`
	AutoRenew bool   `yaml:"auto_renew"`
}

// ─────────────────────────────────────────────
// TUNNELS
// ─────────────────────────────────────────────

// Tunnel defines one tunnel entry.
//
// Why map[string]Tunnel in Config and not []Tunnel?
// Because in YAML, tunnels are named:
//
//	tunnels:
//	  api:          ← this "api" string is the map key
//	    proto: http
//	  grpc:         ← this "grpc" string is another map key
//	    proto: tcp
//
// A slice []Tunnel would give us the values but lose the names.
// A map[string]Tunnel gives us both — the name AND its config together.
// We need the name to match tunnels against firewall rules, load
// balancer config, webhook relay rules etc.
//
// Proto — "http" or "tcp".
//
//	http tunnels: get URL routing, Host header inspection, HTTP logging
//	tcp tunnels:  raw byte forwarding, no HTTP awareness
//
// Addr — local port as a string e.g. "3000".
// We use string not int because sometimes you need "host:port"
// format like "127.0.0.1:3000" — a string handles both cases.
//
// Subdomain — overrides the identity-level domain for THIS tunnel only.
// "gabriel-api" → gabriel-api.namd.online
// Useful when you run multiple tunnels and want distinct URLs per tunnel.
//
// Auth — optional bearer token protection for this tunnel.
// Without this, anyone with the URL can send requests to your tunnel.
type Tunnel struct {
	Proto     string     `yaml:"proto"`
	Addr      string     `yaml:"addr"`
	Subdomain string     `yaml:"subdomain"`
	Auth      TunnelAuth `yaml:"auth"`
}

// TunnelAuth adds bearer token protection to a tunnel.
// Type is "bearer" for now — we will add "basic" and "mtls" later.
// Token MUST use ${ENV_VAR} syntax — secrets never hardcoded in yml files.
// The loader substitutes env vars before the YAML parser runs.
type TunnelAuth struct {
	Type  string `yaml:"type"`
	Token string `yaml:"token"`
}

// ─────────────────────────────────────────────
// FIREWALL
// ─────────────────────────────────────────────

// Firewall holds IP filtering rules for one tunnel.
// The key in the Config.Firewall map must match a key in Config.Tunnels.
// Validator checks this — you cannot define a firewall rule for
// a tunnel that does not exist.
//
// Allow — list of CIDR ranges permitted.
//
//	"0.0.0.0/0"    = everyone (open)
//	"41.0.0.0/8"   = Africa block (rough approximation)
//	"105.0.0.0/8"  = more African IPs
//
// Deny — list of CIDR ranges blocked.
// Deny is evaluated AFTER allow — if an IP matches both, deny wins.
// This means: allow everyone EXCEPT these specific ranges.
//
// RateLimit — per-IP request cap within a time window.
// Protects against webhook floods, scraping, abuse.
type Firewall struct {
	Allow     []string  `yaml:"allow"`
	Deny      []string  `yaml:"deny"`
	RateLimit RateLimit `yaml:"rate_limit"`
}

// RateLimit controls request frequency per IP address.
// Requests — max requests allowed in the Window.
// Window — duration string parsed by time.ParseDuration.
//
//	Valid: "30s", "1m", "5m", "1h"
//	Invalid: "1 minute", "60" (no unit)
//
// The validator checks Window is a valid duration string.
type RateLimit struct {
	Requests int    `yaml:"requests"`
	Window   string `yaml:"window"`
}

// ─────────────────────────────────────────────
// LOAD BALANCER
// ─────────────────────────────────────────────

// LB is the load balancer config for one tunnel.
// Use when you run the same service on multiple local ports
// and want namd to spread incoming traffic across them.
// Common during local load testing or running multiple workers.
//
// The key in Config.LB must match a key in Config.Tunnels.
// Validator enforces this — same rule as Firewall.
//
// Strategy — how requests are distributed across Targets:
//
//	"round_robin" — requests go to targets in rotating order: 1,2,3,1,2,3
//	"least_conn"  — next request goes to the target with fewest open connections
//	"random"      — random target selected per request
//
// Targets — the local ports to balance across.
// HealthCheck — namd probes each target. Dead targets leave rotation.
// They re-enter rotation when health checks pass again.
type LB struct {
	Strategy    string      `yaml:"strategy"`
	Targets     []LBTarget  `yaml:"targets"`
	HealthCheck HealthCheck `yaml:"health_check"`
}

// LBTarget is one backend address the load balancer can route to.
// Addr is a local port "3001" or full address "127.0.0.1:3001".
type LBTarget struct {
	Addr string `yaml:"addr"`
}

// HealthCheck defines how namd probes a backend to check it is alive.
// Path — HTTP GET path that should return 200 when healthy.
//
//	Standard convention: "/health" or "/healthz"
//
// Interval — how often we probe. "10s" = every 10 seconds.
// Parsed by time.ParseDuration. Validator checks it is valid.
type HealthCheck struct {
	Path     string `yaml:"path"`
	Interval string `yaml:"interval"`
}

// ─────────────────────────────────────────────
// WEBHOOKS
// ─────────────────────────────────────────────

// WebhookConfig holds all webhook relay definitions.
// Relay is a slice — you can intercept multiple webhook
// providers on the same tunnel simultaneously.
type WebhookConfig struct {
	Relay []WebhookRelay `yaml:"relay"`
}

// WebhookRelay is one webhook interception rule.
//
// Name — human label for this relay. Used in CLI and dashboard.
//
//	e.g. "payments", "github-events", "crm-hooks"
//
// Tunnel — which tunnel to intercept on.
// Must match a key in Config.Tunnels. Validator checks this.
//
// Path — the specific URL path namd intercepts.
//
//	e.g. "/webhooks/payment"
//	When gabriel.namd.online/webhooks/payment receives a request,
//	namd intercepts it, passes it to the Adapter, then forwards it
//	to your local server. Your local server sees it as normal HTTP.
//
// Adapter — which adapter processes this webhook.
//
//	Built-in: "paystack", "flutterwave", "github", "generic"
//	Community: anyone can add an adapter via PR — they implement
//	the Adapter interface in internal/webhook/adapter.go
//	and register it in internal/webhook/adapters/registry.go
//
// Store — if true, namd saves the raw event payload.
//
//	Why: if your local server is down when the webhook fires,
//	you lose the event. With Store=true, it is saved and
//	you can replay it once your server is back up.
//
// Replay — if true, you can resend stored events:
//
//	`namd webhook replay payments` replays all stored events
//	for the "payments" relay to your local server.
type WebhookRelay struct {
	Name    string `yaml:"name"`
	Tunnel  string `yaml:"tunnel"`
	Path    string `yaml:"path"`
	Adapter string `yaml:"adapter"`
	Store   bool   `yaml:"store"`
	Replay  bool   `yaml:"replay"`
}

// ─────────────────────────────────────────────
// CACHE
// ─────────────────────────────────────────────

// CacheConfig controls the offline proxy cache.
//
// The problem it solves: African devs frequently lose internet mid-session.
// When connectivity drops, any API call to Paystack, Flutterwave etc. fails.
// With cache enabled, namd intercepts outgoing requests to Targets and
// serves the last cached response instead of failing.
// Your app keeps working. You keep coding.
//
// Enabled — master on/off switch.
//
// TTL — how long a cached response is considered fresh.
//
//	"5m" = 5 minutes. After this, the cache entry expires.
//	Next successful online request refreshes it.
//
// Targets — base URLs of external APIs to cache.
//
//	namd caches ALL responses from these base URLs.
//	e.g. "https://api.paystack.co" covers:
//	  GET https://api.paystack.co/transaction
//	  GET https://api.paystack.co/customer/123
//	  etc.
type CacheConfig struct {
	Enabled bool     `yaml:"enabled"`
	TTL     string   `yaml:"ttl"`
	Targets []string `yaml:"targets"`
}

// ─────────────────────────────────────────────
// HANDOFF
// ─────────────────────────────────────────────

// HandoffConfig controls the live server handoff feature.
//
// The problem: your laptop battery is dying mid-demo.
// Your local server is running. Client is watching.
// `namd handoff @tunde` — your server moves to tunde's machine.
// Same URL, same tunnel, zero downtime.
//
// MaxDuration — hard cap on how long tunde runs your server.
// "60m" = 60 minutes then the container is force-killed.
// No extensions. This is a security boundary — not a courtesy.
// After 60m, you need to issue a fresh handoff.
//
// Sandbox — isolation layer your code runs in on the peer machine.
//
//	"docker" — Docker container. Strong filesystem + network isolation.
//	           Peer's machine files, env vars, credentials are invisible.
//	           This is the default and the safest option.
//	"wasm"   — WebAssembly sandbox. Lighter weight but more restricted.
//	           Good for stateless services. Cannot do raw TCP or disk I/O.
//
// TrustedPeers — @handles of people permitted to receive your handoff.
//
//	Must start with @. This is enforced by the validator.
//	Must exist on the namd server. Verified at handoff time, not parse time.
//	Must explicitly accept your handoff request at runtime.
//	Even if listed here, they can reject. You cannot force a handoff.
//
// Security model summary:
//
//	✓ Peer must be in this list
//	✓ Peer must be registered on namd server
//	✓ Peer must actively accept
//	✓ Code runs sandboxed — cannot touch peer's filesystem
//	✓ Token expires — max MaxDuration, then killed
//	✓ Peer can cancel anytime: `namd handoff cancel`
type HandoffConfig struct {
	MaxDuration  string   `yaml:"max_duration"`
	Sandbox      string   `yaml:"sandbox"`
	TrustedPeers []string `yaml:"trusted_peers"`
}

// ─────────────────────────────────────────────
// MESH
// ─────────────────────────────────────────────

// MeshConfig is for team private mesh networking.
//
// Problem: you want to share a tunnel with your team
// without exposing it to the public internet.
// Mesh creates a private encrypted overlay network
// between all team members running namd with the same
// Team name and Secret.
//
// Team — your team's name on the namd network.
// Secret — shared secret all members use to join the mesh.
//
//	MUST use ${ENV_VAR} — never hardcode this in the yml file.
//	Every team member sets MESH_SECRET in their environment.
type MeshConfig struct {
	Team   string `yaml:"team"`
	Secret string `yaml:"secret"`
}

// ─────────────────────────────────────────────
// DASHBOARD
// ─────────────────────────────────────────────

// DashboardConfig controls the local web UI.
//
// When enabled, namd serves a web interface at:
//
//	http://localhost:{Port}
//
// The dashboard shows:
//   - Active tunnels and their public URLs
//   - Live HTTP request log (method, path, status, latency)
//   - Webhook events received and their replay status
//   - Handoff status — who is running your server and for how long
//   - Domain/SSL status — cert expiry, renewal schedule
//   - Custom domain management — add/verify/remove domains
//   - Peer management — add/remove trusted peers
//   - Team mesh status
//
// Port defaults to 5555 if not set in yml.
// The validator sets this default so callers always get a valid port.
//
// Enabled defaults to true — we set this in the validator
// if the dashboard block is missing from the yml entirely.
type DashboardConfig struct {
	Port    int  `yaml:"port"`
	Enabled bool `yaml:"enabled"`
}
