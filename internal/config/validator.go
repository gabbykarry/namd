package config

import (
	"fmt"
	"strings"
	"time"
)

// validate checks the parsed config for correctness and applies defaults.
//
// It is unexported (lowercase) — only loader.go calls it.
// It receives *Config so it can both READ and WRITE the config.
// Writing is needed for defaults — e.g. setting Port=5555 when not specified.
//
// Validation philosophy:
//   - Structural checks happen here (required fields, valid enum values, formats)
//   - Network checks do NOT happen here (does @tunde exist on the server?)
//   - Cross-reference checks happen here (does firewall tunnel name exist in tunnels?)
//
// Why no network checks at parse time?
// Config loading must work offline. A developer might load config to
// inspect it, generate docs, or run dry-run — without a live server.
// Network verification happens at runtime, in the feature packages.
func validate(cfg *Config) error {
	if err := validateRoot(cfg); err != nil {
		return err
	}
	if err := validateIdentity(cfg); err != nil {
		return err
	}
	if err := validateDomain(cfg); err != nil {
		return err
	}
	if err := validateTunnels(cfg); err != nil {
		return err
	}
	if err := validateFirewall(cfg); err != nil {
		return err
	}
	if err := validateLB(cfg); err != nil {
		return err
	}
	if err := validateWebhooks(cfg); err != nil {
		return err
	}
	if err := validateHandoff(cfg); err != nil {
		return err
	}

	// Apply defaults last — after all validation passes.
	// This way defaults only apply to a config we know is valid.
	applyDefaults(cfg)

	return nil
}

// ── Root ─────────────────────────────────────────────────────────────────────

func validateRoot(cfg *Config) error {
	if cfg.Version == "" {
		return fmt.Errorf("config: version is required")
	}
	// We only support version "1" right now.
	// When we add version "2" with breaking changes, old configs
	// will get a clear error instead of silently misbehaving.
	if cfg.Version != "1" {
		return fmt.Errorf("config: unsupported version %q — only \"1\" is supported", cfg.Version)
	}
	return nil
}

// ── Identity ─────────────────────────────────────────────────────────────────

func validateIdentity(cfg *Config) error {
	if cfg.Identity.Name == "" {
		return fmt.Errorf("config: identity.name is required — this becomes your @handle on the network")
	}

	// Names become URL subdomains. Subdomains only allow:
	// lowercase letters, digits, hyphens. No spaces. No underscores.
	// We enforce this so "My Name" does not silently become a broken URL.
	name := cfg.Identity.Name
	for _, c := range name {
		if !isAlphanumericOrHyphen(c) {
			return fmt.Errorf(
				"config: identity.name %q is invalid — only lowercase letters, digits, and hyphens are allowed",
				name,
			)
		}
	}

	validRegions := map[string]bool{
		"af-west":  true, // Lagos
		"af-east":  true, // Nairobi
		"af-south": true, // Cape Town
		"":         true, // empty = server picks closest
	}
	if !validRegions[cfg.Identity.Region] {
		return fmt.Errorf(
			"config: identity.region %q is not valid — valid options: af-west, af-east, af-south",
			cfg.Identity.Region,
		)
	}

	return nil
}

// ── Domain ───────────────────────────────────────────────────────────────────

func validateDomain(cfg *Config) error {
	d := cfg.Domain

	// Both Custom and Subdomain set — ambiguous. Reject it clearly.
	// We could silently pick one but that hides user mistakes.
	// Explicit errors are always better than silent surprises.
	if d.Custom != "" && d.Subdomain != "" {
		return fmt.Errorf(
			"config: domain.custom and domain.subdomain are both set — use one or the other, not both",
		)
	}

	// Custom domain basic format check.
	// We do not do full DNS validation here — that is a network operation.
	// We just check it looks like a domain: has a dot, no spaces, no protocol prefix.
	if d.Custom != "" {
		if strings.Contains(d.Custom, " ") {
			return fmt.Errorf("config: domain.custom %q cannot contain spaces", d.Custom)
		}
		if strings.HasPrefix(d.Custom, "http://") || strings.HasPrefix(d.Custom, "https://") {
			return fmt.Errorf(
				"config: domain.custom %q should be just the domain name, not a URL — use \"gabrielbuilds.dev\" not \"https://gabrielbuilds.dev\"",
				d.Custom,
			)
		}
		if !strings.Contains(d.Custom, ".") {
			return fmt.Errorf("config: domain.custom %q does not look like a valid domain — expected format: \"gabrielbuilds.dev\"", d.Custom)
		}
	}

	// SSL provider must be one of our known values if set.
	validProviders := map[string]bool{
		"letsencrypt": true,
		"self_signed": true,
		"none":        true,
		"":            true, // empty = we default to letsencrypt in applyDefaults
	}
	if !validProviders[d.SSL.Provider] {
		return fmt.Errorf(
			"config: domain.ssl.provider %q is not valid — valid options: letsencrypt, self_signed, none",
			d.SSL.Provider,
		)
	}

	// Let's Encrypt requires an email for renewal warnings.
	// If provider is letsencrypt and email is empty, warn them.
	// We allow it but explain the consequence.
	if d.SSL.Provider == "letsencrypt" && d.SSL.Email == "" {
		fmt.Println("config: warning — domain.ssl.email is not set. Let's Encrypt cannot warn you if auto-renewal fails.")
	}

	return nil
}

// ── Tunnels ───────────────────────────────────────────────────────────────────

func validateTunnels(cfg *Config) error {
	// range over a map gives: key, value
	// name = "api", t = the Tunnel struct for that entry
	for name, t := range cfg.Tunnels {
		if err := validateOneTunnel(name, t); err != nil {
			return err
		}
	}
	return nil
}

func validateOneTunnel(name string, t Tunnel) error {
	if name == "" {
		return fmt.Errorf("config: a tunnel has an empty name — all tunnels must be named")
	}

	// strings.ToLower so "HTTP" and "http" both pass.
	// We store the original value — we only normalise for comparison.
	proto := strings.ToLower(t.Proto)
	if proto != "http" && proto != "tcp" {
		return fmt.Errorf(
			"config: tunnel %q has invalid proto %q — must be \"http\" or \"tcp\"",
			name, t.Proto,
		)
	}

	if t.Addr == "" {
		return fmt.Errorf("config: tunnel %q is missing addr — set the local port e.g. addr: \"3000\"", name)
	}

	// Validate auth if set.
	if t.Auth.Type != "" {
		validAuthTypes := map[string]bool{"bearer": true}
		if !validAuthTypes[t.Auth.Type] {
			return fmt.Errorf(
				"config: tunnel %q auth.type %q is not valid — only \"bearer\" is supported",
				name, t.Auth.Type,
			)
		}
		if t.Auth.Token == "" {
			return fmt.Errorf(
				"config: tunnel %q has auth.type set but auth.token is empty — set the token or remove auth",
				name,
			)
		}
	}

	return nil
}

// ── Firewall ─────────────────────────────────────────────────────────────────

func validateFirewall(cfg *Config) error {
	for name, fw := range cfg.Firewall {
		// Cross-reference check — firewall rule must reference a real tunnel.
		// This is the kind of mistake that is silent without a check:
		// user types "apis" instead of "api" — no error, rule never applies.
		if _, exists := cfg.Tunnels[name]; !exists {
			return fmt.Errorf(
				"config: firewall rule %q references tunnel %q which does not exist in tunnels — check spelling",
				name, name,
			)
		}

		if fw.RateLimit.Requests < 0 {
			return fmt.Errorf("config: firewall %q rate_limit.requests cannot be negative", name)
		}

		// Validate window duration if set.
		if fw.RateLimit.Window != "" {
			if _, err := time.ParseDuration(fw.RateLimit.Window); err != nil {
				return fmt.Errorf(
					"config: firewall %q rate_limit.window %q is not a valid duration — use formats like \"60s\", \"1m\", \"1h\"",
					name, fw.RateLimit.Window,
				)
			}
		}
	}
	return nil
}

// ── Load Balancer ─────────────────────────────────────────────────────────────

func validateLB(cfg *Config) error {
	for name, lb := range cfg.LB {
		// Cross-reference — LB must reference a real tunnel.
		if _, exists := cfg.Tunnels[name]; !exists {
			return fmt.Errorf(
				"config: load_balancer %q references tunnel %q which does not exist",
				name, name,
			)
		}

		if lb.Strategy != "" {
			validStrategies := map[string]bool{
				"round_robin": true,
				"least_conn":  true,
				"random":      true,
			}
			if !validStrategies[lb.Strategy] {
				return fmt.Errorf(
					"config: load_balancer %q strategy %q is not valid — valid options: round_robin, least_conn, random",
					name, lb.Strategy,
				)
			}
		}

		if len(lb.Targets) == 0 {
			return fmt.Errorf("config: load_balancer %q has no targets — add at least one target addr", name)
		}

		for i, target := range lb.Targets {
			if target.Addr == "" {
				return fmt.Errorf("config: load_balancer %q target[%d] is missing addr", name, i)
			}
		}

		// Validate health check interval duration if set.
		if lb.HealthCheck.Interval != "" {
			if _, err := time.ParseDuration(lb.HealthCheck.Interval); err != nil {
				return fmt.Errorf(
					"config: load_balancer %q health_check.interval %q is not a valid duration — use formats like \"10s\", \"1m\"",
					name, lb.HealthCheck.Interval,
				)
			}
		}
	}
	return nil
}

// ── Webhooks ─────────────────────────────────────────────────────────────────

func validateWebhooks(cfg *Config) error {
	// Track relay names to catch duplicates.
	// map[string]bool is a common Go pattern for a "set" —
	// Go has no built-in set type, so we use a map with bool values.
	// true = "this name has been seen". We only use the key, not the value.
	seen := map[string]bool{}

	for i, relay := range cfg.Webhooks.Relay {
		if relay.Name == "" {
			return fmt.Errorf("config: webhooks.relay[%d] is missing a name", i)
		}

		if seen[relay.Name] {
			return fmt.Errorf("config: webhooks.relay has duplicate name %q — relay names must be unique", relay.Name)
		}
		seen[relay.Name] = true

		// Cross-reference — relay must point to a real tunnel.
		if relay.Tunnel != "" {
			if _, exists := cfg.Tunnels[relay.Tunnel]; !exists {
				return fmt.Errorf(
					"config: webhooks.relay %q references tunnel %q which does not exist",
					relay.Name, relay.Tunnel,
				)
			}
		}

		if relay.Path == "" {
			return fmt.Errorf("config: webhooks.relay %q is missing path", relay.Name)
		}

		// Path must start with /
		if !strings.HasPrefix(relay.Path, "/") {
			return fmt.Errorf(
				"config: webhooks.relay %q path %q must start with \"/\" — e.g. \"/webhooks/payment\"",
				relay.Name, relay.Path,
			)
		}

		if relay.Adapter == "" {
			return fmt.Errorf("config: webhooks.relay %q is missing adapter — use \"paystack\", \"flutterwave\", \"github\", or \"generic\"", relay.Name)
		}

		// Replay requires Store. You cannot replay what you did not store.
		if relay.Replay && !relay.Store {
			return fmt.Errorf(
				"config: webhooks.relay %q has replay: true but store: false — enable store to use replay",
				relay.Name,
			)
		}
	}
	return nil
}

// ── Handoff ───────────────────────────────────────────────────────────────────

func validateHandoff(cfg *Config) error {
	h := cfg.Handoff

	if h.MaxDuration != "" {
		d, err := time.ParseDuration(h.MaxDuration)
		if err != nil {
			return fmt.Errorf(
				"config: handoff.max_duration %q is not a valid duration — use formats like \"60m\", \"1h\"",
				h.MaxDuration,
			)
		}
		// Cap at 4 hours. This is a deliberate product decision —
		// handoff is for emergencies, not permanent hosting.
		if d > 4*time.Hour {
			return fmt.Errorf("config: handoff.max_duration %q exceeds the maximum of 4h", h.MaxDuration)
		}
	}

	if h.Sandbox != "" {
		validSandboxes := map[string]bool{
			"docker":  true,
			"wasm":    true,
			"process": true,
		}
		if !validSandboxes[h.Sandbox] {
			return fmt.Errorf(
				"config: handoff.sandbox %q is not valid — valid options: docker, process, wasm",
				h.Sandbox,
			)
		}
	}

	// Validate trusted peer handles.
	// Each must start with @ — this is the namd handle convention.
	// We check format here. We do NOT check if the handle exists on the
	// server — that is a network call that happens at handoff time.
	for i, peer := range h.TrustedPeers {
		if peer == "" {
			return fmt.Errorf("config: handoff.trusted_peers[%d] is empty", i)
		}
		if !strings.HasPrefix(peer, "@") {
			return fmt.Errorf(
				"config: handoff.trusted_peers[%d] %q is missing the @ prefix — namd handles look like \"@tunde\"",
				i, peer,
			)
		}
		// Must have something after the @
		if len(peer) < 2 {
			return fmt.Errorf("config: handoff.trusted_peers[%d] %q is empty after @", i, peer)
		}
	}

	return nil
}

// ── Defaults ─────────────────────────────────────────────────────────────────

// applyDefaults fills in sensible values for fields that were not set in yml.
// This runs AFTER validation so we only default a config we know is valid.
// Users get a fully working config even if they only set the minimum fields.
func applyDefaults(cfg *Config) {
	// Dashboard defaults
	if cfg.Dashboard.Port == 0 {
		cfg.Dashboard.Port = 5555
	}
	// If the dashboard block exists but enabled was not set,
	// default to enabled. Zero value of bool is false in Go,
	// but "not set" and "explicitly false" are indistinguishable
	// from the YAML parser. We choose: if port is set, enable it.
	if cfg.Dashboard.Port != 0 {
		cfg.Dashboard.Enabled = true
	}

	// SSL defaults
	if cfg.Domain.SSL.Provider == "" {
		cfg.Domain.SSL.Provider = "letsencrypt"
	}
	// AutoRenew defaults to true — safer default.
	// Zero value is false in Go, so we must set this explicitly.
	cfg.Domain.SSL.AutoRenew = true

	// Handoff defaults
	if cfg.Handoff.MaxDuration == "" {
		cfg.Handoff.MaxDuration = "60m"
	}
	if cfg.Handoff.Sandbox == "" {
		cfg.Handoff.Sandbox = "docker"
	}

	// Domain fallback pool default — if user did not specify one,
	// use our curated list from loader.go
	if len(cfg.Domain.FallbackPool) == 0 {
		cfg.Domain.FallbackPool = DefaultFallbackPool
	}

	// Load balancer strategy default
	for name, lb := range cfg.LB {
		if lb.Strategy == "" {
			lb.Strategy = "round_robin"
			// Important: maps return copies of values in Go.
			// Modifying lb directly does not modify cfg.LB[name].
			// We must assign the modified copy back into the map.
			cfg.LB[name] = lb
		}
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// isAlphanumericOrHyphen returns true if c is a-z, 0-9, or hyphen.
// Used to validate identity names which become URL subdomains.
//
// rune is Go's type for a single Unicode character.
// A string in Go is a sequence of runes under the hood.
// range over a string gives index + rune.
func isAlphanumericOrHyphen(c rune) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '-'
}
