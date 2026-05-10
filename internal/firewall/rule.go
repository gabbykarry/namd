// Package firewall enforces the IP filtering and rate limiting rules
// configured in namd.yml under the firewall block.
//
// Rules are evaluated in this order for every incoming request:
//  1. Deny list  — if IP matches any deny CIDR → 403 immediately
//  2. Allow list — if non-empty and IP not in it → 403
//  3. Rate limit — if IP exceeded requests/window → 429
//  4. Pass       — forward to tunnel
package firewall

import (
	"fmt"
	"net"
)

// Rule holds the parsed firewall config for one tunnel.
type Rule struct {
	TunnelName string
	AllowCIDRs []*net.IPNet // empty = allow all
	DenyCIDRs  []*net.IPNet
	RateLimit  *RateLimitRule // nil = no rate limiting
}

// RateLimitRule holds parsed rate limit values.
type RateLimitRule struct {
	Requests      int   // max requests allowed in the window
	WindowSeconds int64 // window duration in seconds
}

// ParseCIDRs converts CIDR strings into parsed net.IPNet values.
// Invalid entries are skipped and returned in the second return value.
//
// Examples:
//
//	"0.0.0.0/0"  → matches all IPv4
//	"1.2.3.4/32" → matches exactly 1.2.3.4
//	"10.0.0.0/8" → matches 10.x.x.x
func ParseCIDRs(cidrs []string) ([]*net.IPNet, []string) {
	var parsed []*net.IPNet
	var invalid []string

	for _, cidr := range cidrs {
		// net.ParseCIDR returns the network (not the host IP).
		// "1.2.3.4/24" → network = "1.2.3.0/24"
		// We want the network to check membership with Contains().
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			invalid = append(invalid, cidr)
			continue
		}
		parsed = append(parsed, network)
	}

	return parsed, invalid
}

// MatchesAny returns true if ip is contained in any of the networks.
func MatchesAny(ip net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// ExtractIP parses an IP from a "host:port" string.
// conn.RemoteAddr().String() returns "1.2.3.4:56789" — we need just the IP.
func ExtractIP(remoteAddr string) (net.IP, error) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("firewall: cannot parse address %q: %w", remoteAddr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("firewall: invalid IP %q", host)
	}
	return ip, nil
}
