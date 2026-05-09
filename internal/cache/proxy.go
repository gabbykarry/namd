package cache

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Proxy is a local HTTP proxy server.
// Your app points HTTP_PROXY at it — all outgoing HTTP requests flow through.
// Requests matching configured target URLs are cached.
// All other requests are forwarded transparently.
//
// Listens on :7777 by default.
type Proxy struct {
	store   *Store
	targets []string // base URLs to cache e.g. "https://api.paystack.co"
	port    int
}

// NewProxy creates a cache proxy.
// targets — list of base URLs to cache (from namd.yml cache.targets)
// ttl     — how long responses stay fresh (from namd.yml cache.ttl)
// port    — port to listen on (default 7777)
func NewProxy(targets []string, ttl time.Duration, port int) *Proxy {
	if port == 0 {
		port = 7777
	}
	return &Proxy{
		store:   NewStore(ttl),
		targets: targets,
		port:    port,
	}
}

// Start launches the proxy HTTP server.
// Run in a goroutine: go proxy.Start()
func (p *Proxy) Start() {
	addr := fmt.Sprintf(":%d", p.port)
	log.Printf("[cache] proxy listening on http://localhost%s", addr)
	log.Printf("[cache] set HTTP_PROXY=http://localhost%s in your app", addr)

	// http.ListenAndServe with p as the handler.
	// p implements http.Handler via the ServeHTTP method below.
	if err := http.ListenAndServe(addr, p); err != nil {
		log.Fatalf("[cache] proxy error: %v", err)
	}
}

// ServeHTTP is called for every HTTP request that hits the proxy.
// This makes *Proxy satisfy the http.Handler interface.
//
// Two types of requests arrive at an HTTP proxy:
//
//  1. Regular HTTP requests: "GET http://api.paystack.co/transaction HTTP/1.1"
//     The full URL is in the request line — we forward these directly.
//
//  2. CONNECT requests: "CONNECT api.paystack.co:443 HTTP/1.1"
//     Used for HTTPS tunnelling — browser asks proxy to open a raw TCP
//     connection to the target, then speaks TLS through it.
//     We handle these by opening the TCP connection and piping both ways.
//
// For cached targets: we intercept and cache.
// For other targets: we forward transparently (passthrough proxy).
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleCONNECT(w, r)
		return
	}
	p.handleHTTP(w, r)
}

// handleHTTP handles regular HTTP (non-HTTPS) proxy requests.
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.String()

	// Should we cache this request?
	if p.shouldCache(targetURL) {
		p.serveWithCache(w, r, targetURL)
		return
	}

	// Not a cached target — forward transparently.
	p.forward(w, r)
}

// shouldCache returns true if this URL matches one of our configured targets.
// We match by checking if the request URL starts with any target base URL.
//
// Example:
//
//	target: "https://api.paystack.co"
//	request: "https://api.paystack.co/transaction/verify/abc123"
//	→ matches ✓
func (p *Proxy) shouldCache(requestURL string) bool {
	for _, target := range p.targets {
		if strings.HasPrefix(requestURL, target) {
			return true
		}
	}
	return false
}

// serveWithCache checks the cache first, forwards if miss, caches the response.
func (p *Proxy) serveWithCache(w http.ResponseWriter, r *http.Request, targetURL string) {
	key := cacheKey(r)

	// ── Cache HIT ─────────────────────────────────────────────────────────────
	if entry, ok := p.store.Get(key); ok {
		log.Printf("[cache] HIT  %s %s", r.Method, targetURL)

		// Write the raw cached response bytes directly to the connection.
		// The bytes are a complete HTTP response — status, headers, body.
		// We use http.Hijacker to get the raw TCP connection so we can
		// write raw bytes instead of going through the http.ResponseWriter API.
		//
		// http.Hijacker is an interface that net/http connections implement.
		// Hijack() gives us the raw net.Conn — we take full control.
		// After Hijack(), the http package no longer manages this connection.
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			// Fallback: ResponseWriter does not support Hijack.
			// This happens in tests or with some middleware.
			// Write headers manually and serve the body.
			w.Header().Set("X-Namd-Cache", "HIT")
			w.Header().Set("X-Namd-Cached-At", entry.CachedAt.Format(time.RFC3339))
			w.WriteHeader(200)
			w.Write(entry.Body)
			return
		}

		conn, _, err := hijacker.Hijack()
		if err != nil {
			log.Printf("[cache] hijack error: %v", err)
			return
		}
		defer conn.Close()

		// Write raw cached response bytes to the connection.
		conn.Write(entry.Body)
		return
	}

	// ── Cache MISS ────────────────────────────────────────────────────────────
	log.Printf("[cache] MISS %s %s", r.Method, targetURL)

	// Forward the request to the real server and capture the response.
	resp, err := forwardRequest(r)
	if err != nil {
		log.Printf("[cache] forward error (offline?): %v", err)

		// Internet is down — serve an offline error response.
		// In a future version, we could serve a stale cache entry here
		// (cache-when-offline strategy) even if the TTL has expired.
		http.Error(w, "namd cache: upstream unreachable — no cached response available", 503)
		return
	}
	defer resp.Body.Close()

	// Read the full response body.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[cache] error reading response body: %v", err)
		http.Error(w, "cache: error reading upstream response", 500)
		return
	}

	// Serialise the full HTTP response to raw bytes for caching.
	// We store the complete response — status, headers, body — so we can
	// replay it byte-for-byte when serving from cache later.
	var rawResponse bytes.Buffer
	resp.Body = io.NopCloser(bytes.NewReader(body)) // restore body for Write
	resp.Write(&rawResponse)

	// Only cache successful responses (2xx).
	// We do not cache 404, 500 etc — these might change.
	// We do not cache POST/PUT/DELETE — these are not idempotent.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && r.Method == http.MethodGet {
		p.store.Set(key, targetURL, rawResponse.Bytes())
		log.Printf("[cache] stored %s %s (%d bytes)", r.Method, targetURL, rawResponse.Len())
	}

	// Forward the response to the caller.
	// Copy status code and headers first, then body.
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.Header().Set("X-Namd-Cache", "MISS")
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

// handleCONNECT handles HTTPS CONNECT tunnelling.
//
// When your app makes an HTTPS request through an HTTP proxy, it first sends:
//
//	CONNECT api.paystack.co:443 HTTP/1.1
//
// The proxy opens a raw TCP connection to api.paystack.co:443,
// responds with "200 Connection established", then pipes bytes
// both ways. The app then speaks TLS directly through that pipe.
//
// We cannot cache HTTPS requests here — the traffic is encrypted.
// TLS termination would require a MITM certificate. We just tunnel.
// The cache is most useful for HTTP APIs in development (port 80 or custom).
func (p *Proxy) handleCONNECT(w http.ResponseWriter, r *http.Request) {
	// Dial the target directly.
	targetConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, "cannot connect to target: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// Hijack the client connection.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "hijack failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Tell the client the tunnel is established.
	clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))

	// Pipe bytes both ways — client ↔ target.
	// Both directions run concurrently.
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(targetConn, clientConn)
		done <- struct{}{}
	}()

	go func() {
		io.Copy(clientConn, targetConn)
		done <- struct{}{}
	}()

	// Wait for either direction to finish.
	// When one side closes, the other will too.
	<-done
}

// forward sends a request to the real upstream server and returns the response.
// Used for non-cached targets and for cache misses.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request) {
	resp, err := forwardRequest(r)
	if err != nil {
		http.Error(w, "proxy error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// forwardRequest makes the actual outbound HTTP request to the upstream server.
// Shared between cache miss handling and transparent forwarding.
func forwardRequest(r *http.Request) (*http.Response, error) {
	// Build a new request — we cannot reuse r directly because
	// r is the proxy request (has proxy-specific headers and RequestURI).
	outReq, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}

	// Copy headers from the original request.
	// Skip "Proxy-Connection" — that is a proxy-to-proxy header, not for the server.
	for key, values := range r.Header {
		if strings.EqualFold(key, "Proxy-Connection") {
			continue
		}
		for _, v := range values {
			outReq.Header.Add(key, v)
		}
	}

	// Use a client with a reasonable timeout.
	client := &http.Client{
		Timeout: 30 * time.Second,
		// Do NOT follow redirects automatically — let the caller handle them.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return client.Do(outReq)
}

// cacheKey builds a unique string key for a request.
// We hash the method + URL so the key is compact and safe for use as a map key.
//
// SHA256 of "GET:https://api.paystack.co/transaction/verify/abc123"
// → "a3f2c891..."
//
// Why hash? The URL can be very long (query params, path segments).
// A hash is always 64 hex characters — consistent map key size.
func cacheKey(r *http.Request) string {
	raw := r.Method + ":" + r.URL.String()
	hash := sha256.Sum256([]byte(raw))
	// fmt.Sprintf("%x", hash) formats bytes as lowercase hex.
	// hash[:8] takes the first 8 bytes (16 hex chars) — short enough for a key,
	// collision probability is negligible for a dev cache.
	return fmt.Sprintf("%x", hash[:16])
}

// IsTargetURL checks if a URL matches any configured cache target.
// Exported so the dashboard can display which URLs are being cached.
func (p *Proxy) IsTargetURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	base := u.Scheme + "://" + u.Host
	for _, target := range p.targets {
		if strings.HasPrefix(base, target) {
			return true
		}
	}
	return false
}

// CacheStats returns cache hit/miss stats for the dashboard.
func (p *Proxy) CacheStats() (total, expired int) {
	return p.store.Stats()
}
