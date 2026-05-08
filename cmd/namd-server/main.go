// namd-server runs on the VPS.
// :9000 — accepts namd clients (developer laptops)
// :8080 — accepts public HTTP traffic from real browsers
//
// Phase 4: reads real HTTP Host headers to route to the right tunnel.
// No more "TARGET gabriel" — real browsers work out of the box.
package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/gabbykarry/namd/internal/transport"
	"github.com/gabbykarry/namd/internal/tunnel"
)

func main() {
	registry := tunnel.NewRegistry()
	go listenForClients(registry)
	listenForPublicTraffic(registry)
}

// ── :9000 — tunnel client listener ───────────────────────────────────────────

func listenForClients(registry *tunnel.Registry) {
	ln, err := net.Listen("tcp", ":9000")
	if err != nil {
		log.Fatalf("[server] cannot listen :9000: %v", err)
	}
	defer ln.Close()
	log.Println("[server] tunnel listener on :9000")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[server] accept error: %v", err)
			return
		}
		go handleClient(conn, registry)
	}
}

func handleClient(conn net.Conn, registry *tunnel.Registry) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("[server] handshake error: %v", err)
		return
	}

	message := strings.TrimSpace(line)
	if !strings.HasPrefix(message, "HELLO ") {
		log.Printf("[server] invalid handshake: %q", message)
		return
	}

	name := strings.TrimPrefix(message, "HELLO ")
	if name == "" {
		return
	}

	session, err := transport.WrapServerSide(name, conn)
	if err != nil {
		log.Printf("[server] yamux setup failed: %v", err)
		return
	}
	defer session.Close()

	ctrlStream, err := session.OpenStream()
	if err != nil {
		log.Printf("[server] control stream failed: %v", err)
		return
	}

	if err := registry.Add(session); err != nil {
		fmt.Fprintf(ctrlStream, "ERROR name %q already taken\n", name)
		ctrlStream.Close()
		return
	}
	defer func() {
		registry.Remove(name)
		log.Printf("[server] tunnel removed for %q", name)
	}()

	fmt.Fprintf(ctrlStream, "OK %s.namd.africa\n", name)
	ctrlStream.Close()
	log.Printf("[server] tunnel registered for %q", name)

	// Block until yamux session dies — client disconnected.
	for {
		_, err := session.AcceptStream()
		if err != nil {
			return
		}
	}
}

// ── :8080 — public HTTP listener ──────────────────────────────────────────────

func listenForPublicTraffic(registry *tunnel.Registry) {
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatalf("[server] cannot listen :8080: %v", err)
	}
	defer ln.Close()
	log.Println("[server] public HTTP listener on :8080")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[server] accept error: %v", err)
			return
		}
		go handlePublicConn(conn, registry)
	}
}

func handlePublicConn(publicConn net.Conn, registry *tunnel.Registry) {
	defer publicConn.Close()

	// ── Parse the HTTP request ────────────────────────────────────────────────
	//
	// bufio.NewReader wraps publicConn for line-by-line reading.
	// http.ReadRequest reads the request line and all headers into *http.Request.
	// It does NOT read the body — body bytes stay buffered in pubReader.
	//
	// *http.Request gives us:
	//   req.Host   = "gabriel.namd.africa"  (the Host header)
	//   req.Method = "GET"
	//   req.URL    = parsed URL
	//   req.Header = all headers as a map
	//
	// We use this only to extract the tunnel name from Host.
	// We do NOT use net/http to write the response — we pipe raw bytes.
	pubReader := bufio.NewReader(publicConn)
	req, err := http.ReadRequest(pubReader)
	if err != nil {
		log.Printf("[server] error parsing HTTP request: %v", err)
		writeHTTPError(publicConn, 400, "Bad Request")
		return
	}

	// ── Extract tunnel name from Host header ──────────────────────────────────
	//
	// Host header arrives as one of:
	//   "gabriel.namd.africa"        → we want "gabriel"
	//   "gabriel.namd.africa:8080"   → port suffix, strip it first
	//   "gabriel"                    → bare name (local testing)
	//
	// strings.Cut(s, sep) splits s at the first occurrence of sep.
	// Returns: before, after, found
	// "gabriel.namd.africa", "8080", true  — if port present
	// "gabriel.namd.africa", "",    false  — if no port
	host := req.Host

	// Strip port if present: "gabriel.namd.africa:8080" → "gabriel.namd.africa"
	if h, _, ok := strings.Cut(host, ":"); ok {
		host = h
	}

	// Extract subdomain: "gabriel.namd.africa" → "gabriel"
	// strings.Cut on "." gives us the first label.
	// If there is no dot (bare name like "gabriel"), use the whole thing.
	name, _, hasDot := strings.Cut(host, ".")
	if !hasDot {
		// bare hostname — treat the whole thing as the tunnel name
		// useful for local testing: curl -H "Host: gabriel" localhost:8080
		name = host
	}

	if name == "" {
		writeHTTPError(publicConn, 400, "Missing Host header")
		return
	}

	log.Printf("[server] HTTP %s %s → tunnel %q", req.Method, req.URL.Path, name)

	// ── Find the tunnel ───────────────────────────────────────────────────────
	session, ok := registry.Get(name)
	if !ok {
		log.Printf("[server] no tunnel for %q", name)
		writeHTTPError(publicConn, 502, fmt.Sprintf(
			"No tunnel found for %q. Is `namd --name %s` running?", name, name,
		))
		return
	}

	// ── Open a yamux stream ───────────────────────────────────────────────────
	stream, err := session.OpenStream()
	if err != nil {
		log.Printf("[server] cannot open stream for %q: %v", name, err)
		writeHTTPError(publicConn, 502, "Tunnel unavailable")
		return
	}
	defer stream.Close()

	// ── Reconstruct and forward the full HTTP request ─────────────────────────
	//
	// http.ReadRequest consumed the headers from pubReader into req.
	// The body bytes (if any) are still buffered in pubReader / publicConn.
	//
	// We must forward the COMPLETE original request to the client:
	//   - Request line:  "GET / HTTP/1.1\r\n"
	//   - All headers:   "Host: gabriel.namd.africa\r\n" etc.
	//   - Body:          any POST/PUT body bytes
	//
	// req.Write(w) serialises the *http.Request back to HTTP wire format
	// and writes it to w. This reconstructs exactly what the browser sent.
	// We write to the yamux stream — the client receives it and forwards
	// it to localhost:3000 as-is.
	//
	// Why req.Write and not just io.MultiReader like before?
	// http.ReadRequest already consumed the headers from the bufio buffer.
	// We cannot "un-read" them. req.Write reconstructs them from the
	// parsed *http.Request struct. The body bytes are still in pubReader
	// — req.Write handles the body too via req.Body (which wraps pubReader).
	if err := req.Write(stream); err != nil {
		log.Printf("[server] error writing request to stream: %v", err)
		return
	}

	// ── Pipe the response back ────────────────────────────────────────────────
	//
	// The client's local app writes an HTTP response into the stream.
	// We copy it back to the browser.
	//
	// We only need one direction now — the request is fully sent via req.Write.
	// The response flows stream → publicConn.
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		n, err := io.Copy(publicConn, stream)
		log.Printf("[server] stream→public %d bytes err=%v", n, err)
	}()

	wg.Wait()
}

// writeHTTPError writes a minimal HTTP error response to conn.
// Used when we cannot route the request — browser sees a proper HTTP error
// instead of a connection reset.
//
// statusText examples: "Bad Request", "Bad Gateway", "Not Found"
func writeHTTPError(conn net.Conn, status int, message string) {
	// We build a minimal valid HTTP/1.0 response.
	// HTTP/1.0 closes the connection after the response — simple and clean.
	// HTTP/1.1 would require Content-Length or chunked encoding.
	body := fmt.Sprintf(`<!DOCTYPE html>
<html>
  <head><title>%d - namd</title></head>
  <body>
    <h2>%d Error</h2>
    <p>%s</p>
    <hr><small>namd tunnel server</small>
  </body>
</html>`, status, status, message)

	response := fmt.Sprintf(
		"HTTP/1.0 %d %s\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s",
		status, http.StatusText(status), len(body), body,
	)
	conn.Write([]byte(response))
}
