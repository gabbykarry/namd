package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gabbykarry/namd/internal/dashboard"
	"github.com/gabbykarry/namd/internal/transport"
)

func main() {
	name := flag.String("name", "", "your tunnel name e.g. gabriel")
	localAddr := flag.String("local", "3000", "local port your app runs on")
	serverAddr := flag.String("server", "localhost:9000", "namd server address")
	dashPort := flag.Int("dash", 5555, "dashboard port")
	flag.Parse()

	if *name == "" {
		log.Fatal("client: --name is required")
	}

	// ── Stats store ───────────────────────────────────────────────────────────
	// One Stats instance shared between the stream handler and the dashboard.
	// Both get a pointer — they read/write the same memory safely via RWMutex.
	stats := dashboard.NewStats()

	// ── Dashboard ─────────────────────────────────────────────────────────────
	// Start dashboard in its own goroutine — runs concurrently with the tunnel.
	// It never stops — lives until the process exits.
	dash := dashboard.NewServer(*dashPort, stats)
	go dash.Start()

	// ── Dial the server ───────────────────────────────────────────────────────
	log.Printf("client: connecting to %s", *serverAddr)
	conn, err := net.Dial("tcp", *serverAddr)
	if err != nil {
		log.Fatalf("client: cannot connect: %v", err)
	}

	// Send HELLO on raw conn before yamux takes over.
	fmt.Fprintf(conn, "HELLO %s\n", *name)

	// ── Wrap in yamux ─────────────────────────────────────────────────────────
	session, err := transport.WrapClientSide(*name, conn)
	if err != nil {
		log.Fatalf("client: yamux setup failed: %v", err)
	}
	defer func() {
		session.Close()
		stats.ClearTunnel()
	}()

	// ── Read control stream ───────────────────────────────────────────────────
	ctrlStream, err := session.AcceptStream()
	if err != nil {
		log.Fatalf("client: cannot accept control stream: %v", err)
	}

	ctrlReader := bufio.NewReader(ctrlStream)
	response, err := ctrlReader.ReadString('\n')
	ctrlStream.Close()
	if err != nil {
		log.Fatalf("client: error reading server response: %v", err)
	}

	response = strings.TrimSpace(response)
	if strings.HasPrefix(response, "ERROR") {
		log.Fatalf("client: server rejected: %s", response)
	}

	publicURL := strings.TrimPrefix(response, "OK ")
	log.Printf("client: ✓ tunnel active → http://%s → localhost:%s", publicURL, *localAddr)
	log.Printf("client: dashboard → http://localhost:%d", *dashPort)

	// Record tunnel as active in stats — dashboard will show it immediately.
	stats.SetTunnel(*name, publicURL)

	local := *localAddr
	if !strings.Contains(local, ":") {
		local = "localhost:" + local
	}

	// ── Stream accept loop ────────────────────────────────────────────────────
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			log.Printf("client: session closed: %v", err)
			return
		}
		go handleStream(stream, local, *name, stats)
	}
}

// handleStream handles one yamux stream — one HTTP request/response cycle.
//
// We use http.ReadRequest and http.ReadResponse to parse both sides cleanly.
// Method, path, and status code are captured without any goroutine races.
// No TeeReader, no shared buffer writes, no CloseWrite type assertions.
func handleStream(stream net.Conn, local, tunnelName string, stats *dashboard.Stats) {
	defer stream.Close()

	start := time.Now()

	// Parse the HTTP request from the stream.
	// http.ReadRequest reads the request line and headers into *http.Request.
	// The body stays buffered in streamReader — not consumed yet.
	// We capture method and path immediately — no goroutine has started yet,
	// so there is zero race on these variables.
	streamReader := bufio.NewReader(stream)
	req, err := http.ReadRequest(streamReader)
	if err != nil {
		log.Printf("client: error reading request from stream: %v", err)
		return
	}

	method := req.Method
	path := req.URL.Path

	// Dial the local app fresh for this request.
	localConn, err := net.Dial("tcp", local)
	if err != nil {
		log.Printf("client: cannot reach %s: %v", local, err)
		stream.Write([]byte("HTTP/1.0 502 Bad Gateway\r\n\r\nLocal app is not running.\n"))
		stats.RecordRequest(dashboard.RequestLog{
			Method:     method,
			Path:       path,
			StatusCode: 502,
			Duration:   time.Since(start),
			Timestamp:  start,
			TunnelName: tunnelName,
		})
		return
	}
	defer localConn.Close()

	// Forward the full HTTP request to the local app.
	// req.Write serialises the parsed request back to HTTP wire format.
	// req.Body wraps streamReader — any POST/PUT body bytes are read lazily
	// from the stream as req.Write serialises them. Nothing is lost.
	if err := req.Write(localConn); err != nil {
		log.Printf("client: error forwarding request to local: %v", err)
		return
	}

	// Read and parse the HTTP response from the local app.
	// http.ReadResponse gives us resp.StatusCode directly — no string parsing needed.
	// resp.Body is lazy — it wraps localReader and reads on demand.
	localReader := bufio.NewReader(localConn)
	resp, err := http.ReadResponse(localReader, req)
	if err != nil {
		log.Printf("client: error reading local response: %v", err)
		stats.RecordRequest(dashboard.RequestLog{
			Method:     method,
			Path:       path,
			StatusCode: 0,
			Duration:   time.Since(start),
			Timestamp:  start,
			TunnelName: tunnelName,
		})
		return
	}

	statusCode := resp.StatusCode

	// Forward the full response back through the stream to the server to the browser.
	// resp.Write serialises status line + headers + body to stream.
	// Body bytes are read lazily from localReader as Write runs.
	if err := resp.Write(stream); err != nil {
		log.Printf("client: error forwarding response to stream: %v", err)
	}
	resp.Body.Close()

	duration := time.Since(start)
	log.Printf("client: %s %s -> %d (%s)", method, path, statusCode, duration.Round(time.Millisecond))

	stats.RecordRequest(dashboard.RequestLog{
		Method:     method,
		Path:       path,
		StatusCode: statusCode,
		Duration:   duration,
		Timestamp:  start,
		TunnelName: tunnelName,
	})
}
