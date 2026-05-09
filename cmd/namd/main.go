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
	"github.com/gabbykarry/namd/internal/loadbalancer"
	"github.com/gabbykarry/namd/internal/transport"
)

func main() {
	name := flag.String("name", "", "your tunnel name e.g. gabriel")
	localAddr := flag.String("local", "3000", "local port your app runs on")
	serverAddr := flag.String("server", "localhost:9000", "namd server address")
	dashPort := flag.Int("dash", 5555, "dashboard port")
	strategy := flag.String("strategy", "round_robin", "load balancer strategy: round_robin, least_conn, random")
	targets := flag.String("targets", "", "comma-separated target ports e.g. 3000,3001,3002")
	flag.Parse()

	if *name == "" {
		log.Fatal("client: --name is required")
	}

	stats := dashboard.NewStats()
	dash := dashboard.NewServer(*dashPort, stats)
	go dash.Start()

	log.Printf("client: connecting to %s", *serverAddr)
	conn, err := net.Dial("tcp", *serverAddr)
	if err != nil {
		log.Fatalf("client: cannot connect: %v", err)
	}

	fmt.Fprintf(conn, "HELLO %s\n", *name)

	session, err := transport.WrapClientSide(*name, conn)
	if err != nil {
		log.Fatalf("client: yamux setup failed: %v", err)
	}
	defer func() {
		session.Close()
		stats.ClearTunnel()
	}()

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
	log.Printf("client: tunnel active  -> http://%s", publicURL)
	log.Printf("client: dashboard      -> http://localhost:%d", *dashPort)

	stats.SetTunnel(*name, publicURL)

	// ── Load balancer setup ───────────────────────────────────────────────────
	// Build the list of target addresses.
	// If --targets flag is provided, parse it: "3000,3001,3002"
	// Otherwise fall back to the single --local address.
	//
	// loadbalancer.New() returns the right strategy implementation.
	// All strategies satisfy the Balancer interface so handleStream
	// only calls lb.Next() — it never knows which strategy is running.
	var addrs []string
	if *targets != "" {
		for _, t := range strings.Split(*targets, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				addrs = append(addrs, t)
			}
		}
	}
	if len(addrs) == 0 {
		addrs = []string{*localAddr}
	}

	lb, err := loadbalancer.New(*strategy, addrs)
	if err != nil {
		log.Fatalf("client: load balancer error: %v", err)
	}

	log.Printf("client: load balancer  -> strategy=%s targets=%v", *strategy, addrs)

	// ── Stream accept loop ────────────────────────────────────────────────────
	// Each accepted stream is one inbound request.
	// We pass lb so each request picks its own target.
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			log.Printf("client: session closed: %v", err)
			return
		}
		go handleStream(stream, lb, *name, stats)
	}
}

// handleStream handles one yamux stream — one HTTP request/response cycle.
// lb.Next() decides which local backend to dial for this request.
func handleStream(stream net.Conn, lb loadbalancer.Balancer, tunnelName string, stats *dashboard.Stats) {
	defer stream.Close()

	start := time.Now()

	// Parse the HTTP request.
	streamReader := bufio.NewReader(stream)
	req, err := http.ReadRequest(streamReader)
	if err != nil {
		log.Printf("client: error reading request: %v", err)
		return
	}

	method := req.Method
	path := req.URL.Path

	// Ask the load balancer for the next target address.
	// For single-target setups this always returns the same address.
	// For multi-target setups it rotates / picks least conn / picks random.
	addr, err := lb.Next()
	if err != nil {
		log.Printf("client: no healthy targets: %v", err)
		stream.Write([]byte("HTTP/1.0 503 Service Unavailable\r\n\r\nNo healthy backends.\n"))
		stats.RecordRequest(dashboard.RequestLog{
			Method: method, Path: path, StatusCode: 503,
			Duration: time.Since(start), Timestamp: start, TunnelName: tunnelName,
		})
		return
	}

	// Dial the selected target.
	localConn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Printf("client: cannot reach %s: %v", addr, err)
		stream.Write([]byte("HTTP/1.0 502 Bad Gateway\r\n\r\nLocal app is not running.\n"))
		stats.RecordRequest(dashboard.RequestLog{
			Method: method, Path: path, StatusCode: 502,
			Duration: time.Since(start), Timestamp: start, TunnelName: tunnelName,
		})
		return
	}
	defer localConn.Close()

	// Forward request.
	if err := req.Write(localConn); err != nil {
		log.Printf("client: error forwarding request to %s: %v", addr, err)
		return
	}

	// Read and forward response.
	localReader := bufio.NewReader(localConn)
	resp, err := http.ReadResponse(localReader, req)
	if err != nil {
		log.Printf("client: error reading response from %s: %v", addr, err)
		stats.RecordRequest(dashboard.RequestLog{
			Method: method, Path: path, StatusCode: 0,
			Duration: time.Since(start), Timestamp: start, TunnelName: tunnelName,
		})
		return
	}

	statusCode := resp.StatusCode
	if err := resp.Write(stream); err != nil {
		log.Printf("client: error forwarding response: %v", err)
	}
	resp.Body.Close()

	duration := time.Since(start)
	log.Printf("client: %s %s -> %s -> %d (%s)", method, path, addr, statusCode, duration.Round(time.Millisecond))

	stats.RecordRequest(dashboard.RequestLog{
		Method: method, Path: path, StatusCode: statusCode,
		Duration: duration, Timestamp: start, TunnelName: tunnelName,
	})
}
