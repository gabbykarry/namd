package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"encoding/json"

	"github.com/gabbykarry/namd/internal/auth"
	"github.com/gabbykarry/namd/internal/firewall"
	"github.com/gabbykarry/namd/internal/transport"
	"github.com/gabbykarry/namd/internal/tunnel"
	"github.com/gabbykarry/namd/pkg/logger"
)

func main() {
	registry := tunnel.NewRegistry()
	broker := newHandoffBroker()
	accounts := auth.NewAccountStore()
	fw := firewall.NewEngine(nil) // rules loaded from namd.yml in production
	slog := logger.New("server")

	slog.Info("starting", logger.Fields{
		"tunnel_port":   9000,
		"public_port":   8080,
		"broker_port":   9001,
		"registry_port": 9002,
	})

	go listenForClients(registry, accounts)
	go listenHandoffBroker(broker)
	go listenRegistry(accounts)
	listenForPublicTraffic(registry, fw)
}

// ── :9000 — tunnel client listener ───────────────────────────────────────────

func listenForClients(registry *tunnel.Registry, accounts *auth.AccountStore) {
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
		go handleClient(conn, registry, accounts)
	}
}

func handleClient(conn net.Conn, registry *tunnel.Registry, accounts *auth.AccountStore) {
	defer conn.Close()

	clientIP := conn.RemoteAddr().String()
	slog := logger.New("server")

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("[server] handshake error: %v", err)
		return
	}

	message := strings.TrimSpace(line)

	// New protocol: "HELLO <name> <token>"
	// Old protocol: "HELLO <name>" — rejected for public server
	if !strings.HasPrefix(message, "HELLO ") {
		log.Printf("[server] invalid handshake from %s: %q", clientIP, message)
		return
	}

	parts := strings.Fields(message)
	// parts[0] = "HELLO"
	// parts[1] = name
	// parts[2] = token (required)
	if len(parts) < 3 {
		fmt.Fprintf(conn, "ERROR authentication required — run: namd auth register\n")
		slog.Audit("auth_missing", logger.Fields{"ip": clientIP})
		return
	}

	name := parts[1]
	token := parts[2]

	if name == "" || token == "" {
		fmt.Fprintf(conn, "ERROR name and token are required\n")
		return
	}

	// Verify the token against the account store.
	if err := accounts.Verify(name, token, clientIP); err != nil {
		fmt.Fprintf(conn, "ERROR %s\n", err.Error())
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

	for {
		_, err := session.AcceptStream()
		if err != nil {
			return
		}
	}
}

// ── :8080 — public HTTP listener ──────────────────────────────────────────────

func listenForPublicTraffic(registry *tunnel.Registry, fw *firewall.Engine) {
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
		go handlePublicConn(conn, registry, fw)
	}
}

func handlePublicConn(publicConn net.Conn, registry *tunnel.Registry, fw *firewall.Engine) {
	defer publicConn.Close()

	pubReader := bufio.NewReader(publicConn)
	req, err := http.ReadRequest(pubReader)
	if err != nil {
		log.Printf("[server] HTTP parse error: %v", err)
		writeHTTPError(publicConn, 400, "Bad Request")
		return
	}

	host := req.Host
	if h, _, ok := strings.Cut(host, ":"); ok {
		host = h
	}
	name, _, hasDot := strings.Cut(host, ".")
	if !hasDot {
		name = host
	}
	if name == "" {
		writeHTTPError(publicConn, 400, "Missing or invalid Host header")
		return
	}

	// ── Firewall check ────────────────────────────────────────────────────────
	// Check IP allow/deny rules and rate limits BEFORE touching the tunnel.
	// If blocked: return HTTP error to the client, do not waste tunnel resources.
	if err := fw.Check(name, publicConn.RemoteAddr().String()); err != nil {
		writeHTTPError(publicConn, 403, err.Error())
		return
	}

	log.Printf("[server] HTTP %s %s%s -> tunnel %q", req.Method, req.Host, req.URL.RequestURI(), name)

	session, ok := registry.Get(name)
	if !ok {
		log.Printf("[server] no tunnel for %q", name)
		writeHTTPError(publicConn, 502, fmt.Sprintf(
			"No tunnel found for <code>%s</code>.<br>Is <code>namd --name %s</code> running?",
			host, name,
		))
		return
	}

	stream, err := session.OpenStream()
	if err != nil {
		log.Printf("[server] cannot open stream: %v", err)
		writeHTTPError(publicConn, 502, "Tunnel stream unavailable")
		return
	}
	defer stream.Close()

	req.Header.Set("X-Forwarded-For", publicConn.RemoteAddr().String())
	req.Header.Set("X-Forwarded-Host", req.Host)

	var reqBuf bytes.Buffer
	if err := req.Write(&reqBuf); err != nil {
		log.Printf("[server] request serialisation error: %v", err)
		return
	}

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		n, err := io.Copy(publicConn, stream)
		log.Printf("[server] stream->public %d bytes err=%v", n, err)
	}()

	n, err := io.Copy(stream, &reqBuf)
	log.Printf("[server] public->stream %d bytes err=%v", n, err)

	stream.Close()
	wg.Wait()
}

func writeHTTPError(conn net.Conn, status int, message string) {
	body := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>%d - namd</title></head>
<body style="font-family:sans-serif;max-width:600px;margin:60px auto;padding:20px">
  <h2>%d %s</h2><p>%s</p>
  <hr><small>namd tunnel server</small>
</body>
</html>`, status, status, http.StatusText(status), message)

	fmt.Fprintf(conn,
		"HTTP/1.0 %d %s\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), len(body), body,
	)
}

// ── :9001 — handoff broker ────────────────────────────────────────────────────

// handoffBroker coordinates handoff requests between senders and receivers.
// Receivers register their open connection here.
// When a sender initiates, the broker forwards the request to the receiver,
// waits for acceptance, then confirms back to the sender.
type handoffBroker struct {
	mu        sync.RWMutex
	receivers map[string]net.Conn // @name -> open TCP connection
}

func newHandoffBroker() *handoffBroker {
	return &handoffBroker{
		receivers: make(map[string]net.Conn),
	}
}

func (b *handoffBroker) register(name string, conn net.Conn) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.receivers[name] = conn
	log.Printf("[broker] @%s registered as receiver", name)
}

func (b *handoffBroker) remove(name string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.receivers, name)
	log.Printf("[broker] @%s disconnected", name)
}

func (b *handoffBroker) get(name string) (net.Conn, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	conn, ok := b.receivers[name]
	return conn, ok
}

func listenHandoffBroker(broker *handoffBroker) {
	ln, err := net.Listen("tcp", ":9001")
	if err != nil {
		log.Fatalf("[broker] cannot listen :9001: %v", err)
	}
	defer ln.Close()
	log.Println("[broker] handoff broker on :9001")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[broker] accept error: %v", err)
			return
		}
		go handleBrokerConn(conn, broker)
	}
}

func handleBrokerConn(conn net.Conn, broker *handoffBroker) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	line = strings.TrimSpace(line)

	switch {
	case strings.HasPrefix(line, "HANDOFF_RECEIVER "):
		// Receiver (tunde) registering — keep connection open, wait for requests.
		name := strings.TrimPrefix(line, "HANDOFF_RECEIVER ")
		name = strings.TrimSpace(name)
		broker.register(name, conn)
		defer broker.remove(name)
		fmt.Fprintf(conn, "RECEIVER_REGISTERED\n")
		// Block — hold the connection alive until receiver disconnects.
		// We write handoff requests TO this connection from handleBrokerConn
		// on the sender's goroutine. So we just need to keep it open here.
		io.Copy(io.Discard, reader)

	case strings.HasPrefix(line, "HANDOFF_INIT "):
		// Sender (gabriel) initiating — broker the handoff.
		// Format: HANDOFF_INIT <from> <to> <subdomain> <duration>
		parts := strings.Fields(line)
		if len(parts) < 5 {
			fmt.Fprintf(conn, "ERROR invalid format\n")
			return
		}
		from, to, subdomain, duration := parts[1], parts[2], parts[3], parts[4]
		brokerHandoff(conn, broker, from, to, subdomain, duration)

	case strings.HasPrefix(line, "HANDOFF_CANCEL "):
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			log.Printf("[broker] handoff cancelled by @%s for %s", parts[1], parts[2])
		}
		fmt.Fprintf(conn, "CANCELLED\n")

	default:
		log.Printf("[broker] unknown message: %q", line)
	}
}

// brokerHandoff is the core coordination logic.
// Runs on the sender's goroutine. Communicates with the receiver's
// goroutine via the receiver's stored net.Conn.
func brokerHandoff(senderConn net.Conn, broker *handoffBroker, from, to, subdomain, duration string) {
	log.Printf("[broker] handoff request: @%s -> @%s (%s for %s)", from, to, subdomain, duration)

	// Find the receiver.
	receiverConn, ok := broker.get(to)
	if !ok {
		fmt.Fprintf(senderConn, "PEER_OFFLINE\n")
		log.Printf("[broker] @%s is offline", to)
		return
	}

	// Build a simple token ID — in production use handoff.NewToken().
	// We keep it simple here to avoid the circular import issue
	// (server importing internal/handoff which would import internal/tunnel etc).
	// The full signed token lives in internal/handoff/token.go — the client
	// uses it. The server just brokers the ID.
	tokenID := fmt.Sprintf("hoff-%s-%s-%d", from, to, time.Now().Unix())

	// Forward the request to the receiver's connection.
	// The receiver's goroutine is blocking on io.Copy(io.Discard, reader).
	// Writing to receiverConn interrupts that — the receiver's namd client
	// reads this line in its waitForRequest loop.
	_, err := fmt.Fprintf(receiverConn, "HANDOFF_REQUEST %s %s %s %s\n",
		from, subdomain, duration, tokenID)
	if err != nil {
		fmt.Fprintf(senderConn, "ERROR cannot reach receiver: %v\n", err)
		return
	}

	log.Printf("[broker] forwarded request to @%s — waiting for response", to)

	// Wait for receiver's response — HANDOFF_ACCEPT or HANDOFF_REJECT.
	// 5 minute timeout — if receiver ignores it, we cancel.
	//
	// time.After(d) returns a channel that receives after duration d.
	// We use it in a select alongside the response channel.
	// Whichever fires first wins.
	respCh := make(chan string, 1)
	go func() {
		recv := bufio.NewReader(receiverConn)
		line, err := recv.ReadString('\n')
		if err != nil {
			respCh <- "ERROR"
			return
		}
		respCh <- strings.TrimSpace(line)
	}()

	select {
	case resp := <-respCh:
		if strings.HasPrefix(resp, "HANDOFF_ACCEPT") {
			fmt.Fprintf(senderConn, "CONFIRMED %s\n", tokenID)
			log.Printf("[broker] handoff confirmed — @%s -> @%s token=%s", from, to, tokenID)
		} else {
			reason := strings.TrimPrefix(resp, "HANDOFF_REJECT ")
			fmt.Fprintf(senderConn, "REJECTED %s\n", reason)
			log.Printf("[broker] handoff rejected by @%s: %s", to, reason)
		}

	case <-time.After(5 * time.Minute):
		fmt.Fprintf(senderConn, "ERROR receiver did not respond in 5 minutes\n")
		log.Printf("[broker] handoff timed out waiting for @%s", to)
	}
}

// ── :9002 — registration and peer lookup ─────────────────────────────────────

// listenRegistry handles two things on :9002:
//  1. New account registration: client sends RegisterRequest JSON
//  2. Peer lookup: handoff sender asks if a peer exists and is online
func listenRegistry(accounts *auth.AccountStore) {
	ln, err := net.Listen("tcp", ":9002")
	if err != nil {
		log.Fatalf("[registry] cannot listen :9002: %v", err)
	}
	defer ln.Close()
	log.Println("[registry] registration/lookup on :9002")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[registry] accept error: %v", err)
			return
		}
		go handleRegistryConn(conn, accounts)
	}
}

func handleRegistryConn(conn net.Conn, accounts *auth.AccountStore) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	line = strings.TrimSpace(line)

	// Peer lookup request from handoff sender.
	// "PEER_LOOKUP tunde"
	if strings.HasPrefix(line, "PEER_LOOKUP ") {
		name := strings.TrimPrefix(line, "PEER_LOOKUP ")
		// For now: account exists = found. Online check via tunnel registry
		// would require passing the tunnel registry here too — Phase 13 addition.
		// Simple response for now: PEER_FOUND <name> online/offline
		fmt.Fprintf(conn, "PEER_FOUND %s online\n", name)
		return
	}

	// Registration request — JSON body.
	// {"name":"gabriel","email":"...","token":"..."}
	var req auth.RegisterRequest
	if err := parseJSON(line, &req); err != nil {
		resp := auth.RegisterResponse{Success: false, Message: "invalid request format"}
		writeJSON(conn, resp)
		return
	}

	if req.Name == "" || req.Token == "" {
		resp := auth.RegisterResponse{Success: false, Message: "name and token are required"}
		writeJSON(conn, resp)
		return
	}

	if err := accounts.Register(req.Name, req.Email, req.Token); err != nil {
		resp := auth.RegisterResponse{Success: false, Message: err.Error()}
		writeJSON(conn, resp)
		return
	}

	log.Printf("[registry] registered @%s", req.Name)
	resp := auth.RegisterResponse{Success: true, Name: req.Name, Message: "registered successfully"}
	writeJSON(conn, resp)
}

func parseJSON(line string, v interface{}) error {
	return json.Unmarshal([]byte(line), v)
}

func writeJSON(conn net.Conn, v interface{}) {
	data, err := json.Marshal(v)
	if err != nil {
		fmt.Fprintf(conn, `{"success":false,"message":"internal error"}`)
		return
	}
	fmt.Fprintf(conn, "%s\n", string(data))
}
