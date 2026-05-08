// namd runs on the developer's laptop.
// Connects to namd-server, registers a tunnel name, then loops
// accepting yamux streams — one goroutine per stream, each dialling
// the local app fresh and piping traffic through.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"

	"github.com/gabbykarry/namd/internal/transport"
)

func main() {
	name := flag.String("name", "", "your tunnel name e.g. gabriel")
	localAddr := flag.String("local", "3000", "local port your app runs on")
	serverAddr := flag.String("server", "localhost:9000", "namd server address")
	flag.Parse()

	if *name == "" {
		log.Fatal("client: --name is required")
	}

	// ── Step 1: dial the server ───────────────────────────────────────────────
	log.Printf("client: connecting to %s", *serverAddr)
	conn, err := net.Dial("tcp", *serverAddr)
	if err != nil {
		log.Fatalf("client: cannot connect: %v", err)
	}

	// ── Step 2: send HELLO before yamux takes over ────────────────────────────
	// We send the handshake on the raw conn before wrapping it in yamux.
	// After WrapClientSide(), yamux owns conn — we cannot write to it directly.
	//
	// Why send before yamux? Because the server reads the HELLO line with
	// a plain bufio reader before it calls WrapServerSide. Both sides must
	// agree on what happens before yamux starts. The handshake is our
	// pre-yamux protocol — just one line, then yamux takes over.
	fmt.Fprintf(conn, "HELLO %s\n", *name)

	// ── Step 3: wrap in yamux ─────────────────────────────────────────────────
	// transport.WrapClientSide creates a yamux SERVER session (accepts streams).
	// From this point, conn belongs to yamux. We use session exclusively.
	session, err := transport.WrapClientSide(*name, conn)
	if err != nil {
		log.Fatalf("client: yamux setup failed: %v", err)
	}
	defer session.Close()

	// ── Step 4: read the control stream ──────────────────────────────────────
	// The server opens a control stream immediately after wrapping in yamux.
	// It sends "OK gabriel.namd.africa\n" or "ERROR ...\n" on that stream.
	// We accept that stream and read the response.
	ctrlStream, err := session.AcceptStream()
	if err != nil {
		log.Fatalf("client: cannot accept control stream: %v", err)
	}

	ctrlReader := bufio.NewReader(ctrlStream)
	response, err := ctrlReader.ReadString('\n')
	ctrlStream.Close() // control stream is done after one line
	if err != nil {
		log.Fatalf("client: error reading server response: %v", err)
	}

	response = strings.TrimSpace(response)
	if strings.HasPrefix(response, "ERROR") {
		log.Fatalf("client: server rejected: %s", response)
	}

	publicURL := strings.TrimPrefix(response, "OK ")
	log.Printf("client: ✓ tunnel active → http://%s → localhost:%s", publicURL, *localAddr)
	log.Println("client: waiting for traffic... (Ctrl+C to stop)")

	local := *localAddr
	if !strings.Contains(local, ":") {
		local = "localhost:" + local
	}

	// ── Step 5: stream accept loop ────────────────────────────────────────────
	// Each time the server receives a public request, it opens a yamux stream.
	// session.AcceptStream() blocks until a stream arrives, then returns it.
	// We handle each stream in its own goroutine — fully concurrent.
	// No FORWARD/READY. No sequential lock. Unlimited parallelism.
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			// yamux session closed — server went away or we disconnected.
			log.Printf("client: session closed: %v", err)
			return
		}

		// Each stream is handled in its own goroutine.
		// The loop immediately calls AcceptStream() again — ready for the next one.
		// While stream 1 is being handled, stream 2 can arrive and start immediately.
		// This is the key concurrency improvement over Phase 2.
		go handleStream(stream, local)
	}
}

// handleStream handles one yamux stream — one public request.
//
// stream — the yamux stream opened by the server for this request
// local  — "localhost:3000" — where to forward the request
//
// This runs in its own goroutine. Concurrent calls never interfere
// because each has its own stream and its own local connection.
func handleStream(stream net.Conn, local string) {
	defer stream.Close()

	// Dial the local app fresh for this request.
	localConn, err := net.Dial("tcp", local)
	if err != nil {
		log.Printf("client: cannot reach local app %s: %v", local, err)
		// Write a minimal HTTP error response back through the stream.
		// The server will forward this to the browser.
		stream.Write([]byte("HTTP/1.0 502 Bad Gateway\r\n\r\nLocal app is not running.\n"))
		return
	}
	defer localConn.Close()

	log.Printf("client: stream → %s", local)

	// Bidirectional pipe — same pattern as Phase 2, now per-stream.
	//   stream → localConn : request bytes into local app
	//   localConn → stream : response bytes back to server → browser
	//
	// Because this runs in a goroutine, multiple of these can run
	// simultaneously. Each has its own stream and localConn — no sharing.
	var wg sync.WaitGroup
	wg.Add(1)

	// local app response → stream → server → browser
	go func() {
		defer wg.Done()
		n, err := io.Copy(stream, localConn)
		log.Printf("client: local→stream %d bytes err=%v", n, err)
	}()

	// stream → local app (request bytes)
	n, err := io.Copy(localConn, stream)
	log.Printf("client: stream→local %d bytes err=%v", n, err)

	wg.Wait()
}
