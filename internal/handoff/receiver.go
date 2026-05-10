package handoff

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Receiver manages the receiver side of a handoff.
// Tunde creates a Receiver when namd gets a HANDOFF_REQUEST from the server.
// He accepts, the server issues a token, and the Receiver runs the sandbox.
type Receiver struct {
	name       string        // "tunde"
	serverAddr string        // namd server address
	secret     string        // server secret for token verification
	sandbox    string        // "docker" or "process"
	maxDur     time.Duration // hard cap — kill sandbox after this
}

// NewReceiver creates a receiver for the given peer.
func NewReceiver(name, serverAddr, secret, sandbox string, maxDur time.Duration) *Receiver {
	return &Receiver{
		name:       name,
		serverAddr: serverAddr,
		secret:     secret,
		sandbox:    sandbox,
		maxDur:     maxDur,
	}
}

// Listen connects to the server's handoff coordination port and waits
// for incoming handoff requests directed at this peer.
//
// When a request arrives, it prompts the user to accept or reject.
// If accepted, it starts the sandbox and holds the session alive.
//
// This runs alongside the normal tunnel session — called in a goroutine
// from cmd/namd/main.go when handoff is enabled in namd.yml.
func (r *Receiver) Listen() {
	controlAddr := strings.Replace(r.serverAddr, ":9000", ":9001", 1)

	log.Printf("[handoff] receiver listening for requests as @%s", r.name)

	for {
		conn, err := net.DialTimeout("tcp", controlAddr, 10*time.Second)
		if err != nil {
			log.Printf("[handoff] receiver: cannot connect to server: %v — retrying in 30s", err)
			time.Sleep(30 * time.Second)
			continue
		}

		// Register as a handoff receiver.
		fmt.Fprintf(conn, "HANDOFF_RECEIVER %s\n", r.name)

		reader := bufio.NewReader(conn)
		resp, err := reader.ReadString('\n')
		if err != nil {
			conn.Close()
			time.Sleep(5 * time.Second)
			continue
		}

		resp = strings.TrimSpace(resp)
		if resp != "RECEIVER_REGISTERED" {
			log.Printf("[handoff] receiver: unexpected response: %q", resp)
			conn.Close()
			continue
		}

		// Wait for a handoff request — blocks until one arrives or conn closes.
		r.waitForRequest(conn, reader)
		conn.Close()
	}
}

// waitForRequest blocks waiting for a HANDOFF_REQUEST message from the server.
// When one arrives, it prompts the user and handles accept/reject.
func (r *Receiver) waitForRequest(conn net.Conn, reader *bufio.Reader) {
	for {
		// Block until server sends something.
		line, err := reader.ReadString('\n')
		if err != nil {
			return // connection closed — outer loop will reconnect
		}

		line = strings.TrimSpace(line)

		// Server sends: "HANDOFF_REQUEST gabriel gabriel.namd.africa 60m <encoded_token>"
		if !strings.HasPrefix(line, "HANDOFF_REQUEST ") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}

		from := parts[1]      // "gabriel"
		subdomain := parts[2] // "gabriel.namd.africa"
		duration := parts[3]  // "60m"
		encodedToken := parts[4]

		// Decode and verify the token.
		token, err := DecodeToken(encodedToken)
		if err != nil {
			log.Printf("[handoff] receiver: invalid token: %v", err)
			fmt.Fprintf(conn, "HANDOFF_REJECT invalid_token\n")
			continue
		}

		if err := token.Verify(r.secret, r.name); err != nil {
			log.Printf("[handoff] receiver: token verification failed: %v", err)
			fmt.Fprintf(conn, "HANDOFF_REJECT verification_failed\n")
			continue
		}

		// Prompt the user.
		fmt.Printf("\n")
		fmt.Printf("╔══════════════════════════════════════════════════╗\n")
		fmt.Printf("║           HANDOFF REQUEST RECEIVED               ║\n")
		fmt.Printf("╠══════════════════════════════════════════════════╣\n")
		fmt.Printf("║  From:     @%-37s║\n", from)
		fmt.Printf("║  Domain:   %-37s║\n", subdomain)
		fmt.Printf("║  Duration: %-37s║\n", duration)
		fmt.Printf("╚══════════════════════════════════════════════════╝\n")
		fmt.Printf("\nAccept handoff? (y/n): ")

		var input string
		fmt.Scanln(&input)
		input = strings.ToLower(strings.TrimSpace(input))

		if input != "y" && input != "yes" {
			fmt.Fprintf(conn, "HANDOFF_REJECT user_declined\n")
			log.Printf("[handoff] rejected handoff from @%s", from)
			continue
		}

		// Accept — send confirmation to server.
		fmt.Fprintf(conn, "HANDOFF_ACCEPT %s\n", token.ID)

		// Start the sandbox.
		log.Printf("[handoff] accepted — starting sandbox for @%s", from)
		log.Printf("[handoff] %s will route here for %s", subdomain, duration)

		if err := r.runSandbox(token); err != nil {
			log.Printf("[handoff] sandbox error: %v", err)
		}

		log.Printf("[handoff] sandbox ended — handoff complete")
	}
}

// runSandbox starts the forwarded server in isolation and blocks until
// it exits or the token expires — whichever comes first.
//
// The sandbox receives tunnel traffic on a local port and forwards it
// to a minimal HTTP process running inside the sandbox environment.
//
// For now we implement the "process" sandbox — runs as a subprocess.
// Docker sandbox is the same but wrapped in: docker run --rm -p ...
func (r *Receiver) runSandbox(token *Token) error {
	// Create a context that cancels when the token expires.
	// context.WithDeadline returns a context and a cancel function.
	// When the deadline passes, ctx.Done() is closed — any operation
	// using this context is cancelled.
	ctx, cancel := context.WithDeadline(context.Background(), token.ExpiresAt)
	defer cancel()

	switch r.sandbox {
	case "docker":
		return r.runDockerSandbox(ctx, token)
	case "process", "":
		return r.runProcessSandbox(ctx, token)
	default:
		return fmt.Errorf("unknown sandbox type: %q", r.sandbox)
	}
}

// runProcessSandbox runs a minimal forwarding proxy as a subprocess.
// This is a lightweight sandbox — no Docker required.
// The subprocess forwards traffic from a local port to a configurable target.
//
// In a full implementation, gabriel would send his server binary or config
// over the tunnel connection and we would run it here.
// For Phase 10 we run a simple static file server as a placeholder.
func (r *Receiver) runProcessSandbox(ctx context.Context, token *Token) error {
	// Use a high port to avoid conflicts — 18080 is arbitrary.
	sandboxPort := "18080"

	log.Printf("[handoff] sandbox: process mode on :%s", sandboxPort)
	log.Printf("[handoff] sandbox: expires at %s (%s remaining)",
		token.ExpiresAt.Format("15:04:05"),
		token.TimeRemaining().Round(time.Minute),
	)

	// Start a simple Python HTTP server as a placeholder sandbox.
	// In the full implementation, gabriel sends his namd.yml config
	// and we start namd itself inside the sandbox pointing at a
	// received binary or Docker image.
	//
	// exec.CommandContext creates a command tied to a context.
	// When ctx is cancelled (token expires), the command is killed.
	// os.Args[0] = the namd binary itself — we reuse it in a special mode.
	//
	// For now: run a simple echo server to prove the sandbox works.
	cmd := exec.CommandContext(ctx,
		"node", "-e",
		fmt.Sprintf(
			`require('http').createServer((req,res)=>{ res.end('Handoff active — served by @%s for @%s\n') }).listen(%s, ()=>console.log('[sandbox] listening on :%s'))`,
			r.name, token.From, sandboxPort, sandboxPort,
		),
	)

	// Connect subprocess stdout/stderr to our output so we see its logs.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("sandbox: cannot start process: %w", err)
	}

	// Wait for the process to exit OR the context to expire.
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		// Process exited on its own.
		return err
	case <-ctx.Done():
		// Token expired — kill the process.
		log.Printf("[handoff] sandbox: token expired — killing sandbox")
		cmd.Process.Kill()
		return fmt.Errorf("handoff expired after %s", r.maxDur)
	}
}

// runDockerSandbox runs the sandbox inside a Docker container.
// Stronger isolation — container cannot access host filesystem or network.
// Requires Docker to be installed on the receiver's machine.
func (r *Receiver) runDockerSandbox(ctx context.Context, token *Token) error {
	sandboxPort := "18080"

	log.Printf("[handoff] sandbox: docker mode")

	// docker run --rm removes the container when it exits.
	// -p 18080:18080 maps the container port to host.
	// --network bridge isolates container networking.
	// node:alpine is a tiny Node.js image.
	cmd := exec.CommandContext(ctx,
		"docker", "run", "--rm",
		"--name", fmt.Sprintf("namd-handoff-%s", token.ID[:8]),
		"-p", sandboxPort+":"+sandboxPort,
		"--network", "bridge",
		"--memory", "256m", // cap memory usage
		"--cpus", "0.5", // cap CPU usage
		"node:alpine",
		"node", "-e",
		fmt.Sprintf(
			`require('http').createServer((req,res)=>res.end('Handoff: @%s hosting for @%s\n')).listen(%s)`,
			r.name, token.From, sandboxPort,
		),
	)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		// Docker might not be installed — fall back to process sandbox.
		log.Printf("[handoff] docker unavailable (%v) — falling back to process sandbox", err)
		return r.runProcessSandbox(ctx, token)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		log.Printf("[handoff] sandbox: docker container killed (token expired)")
		// Docker handles cleanup via --rm flag.
		return nil
	}
}
