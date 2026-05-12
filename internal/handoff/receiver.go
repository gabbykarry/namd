package handoff

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

// Receiver manages the receiver side of a handoff.
type Receiver struct {
	name       string
	serverAddr string
	secret     string
	sandbox    string
	maxDur     time.Duration
}

func NewReceiver(name, serverAddr, secret, sandbox string, maxDur time.Duration) *Receiver {
	return &Receiver{
		name:       name,
		serverAddr: serverAddr,
		secret:     secret,
		sandbox:    sandbox,
		maxDur:     maxDur,
	}
}

// Listen connects to the broker and waits for incoming handoff requests.
func (r *Receiver) Listen() {
	controlAddr := strings.Replace(r.serverAddr, ":9000", ":9001", 1)
	controlAddr = strings.Replace(controlAddr, "tunnel.namd.online", "broker.namd.online", 1)
	if strings.Contains(controlAddr, "namd.online") && !strings.Contains(controlAddr, "broker.") {
		controlAddr = strings.Replace(controlAddr, "namd.online", "broker.namd.online", 1)
	}

	log.Printf("[handoff] receiver listening for requests as @%s", r.name)

	for {
		conn, err := net.DialTimeout("tcp", controlAddr, 10*time.Second)
		if err != nil {
			log.Printf("[handoff] receiver: cannot connect to server: %v — retrying in 30s", err)
			time.Sleep(30 * time.Second)
			continue
		}

		fmt.Fprintf(conn, "HANDOFF_RECEIVER %s\n", r.name)

		reader := bufio.NewReader(conn)
		resp, err := reader.ReadString('\n')
		if err != nil {
			conn.Close()
			time.Sleep(5 * time.Second)
			continue
		}

		if strings.TrimSpace(resp) != "RECEIVER_REGISTERED" {
			conn.Close()
			continue
		}

		r.waitForRequest(conn, reader)
		conn.Close()
	}
}

func (r *Receiver) waitForRequest(conn net.Conn, reader *bufio.Reader) {
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "HANDOFF_REQUEST ") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}

		from := parts[1]
		subdomain := parts[2]
		duration := parts[3]
		encodedToken := parts[4]

		token := &Token{
			ID:        encodedToken,
			From:      from,
			To:        r.name,
			Subdomain: subdomain,
			ExpiresAt: time.Now().Add(r.maxDur),
		}

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

		log.Printf("[handoff] accepted — starting sandbox for @%s", from)
		log.Printf("[handoff] %s will route here for %s", subdomain, duration)

		sandboxAddr := "localhost:18080"
		fmt.Fprintf(conn, "HANDOFF_ACCEPT %s %s\n", token.ID, sandboxAddr)

		if err := r.runSandbox(token); err != nil {
			log.Printf("[handoff] sandbox error: %v", err)
		}

		log.Printf("[handoff] sandbox ended — handoff complete")
	}
}

func (r *Receiver) runSandbox(token *Token) error {
	ctx, cancel := context.WithDeadline(context.Background(), token.ExpiresAt)
	defer cancel()

	switch r.sandbox {
	case "docker":
		return r.runDockerSandbox(ctx, token)
	default:
		return r.runProcessSandbox(ctx, token)
	}
}

func (r *Receiver) runProcessSandbox(ctx context.Context, token *Token) error {
	sandboxPort := "18080"

	log.Printf("[handoff] sandbox: process mode on :%s", sandboxPort)
	log.Printf("[handoff] sandbox: expires at %s (%s remaining)",
		token.ExpiresAt.Format("15:04:05"),
		token.TimeRemaining().Round(time.Minute),
	)

	alreadyRunning := isPortInUse(sandboxPort)

	var cmd *exec.Cmd

	if alreadyRunning {
		log.Printf("[handoff] sandbox: port :%s already in use — using existing server", sandboxPort)
	} else {
		log.Printf("[handoff] sandbox: nothing on :%s — starting placeholder", sandboxPort)
		cmd = exec.CommandContext(ctx,
			"node", "-e",
			fmt.Sprintf(
				`require('http').createServer((req,res)=>{ res.end('Handoff active — served by @%s for @%s\n') }).listen(%s, ()=>console.log('[sandbox] listening on :%s'))`,
				r.name, token.From, sandboxPort, sandboxPort,
			),
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("sandbox: cannot start placeholder: %w", err)
		}
		time.Sleep(500 * time.Millisecond)
	}

	go r.openHandoffTunnel(ctx, token, sandboxPort)

	if cmd != nil {
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			return err
		case <-ctx.Done():
			log.Printf("[handoff] sandbox: token expired — killing placeholder")
			cmd.Process.Kill()
			return fmt.Errorf("handoff expired after %s", r.maxDur)
		}
	} else {
		<-ctx.Done()
		return fmt.Errorf("handoff expired after %s", r.maxDur)
	}
}

func isPortInUse(port string) bool {
	conn, err := net.DialTimeout("tcp", "localhost:"+port, 200*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (r *Receiver) openHandoffTunnel(ctx context.Context, token *Token, sandboxPort string) {
	homedir, _ := os.UserHomeDir()
	credsData, err := os.ReadFile(filepath.Join(homedir, ".namd", "credentials"))
	if err != nil {
		log.Printf("[handoff] cannot read credentials: %v", err)
		return
	}

	var creds struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(credsData, &creds); err != nil || creds.Token == "" {
		log.Printf("[handoff] cannot parse credentials: %v", err)
		return
	}

	log.Printf("[handoff] opening tunnel under @%s via %s", token.From, r.serverAddr)

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp", r.serverAddr, tlsCfg,
	)
	if err != nil {
		log.Printf("[handoff] cannot connect to server: %v", err)
		return
	}
	defer conn.Close()

	fmt.Fprintf(conn, "HANDOFF_TUNNEL %s %s %s\n", token.From, creds.Token, token.ID)

	reader := bufio.NewReader(conn)
	resp, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(resp) != "AUTH_OK" {
		log.Printf("[handoff] tunnel auth failed: err=%v resp=%q", err, resp)
		return
	}

	log.Printf("[handoff] tunnel auth ok — setting up yamux")

	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	session, err := yamux.Client(conn, cfg)
	if err != nil {
		log.Printf("[handoff] yamux failed: %v", err)
		return
	}
	defer session.Close()

	// Accept and discard the control stream OK message from server.
	ctrl, err := session.Accept()
	if err != nil {
		log.Printf("[handoff] control stream failed: %v", err)
		return
	}
	io.Copy(io.Discard, ctrl)
	ctrl.Close()

	log.Printf("[handoff] tunnel open — %s.namd.online → localhost:%s", token.From, sandboxPort)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		stream, err := session.Accept()
		if err != nil {
			return
		}

		go func(s net.Conn) {
			defer s.Close()
			sandboxConn, err := net.Dial("tcp", "localhost:"+sandboxPort)
			if err != nil {
				return
			}
			defer sandboxConn.Close()
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); io.Copy(sandboxConn, s) }()
			go func() { defer wg.Done(); io.Copy(s, sandboxConn) }()
			wg.Wait()
		}(stream)
	}
}

func (r *Receiver) runDockerSandbox(ctx context.Context, token *Token) error {
	sandboxPort := "18080"
	cmd := exec.CommandContext(ctx,
		"docker", "run", "--rm",
		"--name", fmt.Sprintf("namd-handoff-%s", token.ID[:8]),
		"-p", sandboxPort+":"+sandboxPort,
		"--network", "bridge",
		"--memory", "256m",
		"--cpus", "0.5",
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
		log.Printf("[handoff] docker unavailable — falling back to process sandbox")
		return r.runProcessSandbox(ctx, token)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return nil
	}
}
