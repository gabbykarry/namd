package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gabbykarry/namd/internal/auth"
	"github.com/gabbykarry/namd/internal/cache"
	"github.com/gabbykarry/namd/internal/config"
	"github.com/gabbykarry/namd/internal/dashboard"
	"github.com/gabbykarry/namd/internal/handoff"
	"github.com/gabbykarry/namd/internal/loadbalancer"
	"github.com/gabbykarry/namd/internal/transport"
	"github.com/gabbykarry/namd/internal/webhook"
	"github.com/gabbykarry/namd/internal/webhook/adapters"
	"github.com/gabbykarry/namd/pkg/version"
	"github.com/spf13/cobra"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "namd",
		Short: "namd - open source tunnel for African developers",
	}

	var configPath string

	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Start the tunnel using namd.yml",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStart(configPath)
		},
	}
	startCmd.Flags().StringVarP(&configPath, "config", "c", "namd.yml", "path to namd.yml")

	var webhookConfigPath string
	webhookCmd := &cobra.Command{Use: "webhook", Short: "Manage webhook events"}
	replayCmd := &cobra.Command{
		Use:   "replay [relay-name]",
		Short: "Replay stored webhook events",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWebhookReplay(webhookConfigPath, args[0])
		},
	}
	replayCmd.Flags().StringVarP(&webhookConfigPath, "config", "c", "namd.yml", "config file")
	webhookCmd.AddCommand(replayCmd)

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(version.String())
		},
	}

	// namd auth register / namd auth status
	authCmd := &cobra.Command{Use: "auth", Short: "Manage your namd identity"}

	var (
		authName   string
		authEmail  string
		authServer string
	)

	registerCmd := &cobra.Command{
		Use:   "register",
		Short: "Register a new account on the namd server",
		Long: `Create your namd identity.
Run this once before namd start.

Example:
  namd auth register --name gabriel --email gabriel@example.com`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAuthRegister(authName, authEmail, authServer)
		},
	}
	registerCmd.Flags().StringVar(&authName, "name", "", "your handle e.g. gabriel")
	registerCmd.Flags().StringVar(&authEmail, "email", "", "your email (for recovery)")
	registerCmd.Flags().StringVar(&authServer, "server", "localhost:9000", "namd server address")
	registerCmd.MarkFlagRequired("name")

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show current registration status",
		Run: func(cmd *cobra.Command, args []string) {
			creds, err := auth.LoadCredentials()
			if err != nil {
				fmt.Println("Not registered. Run: namd auth register --name yourname")
				return
			}
			fmt.Printf("Registered as @%s on %s\n", creds.Name, creds.ServerURL)
			fmt.Printf("Token issued: %s\n", creds.IssuedAt.Format("2006-01-02"))
		},
	}

	authCmd.AddCommand(registerCmd, statusCmd)
	rootCmd.AddCommand(startCmd, webhookCmd, versionCmd, authCmd)

	// namd handoff @tunde
	var handoffConfig string
	handoffCmd := &cobra.Command{
		Use:   "handoff [@peer]",
		Short: "Hand off your tunnel to a trusted peer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runHandoff(handoffConfig, args[0])
		},
	}
	handoffCmd.Flags().StringVarP(&handoffConfig, "config", "c", "namd.yml", "config file")

	cancelCmd := &cobra.Command{
		Use:   "cancel",
		Short: "Cancel an active handoff",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runHandoffCancel(handoffConfig)
		},
	}
	handoffCmd.AddCommand(cancelCmd)

	acceptCmd := &cobra.Command{
		Use:   "accept",
		Short: "Accept incoming handoff requests",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAccept(handoffConfig)
		},
	}
	acceptCmd.Flags().StringVarP(&handoffConfig, "config", "c", "namd.yml", "config file")

	rootCmd.AddCommand(handoffCmd, acceptCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runStart(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	log.Printf("[namd] loaded %s", configPath)
	log.Printf("[namd] identity: @%s", cfg.Identity.Name)

	stats := dashboard.NewStats()
	if cfg.Dashboard.Enabled {
		dash := dashboard.NewServer(cfg.Dashboard.Port, stats)
		go dash.Start()
	}

	lb, localURL, err := buildLoadBalancer(cfg)
	if err != nil {
		return fmt.Errorf("load balancer: %w", err)
	}

	var webhookEngine *webhook.Engine
	if len(cfg.Webhooks.Relay) > 0 {
		webhookEngine, err = buildWebhookEngine(cfg, localURL)
		if err != nil {
			log.Printf("[namd] webhook engine warning: %v", err)
		} else {
			log.Printf("[namd] webhook relay: %d relay(s) configured", len(cfg.Webhooks.Relay))
		}
	}

	// ── Offline cache proxy ───────────────────────────────────────────────────
	// If cache is enabled in namd.yml, start a local HTTP proxy on :7777.
	// The developer sets HTTP_PROXY=http://localhost:7777 in their app.
	// All outgoing requests to configured targets are cached locally.
	if cfg.Cache.Enabled && len(cfg.Cache.Targets) > 0 {
		ttl, err := time.ParseDuration(cfg.Cache.TTL)
		if err != nil {
			ttl = 5 * time.Minute // default if TTL is invalid
		}
		cacheProxy := cache.NewProxy(cfg.Cache.Targets, ttl, 7777)
		go cacheProxy.Start()
		log.Printf("[namd] cache proxy: %d target(s) cached for %s", len(cfg.Cache.Targets), ttl)
	}

	// ── Load credentials ────────────────────────────────────────────────────
	// Every connection to the server requires a valid token.
	// If not registered yet: namd auth register --name gabriel
	creds, err := auth.LoadAndVerifyCredentials()
	if err != nil {
		return fmt.Errorf("%w\n\nRun: namd auth register --name %s --server %s",
			err, cfg.Identity.Name, resolveServerAddr(cfg))
	}

	serverAddr := resolveServerAddr(cfg)
	log.Printf("[namd] connecting to %s as @%s", serverAddr, creds.Name)

	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		return fmt.Errorf("cannot connect to %s: %w", serverAddr, err)
	}

	// Send HELLO with token — server verifies before registering tunnel.
	fmt.Fprintf(conn, "HELLO %s %s\n", creds.Name, creds.Token)

	session, err := transport.WrapClientSide(cfg.Identity.Name, conn)
	if err != nil {
		return fmt.Errorf("yamux setup: %w", err)
	}
	defer func() {
		session.Close()
		stats.ClearTunnel()
	}()

	ctrlStream, err := session.AcceptStream()
	if err != nil {
		return fmt.Errorf("control stream: %w", err)
	}

	ctrlReader := bufio.NewReader(ctrlStream)
	response, err := ctrlReader.ReadString('\n')
	ctrlStream.Close()
	if err != nil {
		return fmt.Errorf("reading server response: %w", err)
	}

	response = strings.TrimSpace(response)
	if strings.HasPrefix(response, "ERROR") {
		return fmt.Errorf("server rejected: %s", response)
	}

	publicURL := strings.TrimPrefix(response, "OK ")
	log.Printf("[namd] tunnel active  -> http://%s", publicURL)
	if cfg.Dashboard.Enabled {
		log.Printf("[namd] dashboard      -> http://localhost:%d", cfg.Dashboard.Port)
	}
	log.Printf("[namd] forwarding to  -> %s", localURL)

	stats.SetTunnel(cfg.Identity.Name, publicURL)

	for {
		stream, err := session.AcceptStream()
		if err != nil {
			log.Printf("[namd] session closed: %v", err)
			return nil
		}
		go handleStream(stream, lb, cfg.Identity.Name, stats, webhookEngine)
	}
}

func runWebhookReplay(configPath, relayName string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}
	localURL, err := firstTunnelURL(cfg)
	if err != nil {
		return err
	}
	engine, err := buildWebhookEngine(cfg, localURL)
	if err != nil {
		return fmt.Errorf("webhook engine: %w", err)
	}
	return engine.Replay(relayName)
}

func handleStream(
	stream net.Conn,
	lb loadbalancer.Balancer,
	tunnelName string,
	stats *dashboard.Stats,
	webhookEngine *webhook.Engine,
) {
	defer stream.Close()

	start := time.Now()
	streamReader := bufio.NewReader(stream)
	req, err := http.ReadRequest(streamReader)
	if err != nil {
		log.Printf("[namd] error reading request: %v", err)
		return
	}

	method := req.Method
	path := req.URL.Path

	// Webhook relay check — does this path match a relay rule?
	if webhookEngine != nil {
		if relay, matched := webhookEngine.Match(path); matched {
			log.Printf("[namd] webhook: %s %s -> relay %q", method, path, relay.Name)
			w := newStreamResponseWriter(stream)
			webhookEngine.Handle(w, req, relay)
			stats.RecordRequest(dashboard.RequestLog{
				Method: method, Path: path, StatusCode: w.statusCode,
				Duration: time.Since(start), Timestamp: start, TunnelName: tunnelName,
			})
			return
		}
	}

	// Normal forwarding via load balancer.
	addr, err := lb.Next()
	if err != nil {
		stream.Write([]byte("HTTP/1.0 503 Service Unavailable\r\n\r\nNo healthy backends.\n"))
		stats.RecordRequest(dashboard.RequestLog{
			Method: method, Path: path, StatusCode: 503,
			Duration: time.Since(start), Timestamp: start, TunnelName: tunnelName,
		})
		return
	}

	localConn, err := net.Dial("tcp", addr)
	if err != nil {
		stream.Write([]byte("HTTP/1.0 502 Bad Gateway\r\n\r\nLocal app is not running.\n"))
		stats.RecordRequest(dashboard.RequestLog{
			Method: method, Path: path, StatusCode: 502,
			Duration: time.Since(start), Timestamp: start, TunnelName: tunnelName,
		})
		return
	}
	defer localConn.Close()

	if err := req.Write(localConn); err != nil {
		return
	}

	localReader := bufio.NewReader(localConn)
	resp, err := http.ReadResponse(localReader, req)
	if err != nil {
		stats.RecordRequest(dashboard.RequestLog{
			Method: method, Path: path, StatusCode: 0,
			Duration: time.Since(start), Timestamp: start, TunnelName: tunnelName,
		})
		return
	}

	statusCode := resp.StatusCode
	resp.Write(stream)
	resp.Body.Close()

	duration := time.Since(start)
	log.Printf("[namd] %s %s -> %s -> %d (%s)", method, path, addr, statusCode, duration.Round(time.Millisecond))

	stats.RecordRequest(dashboard.RequestLog{
		Method: method, Path: path, StatusCode: statusCode,
		Duration: duration, Timestamp: start, TunnelName: tunnelName,
	})
}

func buildLoadBalancer(cfg *config.Config) (loadbalancer.Balancer, string, error) {
	var firstName string
	var firstTunnel config.Tunnel
	for name, t := range cfg.Tunnels {
		firstName = name
		firstTunnel = t
		break
	}
	if firstName == "" {
		return nil, "", fmt.Errorf("no tunnels in namd.yml")
	}

	lbConfig, hasLB := cfg.LB[firstName]

	var addrs []string
	var strategy string

	if hasLB && len(lbConfig.Targets) > 0 {
		strategy = lbConfig.Strategy
		for _, t := range lbConfig.Targets {
			addrs = append(addrs, t.Addr)
		}
	} else {
		strategy = "round_robin"
		addrs = []string{firstTunnel.Addr}
	}

	lb, err := loadbalancer.New(strategy, addrs)
	if err != nil {
		return nil, "", err
	}

	localURL := fmt.Sprintf("http://localhost:%s", addrs[0])
	if strings.Contains(addrs[0], ":") {
		localURL = fmt.Sprintf("http://%s", addrs[0])
	}

	return lb, localURL, nil
}

func buildWebhookEngine(cfg *config.Config, localURL string) (*webhook.Engine, error) {
	relays := make([]webhook.RelayConfig, 0, len(cfg.Webhooks.Relay))
	for _, r := range cfg.Webhooks.Relay {
		relays = append(relays, webhook.RelayConfig{
			Name: r.Name, Path: r.Path, Adapter: r.Adapter,
			Store: r.Store, Replay: r.Replay,
		})
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	store, err := webhook.NewStore(filepath.Join(homeDir, ".namd", "webhooks"))
	if err != nil {
		return nil, err
	}

	return webhook.NewEngine(adapters.Registry(), store, relays, localURL), nil
}

func resolveServerAddr(cfg *config.Config) string {
	if addr := os.Getenv("NAMD_SERVER"); addr != "" {
		return addr
	}
	return "localhost:9000"
}

func firstTunnelURL(cfg *config.Config) (string, error) {
	for _, t := range cfg.Tunnels {
		return fmt.Sprintf("http://localhost:%s", t.Addr), nil
	}
	return "", fmt.Errorf("no tunnels in namd.yml")
}

// streamResponseWriter wraps net.Conn as http.ResponseWriter for the webhook engine.
type streamResponseWriter struct {
	conn       net.Conn
	headers    http.Header
	statusCode int
	written    bool
}

func newStreamResponseWriter(conn net.Conn) *streamResponseWriter {
	return &streamResponseWriter{conn: conn, headers: make(http.Header), statusCode: 200}
}

func (w *streamResponseWriter) Header() http.Header { return w.headers }

func (w *streamResponseWriter) WriteHeader(code int) {
	if w.written {
		return
	}
	w.written = true
	w.statusCode = code
	fmt.Fprintf(w.conn, "HTTP/1.0 %d %s\r\n", code, http.StatusText(code))
	for k, vals := range w.headers {
		for _, v := range vals {
			fmt.Fprintf(w.conn, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprintf(w.conn, "\r\n")
}

func (w *streamResponseWriter) Write(b []byte) (int, error) {
	if !w.written {
		w.WriteHeader(200)
	}
	return w.conn.Write(b)
}

// ── Handoff runner functions ──────────────────────────────────────────────────

func runHandoff(configPath, peer string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	// Strip @ prefix if provided.
	peerName := strings.TrimPrefix(peer, "@")

	// Validate peer is in trusted list.
	trusted := false
	for _, p := range cfg.Handoff.TrustedPeers {
		if strings.TrimPrefix(p, "@") == peerName {
			trusted = true
			break
		}
	}
	if !trusted {
		return fmt.Errorf("@%s is not in your trusted_peers list in namd.yml", peerName)
	}

	maxDur, err := time.ParseDuration(cfg.Handoff.MaxDuration)
	if err != nil {
		maxDur = 60 * time.Minute
	}

	// Find the first tunnel subdomain.
	subdomain := cfg.Identity.Name
	for _, t := range cfg.Tunnels {
		if t.Subdomain != "" {
			subdomain = t.Subdomain
		}
		break
	}

	serverAddr := resolveServerAddr(cfg)
	sender := handoff.NewSender(handoff.HandoffRequest{
		From:        cfg.Identity.Name,
		To:          peerName,
		Subdomain:   subdomain,
		MaxDuration: maxDur,
		ServerAddr:  serverAddr,
	}, os.Getenv("NAMD_SECRET"))

	token, err := sender.Initiate()
	if err != nil {
		return err
	}

	// Block until token expires — then print summary.
	remaining := token.TimeRemaining()
	log.Printf("[handoff] waiting %s until handoff expires...", remaining.Round(time.Minute))
	time.Sleep(remaining)
	log.Printf("[handoff] handoff session ended")
	return nil
}

func runHandoffCancel(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	subdomain := cfg.Identity.Name
	serverAddr := resolveServerAddr(cfg)

	return handoff.Cancel(serverAddr, cfg.Identity.Name, subdomain)
}

func runAccept(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	maxDur, err := time.ParseDuration(cfg.Handoff.MaxDuration)
	if err != nil {
		maxDur = 60 * time.Minute
	}

	serverAddr := resolveServerAddr(cfg)
	receiver := handoff.NewReceiver(
		cfg.Identity.Name,
		serverAddr,
		os.Getenv("NAMD_SECRET"),
		cfg.Handoff.Sandbox,
		maxDur,
	)

	log.Printf("[handoff] waiting for handoff requests as @%s", cfg.Identity.Name)
	receiver.Listen() // blocks forever
	return nil
}

// ── Auth runner ───────────────────────────────────────────────────────────────

func runAuthRegister(name, email, serverAddr string) error {
	// Check if already registered.
	existing, err := auth.LoadCredentials()
	if err == nil {
		fmt.Printf("Already registered as @%s on %s\n", existing.Name, existing.ServerURL)
		fmt.Printf("To re-register, delete ~/.namd/credentials first.\n")
		return nil
	}

	fmt.Printf("Registering @%s on %s...\n", name, serverAddr)

	creds, err := auth.Register(serverAddr, name, email)
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	fmt.Printf("\n✓ Registered successfully!\n")
	fmt.Printf("  Handle:  @%s\n", creds.Name)
	fmt.Printf("  Server:  %s\n", creds.ServerURL)
	fmt.Printf("  Stored:  ~/.namd/credentials\n")
	fmt.Printf("\nYou can now run: namd start\n")
	return nil
}
