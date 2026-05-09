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

	"github.com/gabbykarry/namd/internal/config"
	"github.com/gabbykarry/namd/internal/dashboard"
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

	rootCmd.AddCommand(startCmd, webhookCmd, versionCmd)
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

	serverAddr := resolveServerAddr(cfg)
	log.Printf("[namd] connecting to %s", serverAddr)

	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		return fmt.Errorf("cannot connect to %s: %w", serverAddr, err)
	}

	fmt.Fprintf(conn, "HELLO %s\n", cfg.Identity.Name)

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
