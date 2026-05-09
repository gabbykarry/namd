package dashboard

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"
)

// Server is the dashboard web server.
// It owns an HTTP mux and a reference to the shared Stats store.
// It runs on :5555 in its own goroutine.
type Server struct {
	port  int
	stats *Stats
	mux   *http.ServeMux
}

// NewServer creates a dashboard server.
//
// port  — typically 5555, comes from namd.yml dashboard.port
// stats — the shared Stats store the tunnel also writes to
func NewServer(port int, stats *Stats) *Server {
	s := &Server{
		port:  port,
		stats: stats,
		// http.NewServeMux creates a fresh router.
		// A ServeMux maps URL paths to handler functions.
		// We use a fresh one rather than http.DefaultServeMux so we
		// do not accidentally pick up any globally registered handlers.
		mux: http.NewServeMux(),
	}

	// Register routes.
	// s.mux.HandleFunc(path, handler) means:
	// "when a request hits this path, call this function"
	//
	// http.HandlerFunc signature: func(w http.ResponseWriter, r *http.Request)
	//   w — what you write your response into
	//   r — the incoming request (method, headers, body, URL)
	s.mux.HandleFunc("/", s.handleDashboard)
	s.mux.HandleFunc("/api/stats", s.handleStats)

	return s
}

// Start launches the dashboard HTTP server.
// This is a BLOCKING call — run it in a goroutine:
//
//	go dashboard.Start()
//
// It never returns unless the server crashes.
func (s *Server) Start() {
	addr := fmt.Sprintf(":%d", s.port)
	log.Printf("[dashboard] running on http://localhost%s", addr)

	// http.ListenAndServe starts an HTTP server.
	// addr  — the address to listen on e.g. ":5555"
	// s.mux — the router that handles requests
	//
	// This is different from our manual net.Listen + Accept loop.
	// http.ListenAndServe handles all of that internally for HTTP.
	// We use it here because the dashboard speaks standard HTTP —
	// no custom protocol, no yamux, no raw TCP tricks needed.
	if err := http.ListenAndServe(addr, s.mux); err != nil {
		log.Fatalf("[dashboard] server error: %v", err)
	}
}

// handleDashboard renders the main dashboard HTML page.
//
// w http.ResponseWriter — we write our HTML response here
// r *http.Request       — the incoming request from the browser
//
// We use html/template which is Go's built-in templating engine.
// It automatically escapes HTML in data values — prevents XSS attacks.
// The template lives as a string constant below — we could also
// put it in a .html file and use //go:embed to bundle it.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	// Get a consistent snapshot of current stats.
	// Snapshot() returns copies so the template reads stable data
	// even if the tunnel goroutine updates stats mid-render.
	tunnel, requests := s.stats.Snapshot()

	// templateData is the struct we pass into the template.
	// The template accesses fields with {{ .FieldName }} syntax.
	// All fields must be exported (capital letter) for the template engine
	// to access them via reflection.
	data := struct {
		Tunnel   *TunnelStat
		Requests []RequestLog
		Now      time.Time
	}{
		Tunnel:   tunnel,
		Requests: requests,
		Now:      time.Now(),
	}

	// Parse and execute the template.
	// template.Must panics if parsing fails — acceptable here because
	// a broken template is a programming error, not a runtime error.
	// In production we would parse once at startup and cache the result.
	tmpl := template.Must(template.New("dashboard").Funcs(template.FuncMap{
		// Custom template functions — available inside the template as {{ funcName arg }}

		// ago formats a time.Time as "3m ago", "1h ago" etc.
		"ago": func(t time.Time) string {
			d := time.Since(t)
			switch {
			case d < time.Minute:
				return fmt.Sprintf("%ds ago", int(d.Seconds()))
			case d < time.Hour:
				return fmt.Sprintf("%dm ago", int(d.Minutes()))
			default:
				return fmt.Sprintf("%dh ago", int(d.Hours()))
			}
		},

		// ms formats a duration as milliseconds.
		"ms": func(d time.Duration) string {
			return fmt.Sprintf("%dms", d.Milliseconds())
		},

		// statusClass returns a CSS class based on HTTP status code.
		// Used to colour the status badge in the request log.
		"statusClass": func(code int) string {
			switch {
			case code >= 500:
				return "status-error"
			case code >= 400:
				return "status-warn"
			default:
				return "status-ok"
			}
		},
	}).Parse(dashboardHTML))

	// Set Content-Type so browsers render as HTML, not plain text.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// tmpl.Execute writes the rendered HTML into w.
	// It walks the template, substituting {{ .Field }} with real values from data.
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("[dashboard] template error: %v", err)
	}
}

// handleStats returns current stats as JSON for programmatic access.
// Useful for scripts or future CLI commands that query the dashboard.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	tunnel, requests := s.stats.Snapshot()

	w.Header().Set("Content-Type", "application/json")

	if tunnel == nil {
		fmt.Fprintf(w, `{"tunnel":null,"request_count":%d}`, len(requests))
		return
	}

	fmt.Fprintf(w, `{"tunnel":{"name":%q,"public_url":%q,"requests":%d},"request_count":%d}`,
		tunnel.Name, tunnel.PublicURL, tunnel.Requests, len(requests),
	)
}

// dashboardHTML is the full HTML template for the dashboard.
//
// Go template syntax:
//
//	{{ .Field }}          — insert a value from the data struct
//	{{ if .Field }} {{ end }} — conditional block
//	{{ range .Slice }} {{ end }} — loop over a slice
//	{{ .Field | funcName }} — pipe a value through a template function
//
// html/template automatically HTML-escapes all {{ }} values.
// This prevents XSS — if a tunnel name contains <script>, it is escaped.
const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>namd dashboard</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #0f0f0f;
      color: #e0e0e0;
      min-height: 100vh;
      padding: 32px 24px;
    }

    .header {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 32px;
    }

    .logo {
      font-size: 22px;
      font-weight: 700;
      color: #fff;
      letter-spacing: -0.5px;
    }

    .logo span { color: #4ade80; }

    .badge {
      font-size: 11px;
      padding: 2px 8px;
      border-radius: 999px;
      background: #1a1a1a;
      color: #888;
      border: 1px solid #2a2a2a;
    }

    .section {
      background: #1a1a1a;
      border: 1px solid #2a2a2a;
      border-radius: 10px;
      padding: 20px 24px;
      margin-bottom: 20px;
    }

    .section-title {
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: #555;
      margin-bottom: 16px;
    }

    .tunnel-row {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: #4ade80;
      box-shadow: 0 0 6px #4ade80;
      flex-shrink: 0;
    }

    .dot.offline { background: #ef4444; box-shadow: 0 0 6px #ef4444; }

    .tunnel-url {
      font-size: 15px;
      font-weight: 500;
      color: #fff;
      font-family: "SF Mono", "Fira Code", monospace;
    }

    .tunnel-meta {
      font-size: 12px;
      color: #555;
      margin-left: auto;
    }

    .empty {
      color: #444;
      font-size: 13px;
      padding: 8px 0;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }

    th {
      text-align: left;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: #444;
      padding-bottom: 10px;
      border-bottom: 1px solid #2a2a2a;
    }

    td {
      padding: 10px 0;
      border-bottom: 1px solid #1f1f1f;
      vertical-align: middle;
    }

    tr:last-child td { border-bottom: none; }

    .method {
      font-family: monospace;
      font-size: 11px;
      font-weight: 700;
      color: #60a5fa;
      width: 48px;
    }

    .path {
      font-family: monospace;
      color: #d4d4d4;
    }

    .status-ok   { color: #4ade80; font-weight: 600; font-family: monospace; }
    .status-warn { color: #facc15; font-weight: 600; font-family: monospace; }
    .status-error{ color: #ef4444; font-weight: 600; font-family: monospace; }

    .duration { color: #555; font-family: monospace; font-size: 12px; }
    .time     { color: #3a3a3a; font-size: 11px; font-family: monospace; }

    .stats-row {
      display: flex;
      gap: 24px;
      margin-top: 12px;
    }

    .stat {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .stat-value {
      font-size: 22px;
      font-weight: 700;
      color: #fff;
      font-family: monospace;
    }

    .stat-label {
      font-size: 11px;
      color: #444;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }

    .refresh {
      font-size: 11px;
      color: #333;
      margin-top: 28px;
      text-align: center;
    }
  </style>
  <!-- Auto-refresh every 5 seconds — WebSocket in a later phase -->
  <meta http-equiv="refresh" content="5">
</head>
<body>

<div class="header">
  <div class="logo">na<span>md</span></div>
  <div class="badge">dashboard</div>
</div>

<!-- ── Tunnel Status ─────────────────────────────────────── -->
<div class="section">
  <div class="section-title">Active Tunnel</div>

  {{ if .Tunnel }}
  <div class="tunnel-row">
    <div class="dot"></div>
    <div class="tunnel-url">{{ .Tunnel.PublicURL }}</div>
    <div class="tunnel-meta">
      connected {{ .Tunnel.ConnectedAt | ago }} &nbsp;·&nbsp;
      {{ .Tunnel.Requests }} requests
    </div>
  </div>
  {{ else }}
  <div class="tunnel-row">
    <div class="dot offline"></div>
    <div class="empty">No active tunnel</div>
  </div>
  {{ end }}

  {{ if .Tunnel }}
  <div class="stats-row">
    <div class="stat">
      <div class="stat-value">{{ .Tunnel.Requests }}</div>
      <div class="stat-label">Requests</div>
    </div>
    <div class="stat">
      <div class="stat-value">{{ .Tunnel.BytesIn }}</div>
      <div class="stat-label">Bytes in</div>
    </div>
    <div class="stat">
      <div class="stat-value">{{ .Tunnel.BytesOut }}</div>
      <div class="stat-label">Bytes out</div>
    </div>
  </div>
  {{ end }}
</div>

<!-- ── Request Log ───────────────────────────────────────── -->
<div class="section">
  <div class="section-title">Recent Requests</div>

  {{ if .Requests }}
  <table>
    <thead>
      <tr>
        <th>Method</th>
        <th>Path</th>
        <th>Status</th>
        <th>Duration</th>
        <th>Time</th>
      </tr>
    </thead>
    <tbody>
      {{ range .Requests }}
      <tr>
        <td><span class="method">{{ .Method }}</span></td>
        <td><span class="path">{{ .Path }}</span></td>
        <td><span class="{{ .StatusCode | statusClass }}">{{ .StatusCode }}</span></td>
        <td><span class="duration">{{ .Duration | ms }}</span></td>
        <td><span class="time">{{ .Timestamp | ago }}</span></td>
      </tr>
      {{ end }}
    </tbody>
  </table>
  {{ else }}
  <div class="empty">No requests yet — send some traffic through the tunnel</div>
  {{ end }}
</div>

<div class="refresh">auto-refreshes every 5s</div>

</body>
</html>`
