package dashboard

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"
)

// Server is the dashboard HTTP + WebSocket server.
type Server struct {
	port       int
	stats      *Stats
	mux        *http.ServeMux
	replayFunc func(relayName string) error // called when user clicks replay
}

func NewServer(port int, stats *Stats) *Server {
	s := &Server{
		port:  port,
		stats: stats,
		mux:   http.NewServeMux(),
	}

	s.mux.HandleFunc("/", s.handleDashboard)
	s.mux.HandleFunc("/api/stats", s.handleStatsJSON)
	s.mux.HandleFunc("/ws", s.handleWebSocket)
	s.mux.HandleFunc("/api/webhook/replay", s.handleWebhookReplay)

	return s
}

// SetReplayFunc wires in the webhook engine replay capability.
// Called from cmd/namd/main.go after the webhook engine is created.
func (s *Server) SetReplayFunc(fn func(relayName string) error) {
	s.replayFunc = fn
}

func (s *Server) Start() {
	addr := fmt.Sprintf(":%d", s.port)
	log.Printf("[dashboard] running on http://localhost%s", addr)

	if err := http.ListenAndServe(addr, s.mux); err != nil {
		log.Fatalf("[dashboard] server error: %v", err)
	}
}

// handleDashboard renders the full dashboard page.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	snap := s.stats.Snapshot()

	data := struct {
		Snapshot
		Now time.Time
	}{
		Snapshot: snap,
		Now:      time.Now(),
	}

	tmpl := template.Must(template.New("dash").Funcs(template.FuncMap{
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
		"ms": func(d time.Duration) string {
			return fmt.Sprintf("%dms", d.Milliseconds())
		},
		"statusClass": func(code int) string {
			switch {
			case code >= 500:
				return "err"
			case code >= 400:
				return "warn"
			default:
				return "ok"
			}
		},
		"timeLeft": func(t time.Time) string {
			d := time.Until(t)
			if d <= 0 {
				return "expired"
			}
			return fmt.Sprintf("%dm left", int(d.Minutes()))
		},
	}).Parse(dashboardHTML))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("[dashboard] template error: %v", err)
	}
}

// handleStatsJSON returns all stats as JSON.
func (s *Server) handleStatsJSON(w http.ResponseWriter, r *http.Request) {
	snap := s.stats.Snapshot()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snap)
}

// handleWebSocket implements a minimal WebSocket server.
// When stats change, we push the new stats JSON to all connected browsers.
// The browser JS updates the UI without a full page reload.
//
// WebSocket handshake:
//  1. Browser sends HTTP Upgrade request
//  2. Server responds with 101 Switching Protocols
//  3. Both sides speak the WebSocket framing protocol
//
// We implement just enough WebSocket to push JSON — no full library needed.
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// SSE endpoint — plain GET, no WebSocket upgrade needed.
	// Browser connects with EventSource("/ws") which is a regular HTTP GET.
	// Server keeps the connection open and pushes data frames.
	// SSE is simpler — server pushes text events, browser reads them.
	// No handshake, no framing, just HTTP with chunked transfer.
	// The browser uses EventSource API to receive them.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", 500)
		return
	}

	// Subscribe to stat changes.
	ch := s.stats.Subscribe()
	defer s.stats.Unsubscribe(ch)

	// Send initial state immediately.
	s.sendSSEEvent(w, flusher)

	// Push updates whenever stats change.
	for {
		select {
		case <-ch:
			s.sendSSEEvent(w, flusher)
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) sendSSEEvent(w http.ResponseWriter, flusher http.Flusher) {
	snap := s.stats.Snapshot()
	data, err := json.Marshal(snap)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "data: %s\n\n", string(data))
	flusher.Flush()
}

// handleWebhookReplay triggers replay of a stored webhook event.
func (s *Server) handleWebhookReplay(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	eventID := r.URL.Query().Get("id")
	if eventID == "" {
		http.Error(w, "missing id", 400)
		return
	}
	relayName := r.URL.Query().Get("relay")
	if relayName == "" {
		// Try to find relay from event ID in stats.
		snap := s.stats.Snapshot()
		for _, wh := range snap.Webhooks {
			if wh.ID == eventID {
				relayName = wh.RelayName
				break
			}
		}
	}

	if s.replayFunc != nil && relayName != "" {
		if err := s.replayFunc(relayName); err != nil {
			log.Printf("[dashboard] replay error: %v", err)
			http.Error(w, err.Error(), 500)
			return
		}
		log.Printf("[dashboard] replayed events for relay %q", relayName)
	} else {
		log.Printf("[dashboard] replay requested for event %s (relay=%s)", eventID, relayName)
	}
	w.WriteHeader(200)
	fmt.Fprintf(w, `{"replayed":true,"id":%q}`, eventID)
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>namd</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0a0a0a;color:#e0e0e0;min-height:100vh;padding:28px 20px}
.header{display:flex;align-items:center;gap:10px;margin-bottom:28px}
.logo{font-size:20px;font-weight:700;color:#fff;letter-spacing:-0.5px}
.logo span{color:#4ade80}
.badge{font-size:10px;padding:2px 8px;border-radius:999px;background:#111;color:#666;border:1px solid #222}
.live{width:7px;height:7px;border-radius:50%;background:#4ade80;box-shadow:0 0 6px #4ade80;animation:pulse 2s infinite;margin-left:auto}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.tabs{display:flex;gap:2px;margin-bottom:20px;border-bottom:1px solid #1a1a1a;padding-bottom:0}
.tab{padding:8px 16px;font-size:12px;font-weight:500;color:#555;cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px;transition:color .15s}
.tab:hover{color:#888}
.tab.active{color:#fff;border-bottom-color:#4ade80}
.panel{display:none}.panel.active{display:block}
.card{background:#111;border:1px solid #1e1e1e;border-radius:10px;padding:18px 20px;margin-bottom:16px}
.card-title{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:#444;margin-bottom:14px}
.tunnel-row{display:flex;align-items:center;gap:10px}
.dot{width:7px;height:7px;border-radius:50%;background:#4ade80;box-shadow:0 0 5px #4ade80;flex-shrink:0}
.dot.off{background:#ef4444;box-shadow:0 0 5px #ef4444}
.tunnel-url{font-size:14px;font-weight:500;color:#fff;font-family:monospace;cursor:pointer}
.tunnel-url:hover{color:#4ade80}
.copy-hint{font-size:10px;color:#333;margin-left:6px}
.meta{font-size:11px;color:#444;margin-left:auto}
.stats-row{display:flex;gap:20px;margin-top:14px}
.stat{display:flex;flex-direction:column;gap:2px}
.stat-val{font-size:20px;font-weight:700;color:#fff;font-family:monospace}
.stat-lbl{font-size:10px;color:#333;text-transform:uppercase;letter-spacing:.06em}
.empty{color:#333;font-size:12px;padding:6px 0}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:#333;padding-bottom:8px;border-bottom:1px solid #1a1a1a}
td{padding:9px 0;border-bottom:1px solid #161616;vertical-align:middle}
tr:last-child td{border-bottom:none}
.method{font-family:monospace;font-size:10px;font-weight:700;color:#60a5fa;width:40px}
.path{font-family:monospace;color:#ccc;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ok{color:#4ade80;font-weight:600;font-family:monospace}
.warn{color:#facc15;font-weight:600;font-family:monospace}
.err{color:#ef4444;font-weight:600;font-family:monospace}
.dur{color:#444;font-family:monospace;font-size:11px}
.ts{color:#2a2a2a;font-size:10px;font-family:monospace}
.btn{padding:4px 10px;font-size:11px;border-radius:5px;border:1px solid #2a2a2a;background:#161616;color:#888;cursor:pointer;transition:all .15s}
.btn:hover{background:#1e1e1e;color:#ccc;border-color:#333}
.btn.green{border-color:#166534;background:#052e16;color:#4ade80}
.btn.green:hover{background:#0f3d1e}
.btn.red{border-color:#7f1d1d;background:#2d0a0a;color:#f87171}
.btn.red:hover{background:#3d0e0e}
.provider{font-size:10px;padding:2px 6px;border-radius:4px;background:#1a1a1a;color:#888;font-family:monospace}
.handoff-card{border:1px solid #1e1e1e;border-radius:8px;padding:14px;margin-bottom:10px;background:#0f0f0f}
.handoff-header{display:flex;align-items:center;gap:8px;margin-bottom:8px}
.handoff-status{font-size:10px;padding:2px 8px;border-radius:999px;font-weight:600}
.status-pending{background:#1a1500;color:#facc15;border:1px solid #3d3200}
.status-active{background:#052e16;color:#4ade80;border:1px solid #166534}
.status-expired{background:#1a0a0a;color:#555;border:1px solid #2a1a1a}
.handoff-info{font-size:11px;color:#444;display:flex;gap:16px}
.json-viewer{background:#0a0a0a;border:1px solid #1a1a1a;border-radius:6px;padding:12px;font-family:monospace;font-size:11px;color:#888;max-height:200px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;margin-top:8px}
.expand-btn{font-size:10px;color:#333;cursor:pointer;margin-top:4px;display:inline-block}
.expand-btn:hover{color:#666}
</style>
</head>
<body>

<div class="header">
  <div class="logo">na<span>md</span></div>
  <div class="badge">dashboard</div>
  <div class="live" id="live" title="Live updates via SSE"></div>
</div>

<div class="tabs">
  <div class="tab active" onclick="showTab('tunnel')">Tunnel</div>
  <div class="tab" onclick="showTab('requests')">Requests <span id="req-count"></span></div>
  <div class="tab" onclick="showTab('webhooks')">Webhooks <span id="wh-count"></span></div>
  <div class="tab" onclick="showTab('handoffs')">Handoffs <span id="hf-count"></span></div>
</div>

<!-- Tunnel tab -->
<div class="panel active" id="tab-tunnel">
  <div class="card" id="tunnel-card">
    <div class="card-title">Active Tunnel</div>
    <div id="tunnel-content">
      <div class="tunnel-row">
        <div class="dot off"></div>
        <div class="empty">No active tunnel — run namd start</div>
      </div>
    </div>
  </div>
</div>

<!-- Requests tab -->
<div class="panel" id="tab-requests">
  <div class="card">
    <div class="card-title">Recent Requests</div>
    <div id="requests-content"><div class="empty">No requests yet</div></div>
  </div>
</div>

<!-- Webhooks tab -->
<div class="panel" id="tab-webhooks">
  <div class="card">
    <div class="card-title">Webhook Events</div>
    <div id="webhooks-content"><div class="empty">No webhook events yet</div></div>
  </div>
</div>

<!-- Handoffs tab -->
<div class="panel" id="tab-handoffs">
  <div class="card">
    <div class="card-title">Handoffs</div>
    <div id="handoffs-content"><div class="empty">No handoffs yet</div></div>
  </div>
</div>

<script>
// ── Tab switching ──────────────────────────────────────────────────────────
function showTab(name) {
  document.querySelectorAll('.tab').forEach((t,i) => {
    t.classList.toggle('active', ['tunnel','requests','webhooks','handoffs'][i] === name)
  })
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'))
  document.getElementById('tab-' + name).classList.add('active')
}

// ── Copy tunnel URL on click ───────────────────────────────────────────────
function copyURL(url) {
  navigator.clipboard.writeText('http://' + url).then(() => {
    const hint = document.querySelector('.copy-hint')
    if (hint) { hint.textContent = 'copied!'; setTimeout(() => hint.textContent = 'click to copy', 1500) }
  })
}

// ── Toggle JSON viewer ─────────────────────────────────────────────────────
function toggleJSON(id) {
  const el = document.getElementById(id)
  el.style.display = el.style.display === 'none' ? 'block' : 'none'
}

// ── Replay webhook ─────────────────────────────────────────────────────────
function replayWebhook(id, relay) {
  fetch('/api/webhook/replay?id=' + id + (relay ? '&relay=' + relay : ''), {method:'POST'})
    .then(r => r.json())
    .then(() => { alert('Replayed events for relay: ' + (relay || id)) })
    .catch(e => alert('Replay failed: ' + e))
}

// ── Format helpers ─────────────────────────────────────────────────────────
function ago(ts) {
  const d = (Date.now() - new Date(ts).getTime()) / 1000
  if (d < 60) return Math.floor(d) + 's ago'
  if (d < 3600) return Math.floor(d/60) + 'm ago'
  return Math.floor(d/3600) + 'h ago'
}

function ms(ns) {
  return Math.round(ns / 1e6) + 'ms'
}

function statusClass(code) {
  if (code >= 500) return 'err'
  if (code >= 400) return 'warn'
  return 'ok'
}

// ── Render functions ───────────────────────────────────────────────────────
function renderTunnel(tunnel) {
  const el = document.getElementById('tunnel-content')
  if (!tunnel) {
    el.innerHTML = '<div class="tunnel-row"><div class="dot off"></div><div class="empty">No active tunnel — run namd start</div></div>'
    return
  }
  el.innerHTML = '<div class="tunnel-row">' +
    '<div class="dot"></div>' +
    '<div class="tunnel-url" onclick="copyURL(\'' + tunnel.PublicURL + '\')">' + tunnel.PublicURL + '</div>' +
    '<span class="copy-hint">click to copy</span>' +
    '<div class="meta">connected ' + ago(tunnel.ConnectedAt) + '</div>' +
    '</div>' +
    '<div class="stats-row">' +
    '<div class="stat"><div class="stat-val">' + tunnel.Requests + '</div><div class="stat-lbl">Requests</div></div>' +
    '</div>'
}

function renderRequests(requests) {
  const el = document.getElementById('requests-content')
  document.getElementById('req-count').textContent = requests && requests.length ? '(' + requests.length + ')' : ''
  if (!requests || !requests.length) {
    el.innerHTML = '<div class="empty">No requests yet — send some traffic through the tunnel</div>'
    return
  }
  let html = '<table><thead><tr><th>Method</th><th>Path</th><th>Status</th><th>Duration</th><th>Time</th></tr></thead><tbody>'
  requests.forEach(r => {
    html += '<tr>' +
      '<td><span class="method">' + r.Method + '</span></td>' +
      '<td><span class="path">' + r.Path + '</span></td>' +
      '<td><span class="' + statusClass(r.StatusCode) + '">' + r.StatusCode + '</span></td>' +
      '<td><span class="dur">' + ms(r.Duration) + '</span></td>' +
      '<td><span class="ts">' + ago(r.Timestamp) + '</span></td>' +
      '</tr>'
  })
  el.innerHTML = html + '</tbody></table>'
}

function renderWebhooks(webhooks) {
  const el = document.getElementById('webhooks-content')
  document.getElementById('wh-count').textContent = webhooks && webhooks.length ? '(' + webhooks.length + ')' : ''
  if (!webhooks || !webhooks.length) {
    el.innerHTML = '<div class="empty">No webhook events yet — configure webhooks in namd.yml</div>'
    return
  }
  let html = '<table><thead><tr><th>Provider</th><th>Event</th><th>Relay</th><th>Status</th><th>Time</th><th></th></tr></thead><tbody>'
  webhooks.forEach((w, i) => {
    const jsonID = 'json-' + i
    html += '<tr>' +
      '<td><span class="provider">' + w.Provider + '</span></td>' +
      '<td><span class="path">' + w.EventType + '</span></td>' +
      '<td><span class="ts">' + w.RelayName + '</span></td>' +
      '<td><span class="' + statusClass(w.StatusCode || 200) + '">' + (w.StatusCode || '—') + '</span></td>' +
      '<td><span class="ts">' + ago(w.ReceivedAt) + '</span></td>' +
      '<td>' +
        '<button class="btn" onclick="toggleJSON(\'' + jsonID + '\')">inspect</button> ' +
        (w.RawJSON ? '<button class="btn green" onclick="replayWebhook(\'' + w.ID + '\')">replay</button>' : '') +
      '</td>' +
      '</tr>' +
      '<tr><td colspan="6" style="padding:0">' +
        '<div id="' + jsonID + '" class="json-viewer" style="display:none">' +
          (w.RawJSON || 'no payload stored') +
        '</div>' +
      '</td></tr>'
  })
  el.innerHTML = html + '</tbody></table>'
}

function renderHandoffs(handoffs) {
  const el = document.getElementById('handoffs-content')
  document.getElementById('hf-count').textContent = handoffs && handoffs.length ? '(' + handoffs.length + ')' : ''
  if (!handoffs || !handoffs.length) {
    el.innerHTML = '<div class="empty">No handoffs yet — run: namd handoff @peer</div>'
    return
  }
  let html = ''
  handoffs.forEach(h => {
    const statusClass = h.Status === 'active' ? 'status-active' : h.Status === 'pending' ? 'status-pending' : 'status-expired'
    const timeLeft = h.Status === 'active' || h.Status === 'pending' ?
      Math.max(0, Math.round((new Date(h.ExpiresAt) - Date.now()) / 60000)) + 'm left' : ''

    html += '<div class="handoff-card">' +
      '<div class="handoff-header">' +
        '<span class="handoff-status ' + statusClass + '">' + h.Status + '</span>' +
        '<strong style="font-size:13px">@' + h.From + ' → @' + h.To + '</strong>' +
        (timeLeft ? '<span class="meta">' + timeLeft + '</span>' : '') +
      '</div>' +
      '<div class="handoff-info">' +
        '<span>Subdomain: ' + h.Subdomain + '</span>' +
        '<span>Started: ' + ago(h.StartedAt) + '</span>' +
      '</div>' +
      (h.Status === 'pending' ?
        '<div style="margin-top:10px;display:flex;gap:8px">' +
          '<button class="btn green" onclick="respondHandoff(\'' + h.ID + '\',true)">✓ Accept</button>' +
          '<button class="btn red" onclick="respondHandoff(\'' + h.ID + '\',false)">✗ Decline</button>' +
        '</div>' : '') +
      (h.Status === 'active' ?
        '<div style="margin-top:10px">' +
          '<button class="btn red" onclick="cancelHandoff(\'' + h.ID + '\')">Cancel handoff</button>' +
        '</div>' : '') +
      '</div>'
  })
  el.innerHTML = html
}

function respondHandoff(id, accept) {
  fetch('/api/handoff/respond?id=' + id + '&accept=' + accept, {method:'POST'})
    .then(r => r.json())
    .catch(e => console.error(e))
}

function cancelHandoff(id) {
  fetch('/api/handoff/cancel?id=' + id, {method:'POST'})
    .then(r => r.json())
    .catch(e => console.error(e))
}

// ── SSE live updates ───────────────────────────────────────────────────────
// Using SSE (Server-Sent Events) instead of full WebSocket.
// Simpler — server pushes JSON, browser updates UI instantly.
// No page reload, no battery drain from polling.
function connectSSE() {
  const es = new EventSource('/ws')
  const dot = document.getElementById('live')

  es.onmessage = function(e) {
    try {
      const data = JSON.parse(e.data)
      renderTunnel(data.Tunnel)
      renderRequests(data.Requests)
      renderWebhooks(data.Webhooks)
      renderHandoffs(data.Handoffs)
      dot.style.background = '#4ade80'
      dot.style.boxShadow = '0 0 6px #4ade80'
    } catch(err) {
      console.error('SSE parse error:', err)
    }
  }

  es.onerror = function() {
    dot.style.background = '#ef4444'
    dot.style.boxShadow = '0 0 6px #ef4444'
    // Reconnect after 3 seconds
    setTimeout(connectSSE, 3000)
    es.close()
  }
}

// Start live updates
connectSSE()
</script>
</body>
</html>`
