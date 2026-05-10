// Package admin provides the server-side admin panel.
// Runs on :9003 — never expose this port publicly.
// Protected by NAMD_ADMIN_TOKEN environment variable.
// Access via SSH tunnel: ssh -L 9003:localhost:9003 root@YOUR_VPS
package admin

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"runtime"
	"time"
)

// AccountInfo is a sanitised view of an account for the admin panel.
// We never expose token hashes — just metadata.
type AccountInfo struct {
	Name       string    `json:"name"`
	Email      string    `json:"email"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	Banned     bool      `json:"banned"`
}

// TunnelInfo is a live tunnel shown in the admin panel.
type TunnelInfo struct {
	Name        string    `json:"name"`
	PublicURL   string    `json:"public_url"`
	ClientIP    string    `json:"client_ip"`
	ConnectedAt time.Time `json:"connected_at"`
	Requests    int64     `json:"requests"`
	BytesIn     int64     `json:"bytes_in"`
	BytesOut    int64     `json:"bytes_out"`
}

// AuditEntry is one security event from the server logs.
type AuditEntry struct {
	Time   time.Time `json:"time"`
	Event  string    `json:"event"`
	Name   string    `json:"name"`
	IP     string    `json:"ip"`
	Reason string    `json:"reason,omitempty"`
}

// ServerHealth holds runtime stats about namd-server.
type ServerHealth struct {
	Uptime     string `json:"uptime"`
	Goroutines int    `json:"goroutines"`
	MemoryMB   uint64 `json:"memory_mb"`
	NumCPU     int    `json:"num_cpu"`
}

// Store is the interface the admin panel reads from.
// Implemented by the server — admin never touches internal state directly.
type Store interface {
	// Accounts returns all registered accounts.
	Accounts() []AccountInfo

	// ActiveTunnels returns currently connected tunnels.
	ActiveTunnels() []TunnelInfo

	// RecentAuditLog returns the last N audit events.
	RecentAuditLog(n int) []AuditEntry

	// BanAccount blocks an account from connecting.
	BanAccount(name, reason string) error

	// UnbanAccount re-enables a banned account.
	UnbanAccount(name string) error

	// DisconnectTunnel force-closes a tunnel connection.
	DisconnectTunnel(name string) error
}

// Server is the admin HTTP server.
type Server struct {
	port  int
	token string // NAMD_ADMIN_TOKEN — required on every request
	store Store
	mux   *http.ServeMux
	start time.Time
}

// NewServer creates the admin panel server.
// token — the value of NAMD_ADMIN_TOKEN env var
// store — the server's data store
func NewServer(port int, token string, store Store) *Server {
	s := &Server{
		port:  port,
		token: token,
		store: store,
		mux:   http.NewServeMux(),
		start: time.Now(),
	}

	// All routes go through auth middleware.
	s.mux.HandleFunc("/", s.auth(s.handleDashboard))
	s.mux.HandleFunc("/api/accounts", s.auth(s.handleAccounts))
	s.mux.HandleFunc("/api/tunnels", s.auth(s.handleTunnels))
	s.mux.HandleFunc("/api/audit", s.auth(s.handleAudit))
	s.mux.HandleFunc("/api/health", s.auth(s.handleHealth))
	s.mux.HandleFunc("/api/ban", s.auth(s.handleBan))
	s.mux.HandleFunc("/api/unban", s.auth(s.handleUnban))
	s.mux.HandleFunc("/api/disconnect", s.auth(s.handleDisconnect))

	return s
}

func (s *Server) Start() {
	addr := fmt.Sprintf(":%d", s.port)
	log.Printf("[admin] panel on %s (access via SSH tunnel only)", addr)
	if err := http.ListenAndServe(addr, s.mux); err != nil {
		log.Fatalf("[admin] server error: %v", err)
	}
}

// auth is middleware that checks the admin token.
// Token must be passed as: Authorization: Bearer <token>
// OR as query param: ?token=<token>
// OR as header: X-Admin-Token: <token>
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.token == "" {
			http.Error(w, "admin panel disabled — set NAMD_ADMIN_TOKEN", 503)
			return
		}

		// Check multiple token locations for convenience.
		token := r.Header.Get("X-Admin-Token")
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		if token == "" {
			auth := r.Header.Get("Authorization")
			if len(auth) > 7 && auth[:7] == "Bearer " {
				token = auth[7:]
			}
		}

		if token != s.token {
			w.Header().Set("WWW-Authenticate", `Basic realm="namd admin"`)
			http.Error(w, "unauthorized — wrong or missing admin token", 401)
			return
		}

		next(w, r)
	}
}

// handleDashboard renders the admin HTML page.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	accounts := s.store.Accounts()
	tunnels := s.store.ActiveTunnels()
	audit := s.store.RecentAuditLog(50)
	health := s.health()

	data := struct {
		Accounts []AccountInfo
		Tunnels  []TunnelInfo
		Audit    []AuditEntry
		Health   ServerHealth
		Token    string
	}{
		Accounts: accounts,
		Tunnels:  tunnels,
		Audit:    audit,
		Health:   health,
		Token:    s.token,
	}

	tmpl := template.Must(template.New("admin").Funcs(template.FuncMap{
		"ago": func(t time.Time) string {
			if t.IsZero() {
				return "never"
			}
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
		"bytes": func(b int64) string {
			switch {
			case b < 1024:
				return fmt.Sprintf("%dB", b)
			case b < 1024*1024:
				return fmt.Sprintf("%.1fKB", float64(b)/1024)
			case b < 1024*1024*1024:
				return fmt.Sprintf("%.1fMB", float64(b)/1024/1024)
			default:
				return fmt.Sprintf("%.2fGB", float64(b)/1024/1024/1024)
			}
		},
	}).Parse(adminHTML))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("[admin] template error: %v", err)
	}
}

func (s *Server) handleAccounts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.store.Accounts())
}

func (s *Server) handleTunnels(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.store.ActiveTunnels())
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.store.RecentAuditLog(100))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.health())
}

func (s *Server) handleBan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	name := r.FormValue("name")
	reason := r.FormValue("reason")
	if name == "" {
		http.Error(w, "name required", 400)
		return
	}
	if reason == "" {
		reason = "banned by admin"
	}
	if err := s.store.BanAccount(name, reason); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	log.Printf("[admin] banned account @%s: %s", name, reason)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"banned":true,"name":%q}`, name)
}

func (s *Server) handleUnban(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	name := r.FormValue("name")
	if name == "" {
		http.Error(w, "name required", 400)
		return
	}
	if err := s.store.UnbanAccount(name); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	log.Printf("[admin] unbanned account @%s", name)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"unbanned":true,"name":%q}`, name)
}

func (s *Server) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	name := r.FormValue("name")
	if name == "" {
		http.Error(w, "name required", 400)
		return
	}
	if err := s.store.DisconnectTunnel(name); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	log.Printf("[admin] disconnected tunnel @%s", name)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"disconnected":true,"name":%q}`, name)
}

func (s *Server) health() ServerHealth {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	uptime := time.Since(s.start)

	h := fmt.Sprintf("%dh %dm", int(uptime.Hours()), int(uptime.Minutes())%60)
	if uptime < time.Hour {
		h = fmt.Sprintf("%dm %ds", int(uptime.Minutes()), int(uptime.Seconds())%60)
	}

	return ServerHealth{
		Uptime:     h,
		Goroutines: runtime.NumGoroutine(),
		MemoryMB:   mem.Alloc / 1024 / 1024,
		NumCPU:     runtime.NumCPU(),
	}
}

const adminHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>namd admin</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0a0a0a;color:#e0e0e0;min-height:100vh;padding:28px 20px}
.header{display:flex;align-items:center;gap:10px;margin-bottom:28px}
.logo{font-size:20px;font-weight:700;color:#fff}
.logo span{color:#f87171}
.badge{font-size:10px;padding:2px 8px;border-radius:999px;background:#1a0a0a;color:#f87171;border:1px solid #3d1a1a}
.warn{background:#1a1200;border:1px solid #3d2d00;border-radius:8px;padding:12px 16px;font-size:12px;color:#facc15;margin-bottom:20px}
.tabs{display:flex;gap:2px;margin-bottom:20px;border-bottom:1px solid #1a1a1a}
.tab{padding:8px 16px;font-size:12px;font-weight:500;color:#555;cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px}
.tab:hover{color:#888}
.tab.active{color:#fff;border-bottom-color:#f87171}
.panel{display:none}.panel.active{display:block}
.card{background:#111;border:1px solid #1e1e1e;border-radius:10px;padding:18px 20px;margin-bottom:16px}
.card-title{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:#444;margin-bottom:14px}
.health-row{display:flex;gap:24px}
.stat{display:flex;flex-direction:column;gap:2px}
.stat-val{font-size:22px;font-weight:700;color:#fff;font-family:monospace}
.stat-lbl{font-size:10px;color:#333;text-transform:uppercase;letter-spacing:.06em}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:#333;padding-bottom:8px;border-bottom:1px solid #1a1a1a}
td{padding:9px 0;border-bottom:1px solid #161616;vertical-align:middle}
tr:last-child td{border-bottom:none}
.name{font-family:monospace;font-weight:600;color:#e0e0e0}
.email{color:#444;font-size:11px}
.ts{color:#333;font-size:11px;font-family:monospace}
.ip{color:#555;font-size:11px;font-family:monospace}
.url{color:#60a5fa;font-family:monospace;font-size:11px}
.banned-tag{font-size:10px;padding:1px 6px;border-radius:4px;background:#2d0a0a;color:#f87171;border:1px solid #5a1a1a}
.active-tag{font-size:10px;padding:1px 6px;border-radius:4px;background:#052e16;color:#4ade80;border:1px solid #166534}
.btn{padding:3px 10px;font-size:11px;border-radius:5px;border:1px solid #2a2a2a;background:#161616;color:#888;cursor:pointer;transition:all .15s}
.btn:hover{background:#1e1e1e;color:#ccc}
.btn.red{border-color:#7f1d1d;background:#2d0a0a;color:#f87171}
.btn.red:hover{background:#3d0e0e}
.btn.green{border-color:#166534;background:#052e16;color:#4ade80}
.btn.green:hover{background:#0f3d1e}
.btn.yellow{border-color:#3d2d00;background:#1a1200;color:#facc15}
.btn.yellow:hover{background:#241800}
.event{font-family:monospace;font-size:11px;color:#60a5fa}
.reason{font-size:11px;color:#666}
.empty{color:#333;font-size:12px;padding:6px 0}
.confirm-overlay{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.8);z-index:100;align-items:center;justify-content:center}
.confirm-box{background:#111;border:1px solid #2a2a2a;border-radius:12px;padding:24px;max-width:380px;width:90%}
.confirm-box h3{font-size:15px;margin-bottom:8px;color:#fff}
.confirm-box p{font-size:13px;color:#666;margin-bottom:20px}
.confirm-actions{display:flex;gap:8px;justify-content:flex-end}
input[type=text]{background:#0a0a0a;border:1px solid #2a2a2a;border-radius:6px;padding:6px 10px;font-size:12px;color:#e0e0e0;width:100%;margin-bottom:8px;font-family:monospace}
input[type=text]:focus{outline:none;border-color:#444}
</style>
</head>
<body>

<div class="header">
  <div class="logo">na<span>md</span> <span style="font-size:14px;color:#555">admin</span></div>
  <div class="badge">restricted</div>
</div>

<div class="warn">
  ⚠ Admin panel — access via SSH tunnel only. Never expose port 9003 publicly.
  <code style="margin-left:8px;font-size:11px">ssh -L 9003:localhost:9003 root@YOUR_VPS</code>
</div>

<div class="tabs">
  <div class="tab active" onclick="showTab('health')">Health</div>
  <div class="tab" onclick="showTab('tunnels')">Tunnels ({{len .Tunnels}})</div>
  <div class="tab" onclick="showTab('accounts')">Accounts ({{len .Accounts}})</div>
  <div class="tab" onclick="showTab('audit')">Audit Log</div>
</div>

<!-- Health -->
<div class="panel active" id="tab-health">
  <div class="card">
    <div class="card-title">Server Health</div>
    <div class="health-row">
      <div class="stat"><div class="stat-val">{{.Health.Uptime}}</div><div class="stat-lbl">Uptime</div></div>
      <div class="stat"><div class="stat-val">{{.Health.Goroutines}}</div><div class="stat-lbl">Goroutines</div></div>
      <div class="stat"><div class="stat-val">{{.Health.MemoryMB}}MB</div><div class="stat-lbl">Memory</div></div>
      <div class="stat"><div class="stat-val">{{.Health.NumCPU}}</div><div class="stat-lbl">CPUs</div></div>
      <div class="stat"><div class="stat-val">{{len .Tunnels}}</div><div class="stat-lbl">Active Tunnels</div></div>
      <div class="stat"><div class="stat-val">{{len .Accounts}}</div><div class="stat-lbl">Accounts</div></div>
    </div>
  </div>
</div>

<!-- Tunnels -->
<div class="panel" id="tab-tunnels">
  <div class="card">
    <div class="card-title">Active Tunnels</div>
    {{if .Tunnels}}
    <table>
      <thead><tr><th>Name</th><th>Public URL</th><th>Client IP</th><th>Connected</th><th>Requests</th><th>In</th><th>Out</th><th></th></tr></thead>
      <tbody>
        {{range .Tunnels}}
        <tr>
          <td><span class="name">@{{.Name}}</span></td>
          <td><span class="url">{{.PublicURL}}</span></td>
          <td><span class="ip">{{.ClientIP}}</span></td>
          <td><span class="ts">{{.ConnectedAt | ago}}</span></td>
          <td><span class="ts">{{.Requests}}</span></td>
          <td><span class="ts">{{.BytesIn | bytes}}</span></td>
          <td><span class="ts">{{.BytesOut | bytes}}</span></td>
          <td><button class="btn yellow" onclick="confirmDisconnect('{{.Name}}')">disconnect</button></td>
        </tr>
        {{end}}
      </tbody>
    </table>
    {{else}}
    <div class="empty">No active tunnels</div>
    {{end}}
  </div>
</div>

<!-- Accounts -->
<div class="panel" id="tab-accounts">
  <div class="card">
    <div class="card-title">Registered Accounts</div>
    {{if .Accounts}}
    <table>
      <thead><tr><th>Name</th><th>Email</th><th>Created</th><th>Last seen</th><th>Status</th><th></th></tr></thead>
      <tbody>
        {{range .Accounts}}
        <tr>
          <td><span class="name">@{{.Name}}</span></td>
          <td><span class="email">{{.Email}}</span></td>
          <td><span class="ts">{{.CreatedAt | ago}}</span></td>
          <td><span class="ts">{{.LastSeenAt | ago}}</span></td>
          <td>
            {{if .Banned}}
            <span class="banned-tag">banned</span>
            {{else}}
            <span class="active-tag">active</span>
            {{end}}
          </td>
          <td>
            {{if .Banned}}
            <button class="btn green" onclick="unban('{{.Name}}')">unban</button>
            {{else}}
            <button class="btn red" onclick="confirmBan('{{.Name}}')">ban</button>
            {{end}}
          </td>
        </tr>
        {{end}}
      </tbody>
    </table>
    {{else}}
    <div class="empty">No registered accounts</div>
    {{end}}
  </div>
</div>

<!-- Audit -->
<div class="panel" id="tab-audit">
  <div class="card">
    <div class="card-title">Recent Security Events</div>
    {{if .Audit}}
    <table>
      <thead><tr><th>Time</th><th>Event</th><th>Name</th><th>IP</th><th>Reason</th></tr></thead>
      <tbody>
        {{range .Audit}}
        <tr>
          <td><span class="ts">{{.Time | ago}}</span></td>
          <td><span class="event">{{.Event}}</span></td>
          <td><span class="name">{{if .Name}}@{{.Name}}{{end}}</span></td>
          <td><span class="ip">{{.IP}}</span></td>
          <td><span class="reason">{{.Reason}}</span></td>
        </tr>
        {{end}}
      </tbody>
    </table>
    {{else}}
    <div class="empty">No audit events yet</div>
    {{end}}
  </div>
</div>

<!-- Confirm ban dialog -->
<div class="confirm-overlay" id="ban-overlay">
  <div class="confirm-box">
    <h3>Ban account</h3>
    <p>This will block <strong id="ban-name-display"></strong> from connecting.</p>
    <input type="text" id="ban-reason" placeholder="Reason (e.g. abuse, spam)">
    <div class="confirm-actions">
      <button class="btn" onclick="closeBanDialog()">Cancel</button>
      <button class="btn red" onclick="executeBan()">Ban account</button>
    </div>
  </div>
</div>

<!-- Confirm disconnect dialog -->
<div class="confirm-overlay" id="disconnect-overlay">
  <div class="confirm-box">
    <h3>Disconnect tunnel</h3>
    <p>Force-close the tunnel for <strong id="disconnect-name-display"></strong>.</p>
    <div class="confirm-actions">
      <button class="btn" onclick="closeDisconnectDialog()">Cancel</button>
      <button class="btn yellow" onclick="executeDisconnect()">Disconnect</button>
    </div>
  </div>
</div>

<script>
const TOKEN = '{{.Token}}'

function showTab(name) {
  document.querySelectorAll('.tab').forEach((t,i) => {
    t.classList.toggle('active', ['health','tunnels','accounts','audit'][i] === name)
  })
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'))
  document.getElementById('tab-' + name).classList.add('active')
}

function api(path, method, body) {
  return fetch(path + '?token=' + TOKEN, {
    method: method || 'GET',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: body
  }).then(r => r.json())
}

let pendingBanName = ''
function confirmBan(name) {
  pendingBanName = name
  document.getElementById('ban-name-display').textContent = '@' + name
  document.getElementById('ban-reason').value = ''
  document.getElementById('ban-overlay').style.display = 'flex'
}
function closeBanDialog() {
  document.getElementById('ban-overlay').style.display = 'none'
}
function executeBan() {
  const reason = document.getElementById('ban-reason').value || 'banned by admin'
  api('/api/ban', 'POST', 'name=' + pendingBanName + '&reason=' + encodeURIComponent(reason))
    .then(() => { closeBanDialog(); location.reload() })
    .catch(e => alert('Error: ' + e))
}

function unban(name) {
  if (!confirm('Unban @' + name + '?')) return
  api('/api/unban', 'POST', 'name=' + name)
    .then(() => location.reload())
    .catch(e => alert('Error: ' + e))
}

let pendingDisconnectName = ''
function confirmDisconnect(name) {
  pendingDisconnectName = name
  document.getElementById('disconnect-name-display').textContent = '@' + name
  document.getElementById('disconnect-overlay').style.display = 'flex'
}
function closeDisconnectDialog() {
  document.getElementById('disconnect-overlay').style.display = 'none'
}
function executeDisconnect() {
  api('/api/disconnect', 'POST', 'name=' + pendingDisconnectName)
    .then(() => { closeDisconnectDialog(); location.reload() })
    .catch(e => alert('Error: ' + e))
}

// Auto-refresh health every 30 seconds
setInterval(() => {
  api('/api/health').then(h => {
    // Could update health stats inline here
    // For now just reload the page if on health tab
    if (document.querySelector('.tab.active').textContent.includes('Health')) {
      location.reload()
    }
  })
}, 30000)
</script>
</body>
</html>`
