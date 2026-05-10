<div align="center">

# namd

**Open source tunnel for African developers.**

Expose your localhost to the internet. Test Paystack and Flutterwave webhooks locally. Share your work with clients. Keep coding when your internet drops.

```bash
namd start
# tunnel active → http://gabriel.82-165-x-x.nip.io
```

[Installation](#install) · [Quick start](#quick-start) · [Webhooks](#webhook-testing) · [Config reference](#namdyml-reference) · [Self-hosting](#self-hosting) · [Contributing](#contributing)

</div>

---

## Why namd

Nigerian developers building with Paystack, Flutterwave, or any webhook-based API face a specific problem — you cannot test webhooks on localhost. The payment provider needs a real public URL.

The existing tools cost money for the features you actually need, and their free tiers get more restricted every year.

namd is free, open source, and built with African payment APIs in mind.

---

## Features

- **Tunnel** — expose localhost to the internet with one command
- **Webhook relay** — intercept Paystack, Flutterwave, GitHub webhooks — inspect payload, store events, replay missed ones
- **Load balancer** — round robin, least connections, or random across multiple local backends
- **Offline cache** — serve cached API responses when your internet drops — keep coding
- **Live handoff** — battery dying mid-demo? transfer your running server to a trusted peer's machine
- **Dashboard** — real-time request log, webhook inspector, handoff panel at `localhost:5555`
- **Auth** — token-based identity — no anonymous tunnels
- **Firewall** — per-tunnel IP rules and rate limiting from `namd.yml`

---

## Install

**Go install (recommended for Go developers):**
```bash
go install github.com/gabbykarry/namd/cmd/namd@latest
```

**Download binary:**
```bash
# macOS Apple Silicon
curl -L https://github.com/gabbykarry/namd/releases/latest/download/namd-darwin-arm64 -o namd
chmod +x namd && sudo mv namd /usr/local/bin/

# macOS Intel
curl -L https://github.com/gabbykarry/namd/releases/latest/download/namd-darwin-amd64 -o namd
chmod +x namd && sudo mv namd /usr/local/bin/

# Linux
curl -L https://github.com/gabbykarry/namd/releases/latest/download/namd-linux-amd64 -o namd
chmod +x namd && sudo mv namd /usr/local/bin/
```

---

## Quick start

**1. Register** (one time — free):
```bash
namd auth register --name yourname --email you@example.com
```

**2. Create `namd.yml`** in your project root:
```yaml
version: "1"

identity:
  name: yourname
  region: af-west

tunnels:
  api:
    proto: http
    addr: "3000"

dashboard:
  port: 5555
  enabled: true
```

**3. Start your tunnel:**
```bash
namd start
```

```
[namd] tunnel active  → https://yourname.namd.online
[namd] dashboard      → http://localhost:5555
```

Your `localhost:3000` is now reachable from anywhere in the world.

---

## Webhook testing

Add a webhook relay to `namd.yml`:

```yaml
webhooks:
  relay:
    - name: payments
      tunnel: api
      path: /webhooks/payment
      adapter: paystack        # paystack | flutterwave | github | generic
      store: true              # persist events so you can replay them
      replay: true
```

namd intercepts requests to `/webhooks/payment`, verifies the Paystack signature, stores the event, and forwards it to your local app.

**Point Paystack at your tunnel URL:**
```
https://yourname.namd.online/webhooks/payment
```

**Replay events your local server missed** (e.g. while it was down):
```bash
namd webhook replay payments
```

Or click **replay** in the dashboard Webhooks tab.

**Built-in adapters:**

| Adapter | Verification method |
|---------|-------------------|
| `paystack` | `X-Paystack-Signature` — HMAC-SHA512 |
| `flutterwave` | `verif-hash` header |
| `github` | `X-Hub-Signature-256` — HMAC-SHA256 |
| `generic` | none — relay everything |

---

## Dashboard

Open `http://localhost:5555` while your tunnel is running.

- **Tunnel tab** — live URL, request count, copy URL with one click
- **Requests tab** — every HTTP request with method, path, status, duration — live updates
- **Webhooks tab** — intercepted events, inspect full JSON payload, replay button
- **Handoffs tab** — accept or decline incoming handoffs, cancel active ones

The dashboard uses Server-Sent Events — no page refresh needed, updates appear instantly.

---

## Offline cache

When your internet drops, namd serves cached responses for configured API URLs:

```yaml
cache:
  enabled: true
  ttl: 5m
  targets:
    - https://api.paystack.co
    - https://api.flutterwave.com
```

Point your app at the namd cache proxy:
```bash
export HTTP_PROXY=http://localhost:7777
```

First request hits the real API and caches the response. Subsequent requests — including during outages — are served instantly from cache.

---

## Load balancing

Run multiple local instances and spread traffic across them:

```yaml
load_balancer:
  api:
    strategy: round_robin    # round_robin | least_conn | random
    targets:
      - addr: "3000"
      - addr: "3001"
      - addr: "3002"
    health_check:
      path: /health
      interval: 10s
```

Dead targets are removed from rotation automatically and re-added when they recover.

---

## Live handoff

Your battery is dying mid-demo. Transfer your tunnel to a trusted peer:

```yaml
handoff:
  max_duration: 60m
  sandbox: docker
  trusted_peers:
    - "@tunde"
```

```bash
namd handoff @tunde
```

- tunde must be in your `trusted_peers` list
- tunde must be running `namd start`
- tunde explicitly accepts in their terminal or dashboard
- Your code runs sandboxed on tunde's machine — cannot access their filesystem
- Same public URL, zero downtime, auto-expires after `max_duration`

---

## namd.yml reference

```yaml
version: "1"

identity:
  name: gabriel              # your handle → gabriel.namd.online
  region: af-west            # af-west | af-east | af-south

tunnels:
  api:
    proto: http              # http | tcp
    addr: "3000"             # local port
    auth:
      type: bearer
      token: ${NAMD_TOKEN}   # ${ENV_VAR} substitution — never hardcode secrets

load_balancer:
  api:
    strategy: round_robin
    targets:
      - addr: "3000"
      - addr: "3001"
    health_check:
      path: /health
      interval: 10s

webhooks:
  relay:
    - name: payments
      tunnel: api
      path: /webhooks/payment
      adapter: paystack
      store: true
      replay: true
    - name: github-events
      tunnel: api
      path: /webhooks/github
      adapter: github
      store: true
      replay: true

firewall:
  api:
    allow:
      - 0.0.0.0/0            # allow all (default)
    deny:
      - 1.2.3.4/32           # block specific IP
    rate_limit:
      requests: 100
      window: 60s

cache:
  enabled: true
  ttl: 5m
  targets:
    - https://api.paystack.co
    - https://api.flutterwave.com

handoff:
  max_duration: 60m
  sandbox: docker            # docker | process
  trusted_peers:
    - "@tunde"
    - "@chidi"

mesh:
  team: my-team
  secret: ${MESH_SECRET}

dashboard:
  port: 5555
  enabled: true
```

---

## CLI reference

```bash
# Tunnel
namd start                              # start using namd.yml
namd start --config /path/to/namd.yml  # use specific config

# Auth
namd auth register --name gabriel --email you@example.com
namd auth status

# Webhooks
namd webhook replay payments            # replay all stored events for relay

# Handoff
namd handoff @tunde                     # hand off to trusted peer
namd handoff cancel                     # cancel active handoff
namd accept                             # wait for incoming handoff requests

# Info
namd version
```

---

## Self-hosting

You can run your own namd server instead of using namd.online.

**Requirements:** A VPS with a public IP (DigitalOcean, Hetzner, Contabo — ~$4-6/month).

**Quick deploy:**

```bash
# Clone the repo
git clone https://github.com/gabbykarry/namd
cd namd

# Build for Linux
make build-linux

# First time setup (uploads binary, installs systemd service)
make deploy-setup VPS_HOST=YOUR_IP VPS_USER=root

# Register against your own server
export NAMD_SERVER=YOUR_IP:9000
namd auth register --name yourname --email you@example.com

# Connect
namd start
```

**Server environment variables:**

| Variable | Description |
|----------|-------------|
| `NAMD_SECRET` | Server signing secret — generate with `openssl rand -hex 32` |
| `NAMD_ADMIN_TOKEN` | Admin panel token — access via SSH tunnel on port 9003 |
| `NAMD_CERT` | TLS certificate path (Let's Encrypt) |
| `NAMD_KEY` | TLS private key path |
| `NAMD_DOMAIN` | Your domain e.g. `namd.online` — falls back to nip.io without it |
| `NAMD_MAX_STREAMS` | Max concurrent requests per tunnel (default: 100) |
| `NAMD_MAX_BODY_MB` | Max request body size in MB (default: 10) |

**Admin panel** (via SSH tunnel only — never expose port 9003 publicly):
```bash
ssh -L 9003:localhost:9003 root@YOUR_VPS
# then open: http://localhost:9003?token=YOUR_ADMIN_TOKEN
```

---

## Contributing

namd is open source and welcomes contributions. The most impactful contribution you can make is adding a **webhook adapter** for a provider not yet supported.

### Adding a webhook adapter

Create `internal/webhook/adapters/yourprovider.go`:

```go
package adapters

import (
    "net/http"
    "github.com/gabbykarry/namd/internal/webhook"
)

type YourProviderAdapter struct{}

func (a *YourProviderAdapter) Name() string { return "yourprovider" }

func (a *YourProviderAdapter) Verify(r *http.Request, secret string) error {
    // verify the webhook signature
    return nil
}

func (a *YourProviderAdapter) Normalize(r *http.Request) (*webhook.Event, error) {
    // parse the payload into a webhook.Event
    return &webhook.Event{
        Provider: "yourprovider",
        Type:     "event.type",
    }, nil
}
```

Register it in `internal/webhook/adapters/registry.go`:

```go
func Registry() map[string]webhook.Adapter {
    return map[string]webhook.Adapter{
        "generic":      &GenericAdapter{},
        "paystack":     &PaystackAdapter{},
        "flutterwave":  &FlutterwaveAdapter{},
        "github":       &GitHubAdapter{},
        "yourprovider": &YourProviderAdapter{}, // add this line
    }
}
```

Open a PR — no other files need to change.

### Development setup

```bash
git clone https://github.com/gabbykarry/namd
cd namd
make init           # go mod + dependencies
make run-server     # start local server
make run            # start tunnel (separate terminal)
make test           # run tests
```

### Areas needing help

- Webhook adapters for African payment providers (Interswitch, Monnify, Kora, Bloc)
- Windows binary support
- Tests — unit and integration
- Documentation improvements
- UI improvements to the dashboard

---

## Architecture

```
namd client (your laptop)          namd server (VPS)
┌─────────────────────┐           ┌──────────────────────────┐
│ namd start          │           │ :9000 tunnel listener    │
│   ↓                 │           │ :8080 public HTTP        │
│ yamux session ───────────────── │ :9001 handoff broker     │
│   ↓                 │           │ :9002 registration       │
│ stream per request  │           │ :9003 admin panel        │
│   ↓                 │           └──────────────────────────┘
│ localhost:3000      │
└─────────────────────┘

Browser → VPS :8080 → yamux stream → namd client → localhost:3000
```

Built with Go. Uses [yamux](https://github.com/hashicorp/yamux) for multiplexing.

---

## License

MIT — see [LICENSE](LICENSE)

---

<div align="center">
Built in Nigeria 🇳🇬 for African developers
</div>