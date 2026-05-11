# Contributing to namd

Thank you for contributing. namd is built for African developers and every contribution matters.

---

## What we need most

1. **Webhook adapters** for African payment providers not yet supported
2. **Bug reports** with clear reproduction steps
3. **Documentation** improvements
4. **Tests** — we have very few right now

---

## Webhook adapters

This is the highest-impact contribution. Adding support for a new webhook provider takes one file.

**Providers we need (in priority order):**
- Interswitch / Quickteller
- Monnify
- Kora Pay
- Bloc
- Squad (GTBank)
- Paga
- MTN MoMo Nigeria API
- Barter by Flutterwave
- Stripe (for devs building global products)

**How to add one:**

### Step 1 — Create the adapter file

```bash
touch internal/webhook/adapters/monnify.go
```

```go
package adapters

import (
    "crypto/hmac"
    "crypto/sha512"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io"
    "net/http"

    "github.com/gabbykarry/namd/internal/webhook"
)

// MonnifyAdapter verifies and normalises Monnify webhook events.
// Monnify docs: https://developers.monnify.com/api/#webhooks
type MonnifyAdapter struct{}

func (a *MonnifyAdapter) Name() string { return "monnify" }

func (a *MonnifyAdapter) Verify(r *http.Request, secret string) error {
    // Implement signature verification from Monnify docs
    // Return nil if valid, error if invalid
    return nil
}

func (a *MonnifyAdapter) Normalize(r *http.Request) (*webhook.Event, error) {
    body, err := io.ReadAll(r.Body)
    if err != nil {
        return nil, err
    }

    var payload struct {
        EventType string `json:"eventType"`
    }
    json.Unmarshal(body, &payload)

    return &webhook.Event{
        Provider: "monnify",
        Type:     payload.EventType,
    }, nil
}
```

### Step 2 — Register it

In `internal/webhook/adapters/registry.go`, add one line:

```go
func Registry() map[string]webhook.Adapter {
    return map[string]webhook.Adapter{
        "generic":     &GenericAdapter{},
        "paystack":    &PaystackAdapter{},
        "flutterwave": &FlutterwaveAdapter{},
        "github":      &GitHubAdapter{},
        "monnify":     &MonnifyAdapter{}, // add this
    }
}
```

### Step 3 — Open a PR

Title: `feat(webhooks): add Monnify adapter`

That is it. No other files change. The engine is provider-agnostic.

---

## Development setup

```bash
git clone https://github.com/gabbykarry/namd
cd namd
make init
```

Run the server and client locally:

```bash
# Terminal 1
make run-server

# Terminal 2
namd auth register --name dev --email dev@test.com --server localhost:9000
make run
```

---

## Code structure

```
cmd/
  namd/           client binary — what developers install
  namd-server/    server binary — runs on the VPS

internal/
  auth/           identity, registration, token verification
  cache/          offline proxy cache
  config/         namd.yml parsing and validation
  dashboard/      local web UI on :5555
  firewall/       IP allow/deny rules, rate limiting
  handoff/        live server handoff between peers
  loadbalancer/   round_robin, least_conn, random strategies
  transport/      TCP + TLS + yamux wiring
  tunnel/         session registry
  webhook/        relay engine + adapters

pkg/
  logger/         structured logging with AUDIT level
  version/        build-time version info
```

---

## PR checklist

Before opening a PR:

- [ ] `go build ./...` passes
- [ ] `go test ./...` passes (or you explain why tests are not included)
- [ ] No new dependencies unless absolutely necessary
- [ ] Code follows the existing style — short functions, comments on non-obvious decisions
- [ ] Webhook adapters include the provider docs URL in a comment

---

## Commit style

```
feat(webhooks): add Monnify adapter
fix(auth): handle empty token on registration
docs: update webhook adapter guide
refactor(cache): extract shouldCache into helper
```

---

## Security issues

Do not open public issues for security vulnerabilities. Email directly: security@namd.online

---

## Questions

Open a GitHub Discussion. We respond in West Africa time (WAT, UTC+1).