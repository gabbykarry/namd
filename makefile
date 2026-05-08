# ==============================================================================
# NAMD — Makefile
# ==============================================================================
# Usage:
#   make create     → scaffold the full project folder structure
#   make init       → initialize go module (run after create)
#   make build      → build both binaries
#   make run        → run the client CLI
#   make run-server → run the server
#   make test       → run all tests
#   make lint       → run linter
#   make clean      → remove build artifacts
# ==============================================================================

# MODULE is your Go module path. Change this to your actual GitHub username.
MODULE := github.com/gabbykarry/namd

# GO is the go binary. We define it as a variable so it's easy to override.
GO := go

# GOFLAGS are flags passed to every go command.
GOFLAGS := -v

# Build output directory
BIN := ./bin

# ==============================================================================
# create — scaffolds the entire project from scratch
# This is the only target you need on a fresh clone before anything else.
# ==============================================================================
.PHONY: create
create:
	@echo "→ Creating namd project structure..."

	@# cmd — the two binary entrypoints
	@# namd     = the client developers install on their machines
	@# namd-server = the server that runs on the VPS
	@mkdir -p cmd/namd
	@mkdir -p cmd/namd-server

	@# internal — Go compiler prevents anyone outside this module
	@# from importing these packages. Core protected logic lives here.

	@# auth — user registration, login, keypair management
	@mkdir -p internal/auth

	@# config — namd.yml parsing, env substitution, validation
	@mkdir -p internal/config

	@# tunnel — core domain: session model, tunnel registry
	@mkdir -p internal/tunnel

	@# firewall — IP allow/deny rules, rate limiting engine
	@mkdir -p internal/firewall

	@# loadbalancer — round robin, least conn, random, health checks
	@mkdir -p internal/loadbalancer

	@# proxy — HTTP reverse proxy, TCP proxy handler
	@mkdir -p internal/proxy

	@# webhook — generic relay engine + adapter plugin system
	@# adapters/ is where community PRs go (paystack, github, etc)
	@mkdir -p internal/webhook/adapters

	@# handoff — live server handoff to a trusted peer
	@mkdir -p internal/handoff

	@# deploy — lite deploy to a VPS over SSH
	@mkdir -p internal/deploy

	@# mesh — team mesh networking (WireGuard-based)
	@mkdir -p internal/mesh

	@# cache — offline proxy cache for when internet drops
	@mkdir -p internal/cache

	@# dashboard — web UI served on :5555
	@mkdir -p internal/dashboard/ui

	@# transport — raw TCP + yamux multiplexing wiring
	@mkdir -p internal/transport

	@# pkg — code that CAN be imported by external projects
	@# unlike internal/, these are intentionally public utilities
	@mkdir -p pkg/token
	@mkdir -p pkg/logger
	@mkdir -p pkg/version

	@# docs — architecture docs and mermaid diagrams
	@mkdir -p docs/diagrams

	@# examples — sample namd.yml configs for different use cases
	@mkdir -p examples

	@# .github — open source hygiene: PR templates, issue templates
	@mkdir -p .github/ISSUE_TEMPLATE

	@echo "→ Creating Go source files..."

	@# cmd entrypoints
	@touch cmd/namd/main.go
	@touch cmd/namd-server/main.go

	@# internal/auth
	@touch internal/auth/register.go
	@touch internal/auth/login.go
	@touch internal/auth/keypair.go
	@touch internal/auth/peer.go

	@# internal/config
	@touch internal/config/config.go
	@touch internal/config/loader.go
	@touch internal/config/validator.go

	@# internal/tunnel
	@touch internal/tunnel/session.go
	@touch internal/tunnel/registry.go
	@touch internal/tunnel/errors.go

	@# internal/firewall
	@touch internal/firewall/engine.go
	@touch internal/firewall/rule.go

	@# internal/loadbalancer
	@touch internal/loadbalancer/balancer.go
	@touch internal/loadbalancer/roundrobin.go
	@touch internal/loadbalancer/leastconn.go
	@touch internal/loadbalancer/random.go
	@touch internal/loadbalancer/healthcheck.go

	@# internal/proxy
	@touch internal/proxy/handler.go
	@touch internal/proxy/reverseproxy.go

	@# internal/webhook
	@touch internal/webhook/engine.go
	@touch internal/webhook/store.go
	@touch internal/webhook/adapter.go
	@touch internal/webhook/adapters/paystack.go
	@touch internal/webhook/adapters/flutterwave.go
	@touch internal/webhook/adapters/github.go
	@touch internal/webhook/adapters/generic.go
	@touch internal/webhook/adapters/registry.go

	@# internal/handoff
	@touch internal/handoff/sender.go
	@touch internal/handoff/receiver.go
	@touch internal/handoff/token.go
	@touch internal/handoff/sandbox.go

	@# internal/deploy
	@touch internal/deploy/deployer.go
	@touch internal/deploy/ssh.go

	@# internal/mesh
	@touch internal/mesh/mesh.go
	@touch internal/mesh/peer.go

	@# internal/cache
	@touch internal/cache/proxy.go
	@touch internal/cache/store.go

	@# internal/dashboard
	@touch internal/dashboard/server.go

	@# internal/transport
	@touch internal/transport/mux.go
	@touch internal/transport/tls.go

	@# pkg
	@touch pkg/token/token.go
	@touch pkg/logger/logger.go
	@touch pkg/version/version.go

	@# docs
	@touch docs/architecture.md
	@touch docs/contributing.md
	@touch docs/diagrams/system.mermaid
	@touch docs/diagrams/webhook-flow.mermaid
	@touch docs/diagrams/handoff-flow.mermaid

	@# examples
	@touch examples/namd.full.yml
	@touch examples/namd.minimal.yml
	@touch examples/namd.webhook.yml

	@# open source files
	@touch .github/ISSUE_TEMPLATE/bug_report.md
	@touch .github/ISSUE_TEMPLATE/feature_request.md
	@touch .github/PULL_REQUEST_TEMPLATE.md
	@touch README.md
	@touch .gitignore

	@echo ""
	@echo "✓ Structure created. Next step:"
	@echo "  make init   → initializes the Go module"
	@echo ""

# ==============================================================================
# init — run once after create to set up the Go module
# ==============================================================================
.PHONY: init
init:
	@echo "→ Initializing Go module: $(MODULE)"
	$(GO) mod init $(MODULE)
	@echo "→ Installing core dependencies..."
	$(GO) get gopkg.in/yaml.v3
	$(GO) get github.com/hashicorp/yamux
	$(GO) get github.com/spf13/cobra
	@echo "✓ Module initialized. You can now start writing code."

# ==============================================================================
# build — compiles both binaries into ./bin
# ==============================================================================
.PHONY: build
build:
	@mkdir -p $(BIN)
	@echo "→ Building namd client..."
	$(GO) build $(GOFLAGS) -o $(BIN)/namd ./cmd/namd
	@echo "→ Building namd-server..."
	$(GO) build $(GOFLAGS) -o $(BIN)/namd-server ./cmd/namd-server
	@echo "✓ Binaries in $(BIN)/"

# ==============================================================================
# run — runs the client with a namd.yml in the current directory
# ==============================================================================
.PHONY: run
run:
	$(GO) run ./cmd/namd

.PHONY: run-server
run-server:
	$(GO) run ./cmd/namd-server

# ==============================================================================
# test — runs all tests with race condition detection on
# -race flag tells Go to detect concurrent memory access bugs
# ==============================================================================
.PHONY: test
test:
	$(GO) test -race ./...

# ==============================================================================
# lint — runs golangci-lint (install: brew install golangci-lint)
# ==============================================================================
.PHONY: lint
lint:
	golangci-lint run ./...

# ==============================================================================
# clean — removes build artifacts
# ==============================================================================
.PHONY: clean
clean:
	@rm -rf $(BIN)
	@echo "✓ Cleaned"

# ==============================================================================
# tree — shows the project structure (requires `tree` to be installed)
# ==============================================================================
.PHONY: tree
tree:
	tree -I 'vendor|node_modules|.git' .