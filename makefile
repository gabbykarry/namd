MODULE   := github.com/gabbykarry/namd
GO       := go
BIN      := ./bin
VPS_HOST ?= your-vps-ip
VPS_USER ?= root
VPS_KEY  ?= ~/.ssh/id_rsa

-include Makefile.local

.PHONY: create
create:
	@echo "-> Creating namd project structure..."
	@mkdir -p cmd/namd cmd/namd-server internal/auth internal/config internal/tunnel
	@mkdir -p internal/firewall internal/loadbalancer internal/proxy
	@mkdir -p internal/webhook/adapters internal/handoff internal/deploy
	@mkdir -p internal/mesh internal/cache internal/dashboard/ui internal/transport
	@mkdir -p pkg/token pkg/logger pkg/version docs/diagrams examples
	@mkdir -p .github/ISSUE_TEMPLATE deploy/systemd
	@touch cmd/namd/main.go cmd/namd-server/main.go
	@touch internal/config/config.go internal/config/loader.go internal/config/validator.go
	@touch internal/tunnel/session.go internal/tunnel/registry.go internal/tunnel/errors.go
	@touch internal/firewall/engine.go internal/firewall/rule.go
	@touch internal/loadbalancer/balancer.go internal/loadbalancer/roundrobin.go
	@touch internal/loadbalancer/leastconn.go internal/loadbalancer/random.go
	@touch internal/loadbalancer/healthcheck.go
	@touch internal/proxy/handler.go internal/proxy/reverseproxy.go
	@touch internal/webhook/engine.go internal/webhook/store.go internal/webhook/adapter.go
	@touch internal/webhook/adapters/paystack.go internal/webhook/adapters/flutterwave.go
	@touch internal/webhook/adapters/github.go internal/webhook/adapters/generic.go
	@touch internal/webhook/adapters/registry.go
	@touch internal/handoff/sender.go internal/handoff/receiver.go internal/handoff/token.go
	@touch internal/cache/proxy.go internal/cache/store.go
	@touch internal/dashboard/server.go internal/dashboard/stats.go
	@touch internal/transport/mux.go internal/transport/tls.go
	@touch pkg/token/token.go pkg/logger/logger.go pkg/version/version.go
	@touch docs/architecture.md docs/contributing.md README.md
	@echo ""
	@echo "Structure created. Next: make init"

.PHONY: init
init:
	$(GO) mod init $(MODULE)
	$(GO) get gopkg.in/yaml.v3
	$(GO) get github.com/hashicorp/yamux
	$(GO) get github.com/spf13/cobra

.PHONY: build
build:
	@mkdir -p $(BIN)
	$(GO) build -ldflags "-X $(MODULE)/pkg/version.Version=$(shell git describe --tags --always 2>/dev/null || echo dev)" -o $(BIN)/namd ./cmd/namd
	$(GO) build -o $(BIN)/namd-server ./cmd/namd-server
	@echo "Binaries in $(BIN)/"

.PHONY: build-linux
build-linux:
	@mkdir -p $(BIN)
	GOOS=linux GOARCH=amd64 $(GO) build -o $(BIN)/namd-server-linux ./cmd/namd-server
	@echo "$(BIN)/namd-server-linux ready"

.PHONY: deploy-setup
deploy-setup: build-linux
	scp -i $(VPS_KEY) $(BIN)/namd-server-linux $(VPS_USER)@$(VPS_HOST):/usr/local/bin/namd-server
	scp -i $(VPS_KEY) deploy/systemd/namd-server.service $(VPS_USER)@$(VPS_HOST):/etc/systemd/system/namd-server.service
	ssh -i $(VPS_KEY) $(VPS_USER)@$(VPS_HOST) "chmod +x /usr/local/bin/namd-server && systemctl daemon-reload && systemctl enable namd-server && systemctl start namd-server && systemctl status namd-server --no-pager"

.PHONY: deploy
deploy: build-linux
	scp -i $(VPS_KEY) $(BIN)/namd-server-linux $(VPS_USER)@$(VPS_HOST):/usr/local/bin/namd-server
	ssh -i $(VPS_KEY) $(VPS_USER)@$(VPS_HOST) "chmod +x /usr/local/bin/namd-server && systemctl restart namd-server && systemctl status namd-server --no-pager"

# Upload landing page to VPS 
.PHONY: deploy-landing
deploy-landing:
	scp -i $(VPS_KEY) landing/index.html $(VPS_USER)@$(VPS_HOST):/var/www/namd/index.html
	@echo "Landing page deployed to namd.online"

.PHONY: logs
logs:
	ssh -i $(VPS_KEY) $(VPS_USER)@$(VPS_HOST) "journalctl -u namd-server -f --no-pager"

.PHONY: admin
admin:
	ssh -i $(VPS_KEY) -L 9003:localhost:9003 $(VPS_USER)@$(VPS_HOST)

.PHONY: server-status
server-status:
	ssh -i $(VPS_KEY) $(VPS_USER)@$(VPS_HOST) "systemctl status namd-server --no-pager"

.PHONY: server-restart
server-restart:
	ssh -i $(VPS_KEY) $(VPS_USER)@$(VPS_HOST) "systemctl restart namd-server && systemctl status namd-server --no-pager"

.PHONY: server-stop
server-stop:
	ssh -i $(VPS_KEY) $(VPS_USER)@$(VPS_HOST) "systemctl stop namd-server"

.PHONY: ssh
ssh:
	ssh -i $(VPS_KEY) $(VPS_USER)@$(VPS_HOST)

.PHONY: run
run:
	$(GO) run ./cmd/namd start

.PHONY: run-tls-off
run-tls-off:
	NAMD_TLS=false $(GO) run ./cmd/namd start

.PHONY: run-server
run-server:
	$(GO) run ./cmd/namd-server

# Serve landing page locally on port 4000
.PHONY: landing
landing:
	@echo "Serving landing page on http://localhost:4000"
	@cd landing && npx serve . -p 4000

# Run everything locally — server, client, and landing page
.PHONY: dev
dev:
	@echo "Starting local dev environment..."
	@$(GO) run ./cmd/namd-server &
	@sleep 1
	@cd landing && npx serve . -p 4000 &
	@$(GO) run ./cmd/namd start

.PHONY: test
test:
	$(GO) test -race ./...

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: clean
clean:
	@rm -rf $(BIN)
	@echo "Cleaned"