# Deploying namd-server to a VPS

## What you need

- A VPS with a public IP address
- A domain name (or free subdomain from is-a.dev)
- SSH access to the VPS

## Recommended VPS providers (Africa-friendly)

| Provider | Location | Price | Notes |
|----------|----------|-------|-------|
| Hetzner | Johannesburg | ~$4/mo | Best latency for southern Africa |
| Contabo | Germany | ~$4/mo | Good for West Africa |
| DigitalOcean | Amsterdam | ~$6/mo | Easy setup, good docs |
| AWS Lightsail | Lagos | ~$5/mo | Closest to Nigeria |

---

## Step 1 — Get a VPS

Sign up for Hetzner (recommended for Africa):
1. Go to hetzner.com/cloud
2. Create a CX11 instance (2GB RAM, $4/mo)
3. Choose Ubuntu 22.04
4. Add your SSH public key
5. Note your server IP address

---

## Step 2 — Point your domain at the VPS

You need two DNS records:

```
Type    Name              Value
A       namd.online       YOUR_VPS_IP
A       *.namd.online     YOUR_VPS_IP    ← wildcard for subdomains
```

The wildcard `*.namd.online` is what makes `gabriel.namd.online`,
`tunde.namd.online` etc. all work automatically.

**Using a free domain from is-a.dev:**
1. Go to https://is-a.dev
2. Fork the repository
3. Add `namd.json` in the domains/ folder:
```json
{
  "owner": { "username": "gabbykarry" },
  "record": {
    "A": ["YOUR_VPS_IP"],
    "CNAME": "*.namd"
  }
}
```
4. Open a PR — approved within a day

---

## Step 3 — Deploy namd-server

From your local machine (your Mac):

```bash
# Set your VPS details
export VPS_HOST=YOUR_VPS_IP
export VPS_USER=root
export VPS_KEY=~/.ssh/id_rsa

# First-time setup — installs binary + systemd service
make deploy-setup
```

This:
1. Cross-compiles namd-server for Linux on your Mac
2. Uploads the binary to /usr/local/bin/namd-server
3. Installs the systemd service
4. Starts namd-server and enables it on boot

---

## Step 4 — Set the server secret

SSH into your VPS:

```bash
ssh root@YOUR_VPS_IP
```

Generate a strong secret:
```bash
openssl rand -hex 32
# outputs something like: a3f2c891d4e5b6...
```

Edit the systemd service:
```bash
nano /etc/systemd/system/namd-server.service
```

Replace `change-this-to-a-long-random-secret` with your generated secret.

Restart:
```bash
systemctl daemon-reload
systemctl restart namd-server
systemctl status namd-server
```

Set the same secret locally in your `namd.yml` environment:
```bash
export NAMD_SECRET=a3f2c891d4e5b6...
```

Or add to your shell profile (`~/.zshrc`):
```bash
echo 'export NAMD_SECRET=a3f2c891d4e5b6...' >> ~/.zshrc
```

---

## Step 5 — Open firewall ports

On your VPS:
```bash
# Allow namd ports
ufw allow 22    # SSH
ufw allow 80    # HTTP
ufw allow 443   # HTTPS
ufw allow 8080  # namd public HTTP (temporary — move to 80 with Caddy)
ufw allow 9000  # namd tunnel connections
ufw allow 9001  # namd handoff broker
ufw enable
```

---

## Step 6 — Add Caddy for SSL (optional but recommended)

Caddy automatically gets Let's Encrypt certificates and proxies port 80/443 to namd's :8080.

```bash
# Install Caddy
apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.gpg] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main" | tee /etc/apt/sources.list.d/caddy-stable.list
apt update && apt install caddy
```

Create `/etc/caddy/Caddyfile`:
```
*.namd.online, namd.online {
    reverse_proxy localhost:8080
    tls {
        dns cloudflare {env.CLOUDFLARE_API_TOKEN}
    }
}
```

For wildcard SSL you need DNS challenge — requires Cloudflare or another DNS provider with an API. If you just want basic SSL for specific subdomains, use:

```
gabriel.namd.online {
    reverse_proxy localhost:8080
}
```

---

## Step 7 — Connect your local namd to the real server

Update `NAMD_SERVER` environment variable:

```bash
export NAMD_SERVER=YOUR_VPS_IP:9000
```

Or add to namd.yml (when we add server address to config — Phase 11):

```yaml
server:
  addr: namd.online:9000
```

Run:
```bash
namd start
```

You should see:
```
[namd] tunnel active -> http://gabriel.namd.online
```

And it actually works from the real internet.

---

## Updating the server after code changes

```bash
make deploy
```

This rebuilds the Linux binary and uploads it, then restarts the service. Zero downtime from the client's perspective — yamux reconnects automatically.

---

## Viewing server logs

```bash
make logs
```

Or directly:
```bash
ssh root@YOUR_VPS_IP "journalctl -u namd-server -f"
```

---

## Monitoring

Check if namd-server is running:
```bash
ssh root@YOUR_VPS_IP "systemctl status namd-server"
```

Check active tunnels (future dashboard feature):
```bash
curl http://YOUR_VPS_IP:8080/health
```