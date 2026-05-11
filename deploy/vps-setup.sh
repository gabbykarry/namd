#!/bin/bash
# =============================================================================
# namd VPS hardening script
# Run this ONCE on a fresh Hetzner/DigitalOcean/Contabo Ubuntu 22.04 VPS
# as root immediately after provisioning.
#
# What this does:
#   1. Updates the system
#   2. Creates a non-root user to run namd-server
#   3. Hardens SSH (disable root login, disable password auth)
#   4. Configures ufw firewall — blocks everything except what namd needs
#   5. Installs fail2ban — auto-bans IPs that fail SSH too many times
#   6. Installs certbot — gets Let's Encrypt SSL certificate
#   7. Sets up namd-server as a systemd service
#
# Usage:
#   scp deploy/vps-setup.sh root@YOUR_VPS_IP:/root/
#   ssh root@YOUR_VPS_IP "bash /root/vps-setup.sh YOUR_DOMAIN YOUR_EMAIL"
#
# Example:
#   bash vps-setup.sh namd.online gabriel@example.com
# =============================================================================

set -e  # exit immediately if any command fails

DOMAIN=${1:-"namd.online"}
EMAIL=${2:-"admin@namd.online"}
NAMD_USER="namd"

echo "============================================="
echo "  namd VPS hardening script"
echo "  Domain: $DOMAIN"
echo "  Email:  $EMAIL"
echo "============================================="
echo ""

# ── Step 1: System update ─────────────────────────────────────────────────────
echo "→ Step 1: Updating system packages..."
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq \
    ufw \
    fail2ban \
    curl \
    wget \
    unzip \
    certbot \
    jq
echo "✓ System updated"

# ── Step 2: Create non-root user ──────────────────────────────────────────────
echo "→ Step 2: Creating namd system user..."
if ! id "$NAMD_USER" &>/dev/null; then
    # useradd --system = no login shell, no home directory creation by default
    # --create-home = create /home/namd for config storage
    # --shell /bin/false = cannot log in as this user
    useradd --system --create-home --shell /bin/false $NAMD_USER
    echo "✓ User '$NAMD_USER' created"
else
    echo "  User '$NAMD_USER' already exists — skipping"
fi

# ── Step 3: SSH hardening ──────────────────────────────────────────────────────
echo "→ Step 3: Hardening SSH..."

# Back up the original config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Apply hardening settings
cat > /etc/ssh/sshd_config.d/namd-hardening.conf << 'SSHEOF'
# namd SSH hardening
# Disable root login — use the namd user or a dedicated admin user instead
PermitRootLogin no

# Disable password authentication — SSH keys only
# Make sure you have your SSH public key in ~/.ssh/authorized_keys BEFORE
# running this script, or you will be locked out.
PasswordAuthentication no

# Disable empty passwords
PermitEmptyPasswords no

# Max login attempts before disconnecting
MaxAuthTries 3

# Disconnect idle sessions after 10 minutes
ClientAliveInterval 300
ClientAliveCountMax 2

# Only allow specific users (optional — uncomment and set your username)
# AllowUsers yourusername
SSHEOF

# Restart SSH to apply changes.
# We use 'reload' not 'restart' — reload keeps existing sessions alive.
# If you restart and your config is wrong, you stay connected.
systemctl reload sshd
echo "✓ SSH hardened (root login disabled, password auth disabled)"
echo "  WARNING: Make sure your SSH public key is in authorized_keys"

# ── Step 4: UFW Firewall ──────────────────────────────────────────────────────
echo "→ Step 4: Configuring UFW firewall..."

# Reset to defaults — clean slate
ufw --force reset

# Default policies
# deny incoming = block all unsolicited inbound connections
# allow outgoing = server can initiate outbound connections freely
ufw default deny incoming
ufw default allow outgoing

# Allow SSH — CRITICAL: do this before enabling ufw or you lock yourself out
ufw allow 22/tcp comment "SSH"

# namd ports
ufw allow 80/tcp   comment "HTTP (Caddy/nginx → namd :8080)"
ufw allow 443/tcp  comment "HTTPS (Caddy/nginx)"
ufw allow 8080/tcp comment "namd public HTTP"
ufw allow 9000/tcp comment "namd tunnel connections (TLS)"
ufw allow 9001/tcp comment "namd handoff broker"
ufw allow 9002/tcp comment "namd registration"

# Enable firewall
ufw --force enable
echo "✓ UFW firewall configured"
echo "  Open ports: 22, 80, 443, 8080, 9000, 9001, 9002"

# ── Step 5: Fail2ban ──────────────────────────────────────────────────────────
echo "→ Step 5: Configuring fail2ban..."

cat > /etc/fail2ban/jail.local << 'F2BEOF'
[DEFAULT]
# Ban IP for 1 hour after 5 failed attempts within 10 minutes
bantime  = 3600
findtime = 600
maxretry = 5

# Email alerts (optional — set your email)
# destemail = your@email.com
# sendername = Fail2Ban
# action = %(action_mwl)s

[sshd]
enabled = true
port    = ssh
logpath = %(sshd_log)s
backend = %(syslog_backend)s
maxretry = 3
bantime  = 86400  # 24 hours for SSH failures — be aggressive
F2BEOF

systemctl enable fail2ban
systemctl restart fail2ban
echo "✓ Fail2ban configured (3 SSH failures = 24h ban)"

# ── Step 6: Let's Encrypt SSL certificate ─────────────────────────────────────
echo "→ Step 6: Getting SSL certificate for $DOMAIN..."
echo "  (This requires $DOMAIN to point to this server's IP)"
echo "  If DNS is not set up yet, press Ctrl+C and run this step manually later:"
echo "  certbot certonly --standalone -d $DOMAIN -d *.$DOMAIN --email $EMAIL --agree-tos --non-interactive"
echo ""

# Try to get the certificate — continue if it fails (DNS may not be set up yet)
if certbot certonly \
    --standalone \
    --non-interactive \
    --agree-tos \
    --email "$EMAIL" \
    -d "$DOMAIN" \
    --pre-hook "systemctl stop namd-server || true" \
    --post-hook "systemctl start namd-server || true" 2>/dev/null; then
    echo "✓ SSL certificate obtained"
    echo "  Certificate: /etc/letsencrypt/live/$DOMAIN/fullchain.pem"
    echo "  Key:         /etc/letsencrypt/live/$DOMAIN/privkey.pem"
    CERT_FILE="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
    KEY_FILE="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
else
    echo "  SSL certificate skipped (DNS not set up yet)"
    echo "  Run this after pointing $DOMAIN to this server:"
    echo "  certbot certonly --standalone -d $DOMAIN --email $EMAIL --agree-tos"
    CERT_FILE=""
    KEY_FILE=""
fi

# ── Step 7: namd-server systemd service ──────────────────────────────────────
echo "→ Step 7: Installing namd-server systemd service..."

# Generate a strong random secret for signing handoff tokens.
NAMD_SECRET=$(openssl rand -hex 32)

cat > /etc/systemd/system/namd-server.service << SERVICEEOF
[Unit]
Description=namd tunnel server
Documentation=https://github.com/gabbykarry/namd
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$NAMD_USER
ExecStart=/usr/local/bin/namd-server
Restart=always
RestartSec=5s

# Security — server secret for signing handoff tokens
# Change this to a long random string in production
# Generated: $(date)
Environment=NAMD_SECRET=$NAMD_SECRET

# TLS — set these when your certificate is ready
Environment=NAMD_CERT=$CERT_FILE
Environment=NAMD_KEY=$KEY_FILE

# Limits
Environment=NAMD_MAX_STREAMS=100
Environment=NAMD_MAX_BODY_MB=10

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=namd-server

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/home/$NAMD_USER

[Install]
WantedBy=multi-user.target
SERVICEEOF

systemctl daemon-reload
systemctl enable namd-server
echo "✓ systemd service installed and enabled"
echo ""
echo "============================================="
echo "  Setup complete!"
echo "============================================="
echo ""
echo "Next steps:"
echo "  1. Upload the namd-server binary:"
echo "     make deploy-setup VPS_HOST=$(hostname -I | awk '{print $1}') VPS_USER=root"
echo ""
echo "  2. If DNS is not set up yet, point $DOMAIN to this server:"
echo "     IP address: $(hostname -I | awk '{print $1}')"
echo "     Add: A record  $DOMAIN → $(hostname -I | awk '{print $1}')"
echo "     Add: A record  *.$DOMAIN → $(hostname -I | awk '{print $1}')"
echo ""
echo "  3. After DNS propagates, get the SSL certificate:"
echo "     certbot certonly --standalone -d $DOMAIN --email $EMAIL --agree-tos"
echo ""
echo "  4. Edit /etc/systemd/system/namd-server.service"
echo "     Set NAMD_CERT and NAMD_KEY to the certificate paths"
echo "     Then: systemctl daemon-reload && systemctl restart namd-server"
echo ""
echo "  5. On your laptop, point namd at the real server:"
echo "     export NAMD_SERVER=$DOMAIN:9000"
echo "     namd start"
echo ""
echo "Generated NAMD_SECRET (already in the service file):"
echo "  $NAMD_SECRET"
echo "  Keep this safe — used to sign handoff tokens"