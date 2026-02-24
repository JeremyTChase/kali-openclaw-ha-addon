#!/usr/bin/env bash
set -euo pipefail

# ---- Read add-on options ----
OPTIONS_FILE="/data/options.json"
PORT=$(jq -r '.port // 18790' "$OPTIONS_FILE")
VERBOSE=$(jq -r '.verbose // false' "$OPTIONS_FILE")
REPO_URL=$(jq -r '.repo_url // "https://github.com/openclaw/openclaw.git"' "$OPTIONS_FILE")
BRANCH=$(jq -r '.branch // ""' "$OPTIONS_FILE")
GITHUB_TOKEN=$(jq -r '.github_token // ""' "$OPTIONS_FILE")
SSH_PORT=$(jq -r '.ssh_port // 2223' "$OPTIONS_FILE")
SSH_KEYS=$(jq -r '.ssh_authorized_keys // ""' "$OPTIONS_FILE")

# ---- Persistent directories ----
PERSIST="/config/kali-openclaw"
STATE_DIR="${PERSIST}/.openclaw"
WORKSPACE="${PERSIST}/workspace"

mkdir -p "${STATE_DIR}" "${STATE_DIR}/cron" \
         "${WORKSPACE}/skills" "${WORKSPACE}/scripts" "${WORKSPACE}/data" \
         "${PERSIST}/.config" "${PERSIST}/.ssh" "${PERSIST}/.npm" \
         "/tmp/openclaw"

# Symlink npm cache to persistent storage
ln -sfn "${PERSIST}/.npm" /root/.npm 2>/dev/null || true

# ---- SSH setup (key-only auth) ----
mkdir -p /var/run/sshd /root/.ssh
chmod 700 /root/.ssh

if [ -n "$SSH_KEYS" ]; then
  echo "$SSH_KEYS" > /root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys
fi

# Generate persistent host keys
if [ ! -f "${PERSIST}/.ssh/ssh_host_ed25519_key" ]; then
  ssh-keygen -t ed25519 -f "${PERSIST}/.ssh/ssh_host_ed25519_key" -N "" -q
fi
cp "${PERSIST}/.ssh/ssh_host_ed25519_key"* /etc/ssh/

# Harden sshd: key-only authentication
sed -i "s/^#\?Port .*/Port ${SSH_PORT}/" /etc/ssh/sshd_config
sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#\?PermitEmptyPasswords .*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sed -i 's/^#\?ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#\?KbdInteractiveAuthentication .*/KbdInteractiveAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#\?PubkeyAuthentication .*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#\?UsePAM .*/UsePAM no/' /etc/ssh/sshd_config

/usr/sbin/sshd
echo "[kali-openclaw] SSH listening on port ${SSH_PORT} (key-only auth)"

# ---- Strip file capabilities (HA containers lack CAP_NET_RAW in bounding set) ----
# Without this, binaries with file caps (nmap, tcpdump) refuse to execute.
echo "[kali-openclaw] Stripping file capabilities from Kali binaries..."
for bin in /usr/lib/nmap/nmap /usr/bin/tcpdump /usr/sbin/tcpdump; do
  [ -f "$bin" ] && setcap -r "$bin" 2>/dev/null && echo "  stripped: $bin" || true
done

# ---- Clone / update OpenClaw ----
OPENCLAW_DIR="/opt/openclaw"
if [ -n "$GITHUB_TOKEN" ]; then
  CLONE_URL=$(echo "$REPO_URL" | sed "s|https://|https://${GITHUB_TOKEN}@|")
else
  CLONE_URL="$REPO_URL"
fi

if [ ! -d "${OPENCLAW_DIR}/.git" ]; then
  echo "[kali-openclaw] Cloning OpenClaw..."
  git clone ${BRANCH:+--branch "$BRANCH"} "$CLONE_URL" "$OPENCLAW_DIR"
else
  echo "[kali-openclaw] Updating OpenClaw..."
  cd "$OPENCLAW_DIR"
  git fetch origin
  git reset --hard "origin/${BRANCH:-main}"
fi

# ---- Install / build ----
cd "$OPENCLAW_DIR"
pnpm install --frozen-lockfile 2>/dev/null || pnpm install
echo "[kali-openclaw] Building gateway..."
pnpm build

# Build UI if present
if [ -d "ui" ] && [ ! -d "ui/node_modules" ]; then
  pnpm ui:install 2>/dev/null || true
fi
if [ -d "ui" ]; then
  pnpm ui:build 2>/dev/null || true
fi

# ---- Create openclaw wrapper ----
BINDIR="${PERSIST}/bin"
mkdir -p "$BINDIR"
cat > "${BINDIR}/openclaw" <<'EOF_WRAPPER'
#!/usr/bin/env bash
exec node "/opt/openclaw/openclaw.mjs" "$@"
EOF_WRAPPER
chmod +x "${BINDIR}/openclaw"
export PATH="${BINDIR}:${PATH}"

# ---- Initialize config if first run ----
CONFIG_FILE="${STATE_DIR}/openclaw.json"
if [ ! -f "$CONFIG_FILE" ]; then
  echo "[kali-openclaw] No config found — creating placeholder..."
  cat > "$CONFIG_FILE" << 'DEFAULTCFG'
{
  "gateway": {
    "port": 18790,
    "controlUi": {
      "dangerouslyAllowHostHeaderOriginFallback": true
    }
  },
  "skills": {"load": {"extraDirs": ["/config/kali-openclaw/workspace/skills"]}},
  "tools": {"exec": {"security": "full"}}
}
DEFAULTCFG
fi

# Ensure controlUi setting exists (may be missing from older configs)
if ! jq -e '.gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback' "$CONFIG_FILE" >/dev/null 2>&1; then
  echo "[kali-openclaw] Patching config: adding controlUi fallback..."
  jq '.gateway.controlUi = {"dangerouslyAllowHostHeaderOriginFallback": true}' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" \
    && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
fi

# ---- .env file ----
ENV_FILE="${STATE_DIR}/.env"
if [ ! -f "$ENV_FILE" ]; then
  touch "$ENV_FILE"
  chmod 600 "$ENV_FILE"
fi

# Generate gateway tokens if missing
if ! grep -q 'OPENCLAW_GATEWAY_TOKEN' "$ENV_FILE" 2>/dev/null; then
  echo "OPENCLAW_GATEWAY_TOKEN=$(openssl rand -hex 32)" >> "$ENV_FILE"
  echo "OPENCLAW_GATEWAY_REMOTE_TOKEN=$(openssl rand -hex 32)" >> "$ENV_FILE"
fi

# ---- Decompress rockyou.txt if needed ----
if [ -f /usr/share/wordlists/rockyou.txt.gz ] && [ ! -f /usr/share/wordlists/rockyou.txt ]; then
  echo "[kali-openclaw] Decompressing rockyou.txt..."
  gunzip -k /usr/share/wordlists/rockyou.txt.gz
fi

# ---- Initialize Metasploit DB ----
echo "[kali-openclaw] Initializing Metasploit DB..."
msfdb init 2>/dev/null || true

# ---- Launch OpenClaw gateway ----
VERBOSE_FLAG=""
if [ "$VERBOSE" = "true" ]; then
  VERBOSE_FLAG="--verbose"
fi

export OPENCLAW_CONFIG_PATH="${CONFIG_FILE}"

ARGS=(gateway --allow-unconfigured --port "$PORT" --bind lan)
if [ "$VERBOSE" = "true" ]; then
  ARGS+=(--verbose)
fi

echo "[kali-openclaw] Starting OpenClaw gateway on port ${PORT}..."
exec openclaw "${ARGS[@]}"
