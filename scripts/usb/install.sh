#!/usr/bin/env bash
# One-shot KovanicaDAG node install — no git clone.
#   curl -sSfL https://raw.githubusercontent.com/KovanicaDAG/kovanica-node/main/scripts/install.sh | bash
# Optional: KOVANICA_HOME=~/kovanica-node  KOVANICA_PEERS=seed.kovanica.online:9000
#           bash scripts/install.sh --systemd
set -euo pipefail

HOME_DIR="${KOVANICA_HOME:-$HOME/kovanica-node}"
SEED="${KOVANICA_PEERS:-seed.kovanica.online:9000}"
SYSTEMD=0
for a in "$@"; do
  case "$a" in
    --systemd) SYSTEMD=1 ;;
    -h|--help)
      echo "usage: install.sh [--systemd]"
      echo "  installs a clone node into $HOME_DIR (override with KOVANICA_HOME)"
      exit 0
      ;;
  esac
done

need() { command -v "$1" >/dev/null 2>&1 || return 1; }

if need apt-get; then
  sudo apt-get update -y
  sudo apt-get install -y build-essential git pkg-config libssl-dev curl tar
elif need brew; then
  brew list curl >/dev/null 2>&1 || brew install curl
elif need dnf; then
  sudo dnf install -y gcc gcc-c++ make openssl-devel curl tar
fi

if ! need rustc || ! need cargo; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi
# shellcheck disable=SC1091
source "$HOME/.cargo/env" 2>/dev/null || true
export PATH="$HOME/.cargo/bin:$PATH"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
echo "downloading kovanica-node main (tarball, no git)…"
curl -sSfL https://github.com/KovanicaDAG/kovanica-node/archive/refs/heads/main.tar.gz \
  | tar -xz -C "$TMP"
SRC="$(find "$TMP" -maxdepth 1 -type d -name 'kovanica-node-*' | head -1)"
test -n "$SRC"

mkdir -p "$HOME_DIR/bin" "$HOME_DIR/data"
(cd "$SRC" && cargo build --release -p kovanica-node)
install -m 755 "$SRC/target/release/kovanica-node" "$HOME_DIR/bin/kovanica-node"

cat > "$HOME_DIR/run.sh" << EOF
#!/usr/bin/env bash
set -euo pipefail
export KOVANICA_LISTEN=0.0.0.0:9000
export KOVANICA_PEERS=${SEED}
export KOVANICA_MINE=0
export KOVANICA_MINE_SECS=120
export KOVANICA_FAUCET=0
export KOVANICA_TAP=0
export KOVANICA_POW=1
export KOVANICA_ALLOW_RESET=0
export KOVANICA_DATA="$HOME_DIR/data"
exec "$HOME_DIR/bin/kovanica-node" explorer 127.0.0.1:8080
EOF
chmod +x "$HOME_DIR/run.sh"

if [ "$SYSTEMD" = 1 ] && need systemctl; then
  mkdir -p "$HOME/.config/systemd/user"
  cat > "$HOME/.config/systemd/user/kovanica-clone.service" << EOF
[Unit]
Description=Kovanica DAG clone
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=KOVANICA_LISTEN=0.0.0.0:9000
Environment=KOVANICA_PEERS=${SEED}
Environment=KOVANICA_MINE=0
Environment=KOVANICA_MINE_SECS=120
Environment=KOVANICA_FAUCET=0
Environment=KOVANICA_POW=1
Environment=KOVANICA_DATA=${HOME_DIR}/data
ExecStart=${HOME_DIR}/bin/kovanica-node explorer 127.0.0.1:8080
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
EOF
  systemctl --user daemon-reload
  systemctl --user enable --now kovanica-clone.service
  loginctl enable-linger "$USER" 2>/dev/null || true
  echo "systemd user unit: kovanica-clone.service"
else
  echo "start: $HOME_DIR/run.sh"
fi

echo "binary: $HOME_DIR/bin/kovanica-node"
echo "check:  curl -s http://127.0.0.1:8080/api/head"
echo "live:   curl -s https://explorer.kovanica.online/api/head"
