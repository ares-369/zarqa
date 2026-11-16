#!/usr/bin/env bash
set -euo pipefail

# Bare-Linux installer for Zarqa (/opt/zarqa + systemd).
# Usage: sudo bash scripts/install.sh [EXTRAS]   (e.g. "all", "gemini,oidc", or "")
# Storage: SQLite by default (nothing else to install). For PostgreSQL:
#   sudo ZARQA_DATABASE=postgres ZARQA_DB_URL=postgresql://user:pass@host/db bash scripts/install.sh
# Run interactively without ZARQA_DATABASE and it asks.

DIR="${ZARQA_DIR:-/opt/zarqa}"
EXTRAS="${1:-}"
DATABASE="${ZARQA_DATABASE:-}"
if [ -z "$DATABASE" ] && [ -t 0 ] && [ ! -f "$DIR/config.yaml" ]; then
  echo "Storage:"
  echo "  1) SQLite      - default, nothing else to install, one machine"
  echo "  2) PostgreSQL  - an existing PostgreSQL server"
  read -r -p "Choose [1]: " choice
  [ "$choice" = "2" ] && DATABASE=postgres
fi
DATABASE="${DATABASE:-sqlite}"
if [ "$DATABASE" = "postgres" ]; then
  EXTRAS="${EXTRAS:+$EXTRAS,}postgres"
fi
SRC="$(cd "$(dirname "$0")/.." && pwd)"

id -u zarqa >/dev/null 2>&1 || useradd --system --home-dir "$DIR" --shell /usr/sbin/nologin zarqa
mkdir -p "$DIR/data"
python3 -m venv "$DIR/.venv"
"$DIR/.venv/bin/pip" install --upgrade pip
if [ -n "$EXTRAS" ]; then
  "$DIR/.venv/bin/pip" install "${SRC}[${EXTRAS}]"
else
  "$DIR/.venv/bin/pip" install "$SRC"
fi

if [ ! -f "$DIR/config.yaml" ]; then
  ZARQA_HOME="$DIR" "$DIR/.venv/bin/zarqa" init --database "$DATABASE" || \
    echo "PostgreSQL is not reachable yet: fix ZARQA_DB_URL in $DIR/.env, then run zarqa doctor"
fi

chown -R zarqa:zarqa "$DIR"
chmod 600 "$DIR/.env" 2>/dev/null || true

if command -v systemctl >/dev/null 2>&1 && [ -d /etc/systemd/system ]; then
  cp "$SRC/deploy/zarqa.service" /etc/systemd/system/zarqa.service
  systemctl daemon-reload
  echo "Installed systemd unit. Edit $DIR/config.yaml and $DIR/.env, then run:"
  echo "  sudo systemctl enable --now zarqa"
else
  echo "Installed into $DIR. Run: ZARQA_HOME=$DIR $DIR/.venv/bin/zarqa serve"
fi
