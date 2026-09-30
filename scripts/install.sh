#!/usr/bin/env bash
# Install blackhole-sec without touching pip yourself.
#
# One-liner (user install):
#   curl -fsSL https://raw.githubusercontent.com/Satin-networks/blackhole-sec/main/scripts/install.sh | bash
#
# System-wide (so `sudo blackhole ...` works too):
#   curl -fsSL https://raw.githubusercontent.com/Satin-networks/blackhole-sec/main/scripts/install.sh | sudo bash
#
# Knobs (env vars):
#   INSTALL_DIR  where the venv lives (default: ~/.local/share/blackhole-sec)
#   BIN_DIR      where the `blackhole` links go (default: ~/.local/bin)
#   VERSION      pin a release, e.g. 0.1.1 (default: latest from PyPI)
set -euo pipefail

if [ "$(id -u)" -eq 0 ]; then
  DEFAULT_INSTALL_DIR="/usr/local/share/blackhole-sec"
  DEFAULT_BIN_DIR="/usr/local/bin"
else
  DEFAULT_INSTALL_DIR="$HOME/.local/share/blackhole-sec"
  DEFAULT_BIN_DIR="$HOME/.local/bin"
fi
INSTALL_DIR="${INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"
BIN_DIR="${BIN_DIR:-$DEFAULT_BIN_DIR}"
VERSION="${VERSION:-}"

need() {
  command -v "$1" >/dev/null 2>&1 || { echo "error: missing '$1', please install it first" >&2; exit 1; }
}
need curl
need python3

python3 - <<'EOF'
import sys
if sys.version_info < (3, 11):
    sys.exit("error: python 3.11 or newer is required")
EOF

if [ -n "$VERSION" ]; then
  SPEC="blackhole-sec==$VERSION"
else
  SPEC="blackhole-sec"
fi

echo "creating venv at $INSTALL_DIR ..."
python3 -m venv "$INSTALL_DIR"
"$INSTALL_DIR/bin/python" -m pip install --quiet --upgrade pip
"$INSTALL_DIR/bin/python" -m pip install --quiet "$SPEC"

mkdir -p "$BIN_DIR"
ln -sf "$INSTALL_DIR/bin/blackhole" "$BIN_DIR/blackhole"
ln -sf "$INSTALL_DIR/bin/blackhole-sec" "$BIN_DIR/blackhole-sec"

echo "installed: $("$BIN_DIR/blackhole" --version)"
echo "try: blackhole --help"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "note: $BIN_DIR is not on your PATH yet. Add this to your shell rc:"; echo "  export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac
