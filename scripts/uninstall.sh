#!/usr/bin/env bash
# Remove a script-installed blackhole-sec.
# Your vault is left alone (it lives at ~/.blackhole/vault.db by default).
#
# One-liner:
#   curl -fsSL https://raw.githubusercontent.com/Satin-networks/blackhole-sec/main/scripts/uninstall.sh | bash
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

rm -rf "$INSTALL_DIR"
for name in blackhole blackhole-sec; do
  link="$BIN_DIR/$name"
  if [ -L "$link" ]; then
    rm -f "$link"
  fi
done

echo "removed. Your vault (if any) is still at ~/.blackhole/vault.db"
