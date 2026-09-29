#!/usr/bin/env bash
# Remove a script-installed blackhole-sec.
# Your vault is left alone (it lives at ~/.blackhole/vault.db by default).
#
# One-liner:
#   curl -fsSL https://raw.githubusercontent.com/Satin-networks/blackhole-sec/main/scripts/uninstall.sh | bash
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/share/blackhole-sec}"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"

rm -rf "$INSTALL_DIR"
for name in blackhole blackhole-sec; do
  link="$BIN_DIR/$name"
  if [ -L "$link" ]; then
    rm -f "$link"
  fi
done

echo "removed. Your vault (if any) is still at ~/.blackhole/vault.db"
