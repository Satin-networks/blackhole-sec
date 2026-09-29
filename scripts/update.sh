#!/usr/bin/env bash
# Upgrade a script-installed blackhole-sec to the latest release.
#
# One-liner:
#   curl -fsSL https://raw.githubusercontent.com/Satin-networks/blackhole-sec/main/scripts/update.sh | bash
#
# Same INSTALL_DIR knob as install.sh. (Or just run `blackhole upgrade`.)
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/share/blackhole-sec}"

if [ ! -x "$INSTALL_DIR/bin/python" ]; then
  echo "error: no install found at $INSTALL_DIR (run install.sh first)" >&2
  exit 1
fi

"$INSTALL_DIR/bin/python" -m pip install --upgrade blackhole-sec
"$INSTALL_DIR/bin/blackhole" --version
