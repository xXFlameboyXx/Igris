#!/usr/bin/env bash
# =============================================================================
# Igris Automated Uninstaller for Linux / macOS
# =============================================================================
set -euo pipefail

GLOBAL_BIN_DIR="${HOME}/.local/bin"
LAUNCHER_SCRIPT="$GLOBAL_BIN_DIR/igris"

echo "===================================================================="
echo "               Uninstalling Igris Global Launcher                    "
echo "===================================================================="

if [ -f "$LAUNCHER_SCRIPT" ]; then
    rm -f "$LAUNCHER_SCRIPT"
    echo "Removed launcher command: $LAUNCHER_SCRIPT"
fi

echo ""
echo "===================================================================="
echo "            Igris Global Launcher Uninstalled Successfully!         "
echo "===================================================================="
echo "Note: Your sample binaries, database records, notes, and analysis"
echo "artifacts in the repository directory have been preserved."
