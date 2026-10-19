#!/usr/bin/env bash
# Installs venomscanner so you can run it from anywhere as: venomscanner
set -e
SRC="$(cd "$(dirname "$0")" && pwd)/venomscanner.sh"
[[ -f $SRC ]] || { echo "venomscanner.sh not found next to install.sh"; exit 1; }
if [[ $EUID -ne 0 ]]; then SUDO=sudo; else SUDO=""; fi
$SUDO install -m 755 "$SRC" /usr/local/bin/venomscanner
echo "[+] Installed: $(command -v venomscanner)"
echo "[+] Try: venomscanner -h"
