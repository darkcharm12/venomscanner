#!/usr/bin/env bash
# Installs VenomScanner (launcher + Python engine + Bash engine).
#   ./install.sh              install
#   ./install.sh --uninstall  remove
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
LIB=/usr/local/lib/venomscanner
BIN=/usr/local/bin/venomscanner
if [[ $EUID -ne 0 ]]; then SUDO=sudo; else SUDO=""; fi

if [[ ${1:-} == --uninstall ]]; then
    $SUDO rm -f "$BIN"
    $SUDO rm -rf "$LIB"
    echo "[+] VenomScanner removed"
    exit 0
fi

for f in venomscanner venomscanner.sh venomscanner.py; do
    [[ -f $HERE/$f ]] || { echo "[x] $f not found next to install.sh"; exit 1; }
done

$SUDO mkdir -p "$LIB"
$SUDO install -m 755 "$HERE/venomscanner" "$HERE/venomscanner.sh" "$HERE/venomscanner.py" "$LIB/"
$SUDO rm -f "$BIN"                       # also replaces an older single-file install
$SUDO ln -s "$LIB/venomscanner" "$BIN"

echo "[+] Installed to $LIB"
echo "[+] Command: $(command -v venomscanner || echo "$BIN")"
echo "[+] Try: venomscanner -h"
