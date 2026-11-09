#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# GSD Core is an optional AI-coding workflow, not a Sentinel runtime dependency.
# Offer its official installer once; the user chooses runtime and install scope.
if [[ ! -f ".gsd-core-setup-asked" ]]; then
  if command -v npx >/dev/null 2>&1 && [[ -t 0 ]]; then
    echo
    echo "[Optional developer tooling] GSD Core adds AI-assisted spec-driven workflows."
    answer=""
    read -r -t 8 -p "Install GSD Core now? [Y/n; default Yes] " answer || true
    if [[ -z "$answer" || "$answer" =~ ^[Yy] ]]; then
      ./install_gsd_core.sh || echo "[GSD Core] Setup did not complete. Rerun ./install_gsd_core.sh to retry."
    else
      echo "[GSD Core] Skipped. Rerun ./install_gsd_core.sh whenever you are ready."
    fi
  else
    echo "[GSD Core] First-run prompt skipped (npx unavailable or no interactive terminal). Run ./install_gsd_core.sh later."
  fi
  touch ".gsd-core-setup-asked"
fi

if [[ -n "${VIRTUAL_ENV:-}" && -x "$VIRTUAL_ENV/bin/python" ]]; then
  PYTHON="$VIRTUAL_ENV/bin/python"
elif [[ -x ".venv/bin/python" ]]; then
  PYTHON=".venv/bin/python"
else
  echo "[setup] Creating an isolated .venv (no Tkinter or desktop toolkit needed)"
  python3 -m venv .venv
  PYTHON=".venv/bin/python"
fi

"$PYTHON" -m pip install -r requirements.txt
exec "$PYTHON" web_ui.py
