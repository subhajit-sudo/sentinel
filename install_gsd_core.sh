#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if ! command -v node >/dev/null 2>&1 || ! command -v npx >/dev/null 2>&1; then
  echo "[GSD Core] Node.js 18+ and npm/npx are required. Install Node.js, then rerun this script." >&2
  exit 1
fi
node -e 'const major=Number(process.versions.node.split(".")[0]); if(major<18){console.error("[GSD Core] Node.js 18 or newer is required."); process.exit(1)}'
echo "[GSD Core] Starting the official interactive installer."
echo "Choose your AI coding runtime and local/global install scope when prompted."
exec npx --yes @opengsd/gsd-core@latest
