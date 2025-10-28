#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT_DIR"

if [ ! -d "node_modules" ]; then
  echo "Installing Node dependencies..."
  npm install
fi

exec npm run tauri:dev
