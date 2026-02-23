#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

VERSION="$(node -p "require('./package.json').version")"
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  arm64)
    ARCH_TAG="aarch64"
    ;;
  x86_64)
    ARCH_TAG="x64"
    ;;
  *)
    ARCH_TAG="$ARCH_RAW"
    ;;
esac

APP_BUNDLE="src-tauri/target/release/bundle/macos/Quantum Drop.app"
DMG_DIR="src-tauri/target/release/bundle/dmg"
DMG_PATH="$DMG_DIR/Quantum Drop_${VERSION}_${ARCH_TAG}.dmg"
STAGE_DIR="$DMG_DIR/stage"

echo "[build] tauri app bundle"
npx tauri build --bundles app

if [[ ! -d "$APP_BUNDLE" ]]; then
  echo "[error] app bundle not found: $APP_BUNDLE" >&2
  exit 1
fi

mkdir -p "$DMG_DIR"
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"
cp -R "$APP_BUNDLE" "$STAGE_DIR/"
ln -s /Applications "$STAGE_DIR/Applications"
rm -f "$DMG_DIR"/Quantum\ Drop_*.dmg
rm -f "$DMG_PATH"

echo "[build] dmg"
hdiutil create -volname "Quantum Drop" -srcfolder "$STAGE_DIR" -ov -format UDZO "$DMG_PATH" >/dev/null

rm -rf "$STAGE_DIR"
echo "[ok] DMG: $DMG_PATH"
