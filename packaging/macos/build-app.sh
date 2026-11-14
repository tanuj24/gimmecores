#!/bin/bash
# Builds GimmeCores.app (desktop app + gmcd + gmc), its update archive GimmeCores.app.tar.gz
# and the disk image GimmeCores.dmg (drag the app onto the Applications shortcut).
#
#   GMC_OUT=<dir>        where to put them (default: dist). Only these three are replaced.
#   GMC_NO_DMG=1         skip the disk image (the Homebrew formula installs the .app directly).
#   GMC_RELEASE=1        a release: refuses to build without the update key's public half
#                        (packaging/release/update-key.pub), so no release ships an app that
#                        can never update itself, and refuses test-only options.
#   GMC_PROFILE=debug    tests only: debug builds (scripts/test-self-update.sh).
#   GMC_DESKTOP_FEATURES tests only: e.g. update-test (never in a shipped build; CI checks).
#
# Signing: ad-hoc by default (runs on this Mac; other Macs will warn). With a Developer ID,
# set GMC_SIGN_ID="Developer ID Application: …" to sign with the hardened runtime;
# notarization is a separate step (xcrun notarytool) once an Apple account is set up.
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT="$PWD"
OUT="${GMC_OUT:-dist}"
PROFILE="${GMC_PROFILE:-release}"
FEATURES="${GMC_DESKTOP_FEATURES:-}"
# A configuration merged in from the environment would change what the app trusts.
unset TAURI_CONFIG

if [ -n "${GMC_RELEASE:-}" ]; then
  if [ "$PROFILE" != release ] || [ -n "$FEATURES" ]; then
    echo "error: GMC_PROFILE and GMC_DESKTOP_FEATURES are for tests, not releases" >&2
    exit 1
  fi
  if ! [ -s packaging/release/update-key.pub ]; then
    echo "error: packaging/release/update-key.pub is missing: the app could never update itself (docs/RELEASING.md)" >&2
    exit 1
  fi
fi

case "$PROFILE" in
  release) OPT=--release ;;
  debug) OPT= ;;
  *) echo "error: GMC_PROFILE must be release or debug" >&2; exit 1 ;;
esac
cargo build $OPT --locked -p gimmecores-cli
(cd apps/desktop && CARGO_TARGET_DIR="$ROOT/target" cargo build $OPT --locked ${FEATURES:+--features "$FEATURES"})
BIN="target/$PROFILE"

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' apps/desktop/Cargo.toml | head -1)"
APP="$OUT/GimmeCores.app"
mkdir -p "$OUT"
rm -rf "$APP" "$OUT/GimmeCores.app.tar.gz" "$OUT/GimmeCores.dmg"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN/gimmecores-desktop" "$BIN/gmcd" "$BIN/gmc" "$BIN/gimmecores" "$APP/Contents/MacOS/"
cp apps/desktop/icons/icon.icns "$APP/Contents/Resources/icon.icns"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>GimmeCores</string>
  <key>CFBundleDisplayName</key><string>GimmeCores</string>
  <key>CFBundleIdentifier</key><string>dev.gimmecores.desktop</string>
  <key>CFBundleVersion</key><string>${VERSION}</string>
  <key>CFBundleShortVersionString</key><string>${VERSION}</string>
  <key>CFBundleExecutable</key><string>gimmecores-desktop</string>
  <key>CFBundleIconFile</key><string>icon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.developer-tools</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST
plutil -lint "$APP/Contents/Info.plist"

if [ -n "${GMC_SIGN_ID:-}" ]; then
  for b in gmcd gmc gimmecores gimmecores-desktop; do
    codesign --force --options runtime --timestamp --sign "$GMC_SIGN_ID" "$APP/Contents/MacOS/$b"
  done
  codesign --force --options runtime --timestamp --sign "$GMC_SIGN_ID" "$APP"
else
  codesign --force --deep --sign - "$APP"
fi
codesign --verify --deep --strict "$APP"

if [ -n "${GMC_RELEASE:-}" ]; then
  # The shipped app trusts the committed update key, and is not a test build.
  grep -qF "$(tr -d '[:space:]' < packaging/release/update-key.pub)" "$APP/Contents/MacOS/gimmecores-desktop" \
    || { echo "error: the app was not built with packaging/release/update-key.pub" >&2; exit 1; }
  if grep -q GMC_UPDATE_TEST "$APP/Contents/MacOS/gimmecores-desktop"; then
    echo "error: the app is a test build (update-test)" >&2; exit 1
  fi
fi

# The update archive: GimmeCores.app at its root and nothing else. No macOS metadata files
# (._*), extended attributes or the builder's user name (the app refuses anything but plain
# files and folders inside GimmeCores.app: crates/gimmecores-bundle).
COPYFILE_DISABLE=1 tar --no-xattrs --no-mac-metadata --no-acls --no-fflags \
  --uid 0 --gid 0 --uname root --gname wheel \
  -C "$OUT" -czf "$OUT/GimmeCores.app.tar.gz" GimmeCores.app

if [ -n "${GMC_NO_DMG:-}" ]; then
  echo "Built $APP and $OUT/GimmeCores.app.tar.gz (version $VERSION)"
  exit 0
fi
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
ditto "$APP" "$STAGE/GimmeCores.app"
ln -s /Applications "$STAGE/Applications"
hdiutil create -quiet -volname GimmeCores -srcfolder "$STAGE" -ov -format UDZO "$OUT/GimmeCores.dmg"
echo "Built $APP, $OUT/GimmeCores.app.tar.gz and $OUT/GimmeCores.dmg (version $VERSION)"
