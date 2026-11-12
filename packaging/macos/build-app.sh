#!/bin/bash
# Builds dist/GimmeCores.app (desktop app + gmcd + gmc) and dist/GimmeCores.dmg.
#
# Signing: ad-hoc by default (runs on this Mac; other Macs will warn). With a Developer ID,
# set GMC_SIGN_ID="Developer ID Application: …" to sign with the hardened runtime;
# notarization is a separate step (xcrun notarytool) once an Apple account is set up.
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT="$PWD"

cargo build --release -p gimmecores-cli
(cd apps/desktop && CARGO_TARGET_DIR="$ROOT/target" cargo build --release)

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' apps/desktop/Cargo.toml | head -1)"
APP="dist/GimmeCores.app"
rm -rf dist
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp target/release/gimmecores-desktop target/release/gmcd target/release/gmc target/release/gimmecores "$APP/Contents/MacOS/"
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

hdiutil create -quiet -volname GimmeCores -srcfolder "$APP" -ov -format UDZO dist/GimmeCores.dmg
echo "Built $APP and dist/GimmeCores.dmg (version $VERSION)"
