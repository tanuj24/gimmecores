#!/bin/bash
# Builds the Windows installer, dist/GimmeCores-<version>-x64-setup.exe, on a Mac or Linux:
# the programs cross-compiled for Windows x64 (MinGW, in Docker: no Microsoft SDK licence) and
# packed with NSIS. They also run on Windows on ARM (Windows' x64 emulation). Unsigned for now:
# Windows SmartScreen asks once ("More info" > "Run anyway").
#
#   packaging/windows/build-installer.sh            GMC_OUT=<dir> to put it elsewhere
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT="$PWD"
OUT="${GMC_OUT:-dist}"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' apps/desktop/Cargo.toml | head -1)"
TARGET=x86_64-pc-windows-gnu

docker buildx build --builder "$(docker context show)" --load -q -t gmc-windows-cross \
  -f scripts/ci/Dockerfile.windows scripts/ci >/dev/null
STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
# Microsoft's WebView2 loader, signed and redistributable, from the webview2-com-sys crate the
# app builds with (MinGW builds load it at run time; Microsoft's toolchain links it in).
LOADER="$(ls -d "${CARGO_HOME:-$HOME/.cargo}"/registry/src/*/webview2-com-sys-*/x64/WebView2Loader.dll 2>/dev/null | sort -V | tail -1)"
[ -f "$LOADER" ] || { echo "error: WebView2Loader.dll not found (build apps/desktop once first)" >&2; exit 1; }
cp "$LOADER" "$STAGE/"
cp LICENSE "$STAGE/LICENSE"
cp apps/desktop/icons/icon.ico "$STAGE/icon.ico"

docker run --rm -v "$ROOT":/src -v gmc-win-target:/target -v gmc-win-cargo:/usr/local/cargo/registry \
  -v "$STAGE":/stage gmc-windows-cross sh -c "
    set -e
    cargo build -q --locked --release -p gimmecores-cli --bins --target $TARGET
    (cd apps/desktop && cargo build -q --locked --release --target $TARGET)
    cp /target/$TARGET/release/gmc.exe /target/$TARGET/release/gmcd.exe \
       /target/$TARGET/release/gimmecores.exe /target/$TARGET/release/gimmecores-desktop.exe /stage/
    makensis -V2 -DVERSION=$VERSION -DSRC=/stage -DICON=/stage/icon.ico \
      -DOUTFILE=/stage/GimmeCores-$VERSION-x64-setup.exe /src/packaging/windows/gimmecores.nsi"
mkdir -p "$OUT"
cp "$STAGE/GimmeCores-$VERSION-x64-setup.exe" "$OUT/"
echo "Built $OUT/GimmeCores-$VERSION-x64-setup.exe"
