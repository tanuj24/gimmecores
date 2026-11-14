#!/bin/bash
# Builds gmc and gmcd for Windows (cross-compiled here, x64; they run on Windows on ARM too),
# copies them into the test VM (scripts/windows/make-test-vm.sh) and runs the Windows checks
# there over SSH. Never touches this Mac's GimmeCores.
#
#   scripts/windows/test-windows.sh
set -eo pipefail
cd "$(dirname "$0")/../.."
ROOT="$PWD"
UTMCTL=/Applications/UTM.app/Contents/MacOS/utmctl
IP="${GMC_WINDOWS_VM:-$("$UTMCTL" ip-address "GimmeCores Windows" 2>/dev/null | head -1)}"
[ -n "$IP" ] || { echo "error: the test VM is not running (scripts/windows/make-test-vm.sh)" >&2; exit 1; }
SSH=(-i "$HOME/.ssh/gimmecores_vm" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=10)

echo "== Building gmc and gmcd for Windows"
docker buildx build --builder "$(docker context show)" --load -q -t gmc-windows-cross \
  -f scripts/ci/Dockerfile.windows scripts/ci >/dev/null
OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"' EXIT
docker run --rm -v "$ROOT":/src -v gmc-win-target:/target -v gmc-win-cargo:/usr/local/cargo/registry \
  -v "$OUT":/out gmc-windows-cross sh -c \
  'cargo build -q --locked --release -p gimmecores-cli --bins --target x86_64-pc-windows-gnu &&
   cp /target/x86_64-pc-windows-gnu/release/gmc.exe /target/x86_64-pc-windows-gnu/release/gmcd.exe /out/'

echo "== Copying them to the VM ($IP)"
ssh "${SSH[@]}" "tanuj@$IP" 'New-Item -ItemType Directory -Force C:\gmc | Out-Null'
scp -q "${SSH[@]}" "$OUT/gmc.exe" "$OUT/gmcd.exe" scripts/windows/local-api-checks.ps1 "tanuj@$IP:C:/gmc/"

echo "== Local API checks on Windows"
ssh "${SSH[@]}" "tanuj@$IP" 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\gmc\local-api-checks.ps1'
