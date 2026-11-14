#!/bin/bash
# End-to-end test of the app updating itself (macOS): a real app bundle, a local update
# server, real signed archives. It uses a THROWAWAY key (never the release key) and a test
# build of the app (`update-test`, debug), installed in a temporary folder. It never touches
# this Mac's GimmeCores, its login item or its background service, and checks that at the end.
#
#   scripts/test-self-update.sh
#
# Each case installs a fresh copy of version N, offers it an update and checks what happened:
# only a correctly signed, newer GimmeCores with nothing but plain files is installed.
set -eo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
[ "$(uname)" = Darwin ] || { echo "macOS only" >&2; exit 1; }
export PATH="$HOME/.cargo/bin:$PATH"

# With links resolved (/var is a link to /private/var): Tauri refuses an app whose own
# path contains a link.
W="$(cd "$(mktemp -d)" && pwd -P)"
SERVER=""
cleanup() {
  if [ -n "$SERVER" ]; then kill "$SERVER" 2>/dev/null || true; wait "$SERVER" 2>/dev/null || true; fi
  rm -rf "$W"
}
trap cleanup EXIT

LABEL=dev.gimmecores.gmcd
LOGIN="$HOME/Library/LaunchAgents/$LABEL.plist"
service_state() {
  if [ -f "$LOGIN" ]; then shasum "$LOGIN"; else echo "no login item"; fi
  launchctl print "gui/$(id -u)/$LABEL" 2>/dev/null | grep -E '^\s*pid = ' || echo "not running"
}
BEFORE="$(service_state)"

echo "== Building a test app (debug, update-test) in a temporary folder"
GMC_OUT="$W/build" GMC_PROFILE=debug GMC_DESKTOP_FEATURES=update-test GMC_NO_DMG=1 \
  packaging/macos/build-app.sh >"$W/build.log" 2>&1 || { cat "$W/build.log"; exit 1; }
cargo build -q --locked -p gimmecores-release --example sign-for-tests
SIGNER="$ROOT/target/debug/examples/sign-for-tests"
APP="$W/build/GimmeCores.app"
version_of() { plutil -extract CFBundleShortVersionString raw "$1/Contents/Info.plist"; }
CUR="$(version_of "$APP")"
NEXT="$(echo "$CUR" | awk -F. '{print $1"."$2"."$3+1}')"
LATER="$(echo "$CUR" | awk -F. '{print $1"."$2"."$3+2}')"
echo "   installed copies are $CUR; updates offer $NEXT"

"$SIGNER" keygen "$W/key"
"$SIGNER" keygen "$W/other-key"
PUB="$(cat "$W/key/test.pub.b64")"

# pack <version in Info.plist> <archive> [link]: the test app as that version.
pack() {
  local d="$W/pack"
  rm -rf "$d"; mkdir -p "$d"
  ditto "$APP" "$d/GimmeCores.app"
  local plist="$d/GimmeCores.app/Contents/Info.plist"
  plutil -replace CFBundleShortVersionString -string "$1" "$plist"
  plutil -replace CFBundleVersion -string "$1" "$plist"
  plutil -convert xml1 "$plist"
  if [ "${3:-}" = link ]; then ln -s "$HOME" "$d/GimmeCores.app/Contents/Resources/home"; fi
  codesign --force --deep --sign - "$d/GimmeCores.app" 2>/dev/null || true
  COPYFILE_DISABLE=1 tar --no-xattrs --no-mac-metadata --no-acls --no-fflags \
    --uid 0 --gid 0 --uname root --gname wheel -C "$d" -czf "$2" GimmeCores.app
  rm -rf "$d"
}

SRV="$W/srv"
mkdir -p "$SRV" "$W/home"
PORT="$(python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
BASE="http://127.0.0.1:$PORT"
python3 -I -m http.server "$PORT" --bind 127.0.0.1 --directory "$SRV" >/dev/null 2>&1 &
SERVER=$!
for _ in $(seq 1 50); do curl -s -o /dev/null "$BASE/" && break; sleep 0.1; done

# offer <manifest> <archive> <version announced> <key dir> [version signed]
offer() {
  "$SIGNER" sign "$4" "${5:-$3}" "$SRV/$2"
  "$SIGNER" manifest "$3" "${URL:-$BASE/$2}" "$SRV/$2.sig" "$SRV/$1"
}

FAILED=0
# attempt <name> <manifest> <expected words in the result> [public key]
attempt() {
  local name="$1" manifest="$2" expect="$3" key="${4-$PUB}"
  rm -rf "$W/inst" "$W/result"; mkdir -p "$W/inst"
  ditto "$APP" "$W/inst/GimmeCores.app"
  GMC_HOME="$W/home" GMC_UPDATE_TEST_RUN=1 GMC_UPDATE_TEST_RESULT="$W/result" \
    GMC_UPDATE_TEST_ENDPOINT="$BASE/$manifest" GMC_UPDATE_TEST_PUBKEY="$key" \
    "$W/inst/GimmeCores.app/Contents/MacOS/gimmecores-desktop" >"$W/app.log" 2>&1 &
  local pid=$! i
  for i in $(seq 1 240); do kill -0 "$pid" 2>/dev/null || break; sleep 0.25; done
  if kill "$pid" 2>/dev/null; then
    echo "FAIL $name: the app did not finish"; FAILED=1; return
  fi
  local result now
  result="$(cat "$W/result" 2>/dev/null || echo "no result")"
  now="$(version_of "$W/inst/GimmeCores.app" 2>/dev/null || echo "app missing")"
  case "$result" in
    *"$expect"*) ;;
    *) echo "FAIL $name: expected \"$expect\", got: $result"; FAILED=1; return ;;
  esac
  if [ "$expect" = "installed $NEXT" ]; then
    if [ "$now" != "$NEXT" ] || ! codesign --verify --deep --strict "$W/inst/GimmeCores.app" 2>/dev/null \
      || ! [ -x "$W/inst/GimmeCores.app/Contents/MacOS/gmcd" ]; then
      echo "FAIL $name: the installed app is $now, or broken"; FAILED=1; return
    fi
    # Not marked as downloaded, so Gatekeeper does not block the updated app again.
    if xattr -r "$W/inst/GimmeCores.app" 2>/dev/null | grep -q com.apple.quarantine; then
      echo "FAIL $name: the updated app is quarantined"; FAILED=1; return
    fi
  elif [ "$now" != "$CUR" ]; then
    echo "FAIL $name: refused, yet the app changed to $now"; FAILED=1; return
  fi
  echo "ok   $name: $(echo "$result" | cut -c1-110)"
}

echo "== Updating"
pack "$NEXT" "$SRV/next.tar.gz"
offer good.json next.tar.gz "$NEXT" "$W/key"
attempt "a newer version, signed with the update key, is installed" good.json "installed $NEXT"

cp "$SRV/next.tar.gz" "$SRV/other.tar.gz"
offer other-key.json other.tar.gz "$NEXT" "$W/other-key"
attempt "signed with another key: refused" other-key.json "not signed by GimmeCores"

cp "$SRV/next.tar.gz" "$SRV/tampered.tar.gz"
offer tampered.json tampered.tar.gz "$NEXT" "$W/key"
printf 'x' >>"$SRV/tampered.tar.gz"
attempt "changed after signing: refused" tampered.json "not signed by GimmeCores"

cp "$SRV/next.tar.gz" "$SRV/relabelled.tar.gz"
offer relabelled.json relabelled.tar.gz "$LATER" "$W/key" "$NEXT"
attempt "signed for $NEXT, announced as $LATER: refused" relabelled.json "not signed by GimmeCores"

cp "$SRV/next.tar.gz" "$SRV/inner.tar.gz"
offer inner.json inner.tar.gz "$LATER" "$W/key"
attempt "signed and announced as $LATER, holds $NEXT: refused" inner.json "holds version $NEXT"

cp "$SRV/next.tar.gz" "$SRV/unversioned.tar.gz"
"$SIGNER" sign-unversioned "$W/key" "$SRV/unversioned.tar.gz"
"$SIGNER" manifest "$NEXT" "$BASE/unversioned.tar.gz" "$SRV/unversioned.tar.gz.sig" "$SRV/unversioned.json"
attempt "signed without a version (could be replayed as any): refused" unversioned.json "not signed by GimmeCores"

pack "$CUR" "$SRV/same.tar.gz"
offer same.json same.tar.gz "$CUR" "$W/key"
attempt "the installed version again (a replay): not offered" same.json "no update offered"

pack "$NEXT" "$SRV/link.tar.gz" link
offer link.json link.tar.gz "$NEXT" "$W/key"
attempt "holds a link to outside the app: refused" link.json "link or special file"

URL="http://localhost:$PORT/next.tar.gz" offer elsewhere.json next.tar.gz "$NEXT" "$W/key"
attempt "downloaded from anywhere but the release files: refused" elsewhere.json "not hosted where GimmeCores releases are"

attempt "a copy built without a key: cannot update" good.json "no test key" ""

AFTER="$(service_state)"
if [ "$BEFORE" != "$AFTER" ]; then
  echo "FAIL this Mac's GimmeCores service or login item changed:"; echo "$BEFORE"; echo "$AFTER"; FAILED=1
else
  echo "ok   this Mac's GimmeCores service and login item are untouched"
fi
[ "$FAILED" = 0 ] && echo "== All self-update checks passed" || { echo "== Self-update checks FAILED"; exit 1; }
