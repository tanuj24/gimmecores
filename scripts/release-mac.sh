#!/bin/bash
# Signs and publishes the macOS app of a GimmeCores release, on the maintainer's Mac (the update
# key never leaves it; docs/RELEASING.md). Installed copies are offered the update only once the
# release is published, and this script publishes only when you type the version.
#
#   scripts/release-mac.sh <version> --key <secret key file> --notes <release notes file>
#
# The app comes from the release.yml run for the tag when its draft release holds one (its
# provenance is checked), and is built here from a clean checkout of the tag otherwise.
set -eo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
REPO=tanuj24/gimmecores
ARCHIVE_NAME=GimmeCores.app.tar.gz

die() { echo "error: $*" >&2; exit 1; }
VERSION="" KEY="" NOTES=""
while [ $# -gt 0 ]; do
  case "$1" in
    --key) KEY="$2"; shift 2 ;;
    --notes) NOTES="$2"; shift 2 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    -*) die "unknown option $1" ;;
    *) VERSION="$1"; shift ;;
  esac
done
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "give the version as 1.2.3 (no v)"
[ -n "$KEY" ] && [ -f "$KEY" ] || die "--key: the update key's secret file (gimmecores-update.key)"
[ -n "$NOTES" ] && [ -s "$NOTES" ] || die "--notes: a plain-text file with the release notes"
KEY="$(cd "$(dirname "$KEY")" && pwd -P)/$(basename "$KEY")"
case "$KEY" in "$ROOT"/*) die "keep the update key outside the repository" ;; esac
[ "$(stat -f %Lp "$KEY")" = 600 ] || die "the key file must be readable by you only: chmod 600 '$KEY'"
[ "$(uname -s)/$(uname -m)" = Darwin/arm64 ] || die "run this on an Apple silicon Mac"
command -v gh >/dev/null && gh auth status >/dev/null 2>&1 || die "gh must be installed and signed in"
export PATH="$HOME/.cargo/bin:$PATH"

TAG="v$VERSION"
echo "== Checking the tag $TAG"
git fetch -q origin main
LOCAL="$(git rev-parse -q --verify "refs/tags/$TAG^{commit}")" || die "no tag $TAG here (git fetch --tags)"
REMOTE="$(git ls-remote origin "refs/tags/$TAG^{}" | cut -f1)"
[ -n "$REMOTE" ] || REMOTE="$(git ls-remote origin "refs/tags/$TAG" | cut -f1)"
[ "$LOCAL" = "$REMOTE" ] || die "the tag $TAG is not the same commit here ($LOCAL) and on GitHub (${REMOTE:-missing})"
git merge-base --is-ancestor "$LOCAL" origin/main || die "$TAG is not on main"
AT_TAG="$(git show "$LOCAL:apps/desktop/Cargo.toml" | sed -n 's/^version = "\(.*\)"/\1/p' | head -1)"
[ "$AT_TAG" = "$VERSION" ] || die "apps/desktop/Cargo.toml at $TAG says $AT_TAG, not $VERSION"
W="$(cd "$(mktemp -d)" && pwd -P)"
trap 'git worktree remove --force "$W/src" >/dev/null 2>&1 || true; rm -rf "$W"' EXIT
git show "$LOCAL:packaging/release/update-key.pub" > "$W/update-key.pub" 2>/dev/null \
  || die "packaging/release/update-key.pub is missing at $TAG"
echo "   $TAG = $LOCAL, on main, version $VERSION"

mkdir -p "$W/out"
if gh release view "$TAG" -R "$REPO" --json assets -q '.assets[].name' 2>/dev/null | grep -qx "$ARCHIVE_NAME"; then
  echo "== Using the app GitHub built for $TAG; checking its provenance"
  gh release download "$TAG" -R "$REPO" -p "$ARCHIVE_NAME" -p GimmeCores.dmg -D "$W/out"
  for f in "$ARCHIVE_NAME" GimmeCores.dmg; do
    gh attestation verify "$W/out/$f" -R "$REPO" --deny-self-hosted-runners \
      --signer-workflow "$REPO/.github/workflows/release.yml" --source-ref "refs/tags/$TAG" >/dev/null \
      || die "$f has no valid provenance from release.yml at $TAG"
  done
  SOURCE="built by GitHub Actions (release.yml) from $TAG, provenance checked"
else
  echo "== Building the app here from a clean checkout of $TAG (takes a while)"
  git worktree add --detach -q "$W/src" "$LOCAL"
  (cd "$W/src" && GMC_RELEASE=1 GMC_OUT="$W/out" packaging/macos/build-app.sh) >"$W/build.log" 2>&1 \
    || { tail -30 "$W/build.log"; die "the build failed"; }
  git worktree remove --force "$W/src"
  rm -rf "$W/out/GimmeCores.app"
  SOURCE="built on this Mac from a clean checkout of $TAG"
fi
ARCHIVE="$W/out/$ARCHIVE_NAME"

echo "== Checking the app inside"
mkdir -p "$W/x"
/usr/bin/tar -xzf "$ARCHIVE" -C "$W/x"
BIN="$W/x/GimmeCores.app/Contents/MacOS/gimmecores-desktop"
grep -qF "$(cat "$W/update-key.pub")" "$BIN" || die "the app was not built with $TAG's update key"
! grep -q GMC_UPDATE_TEST "$BIN" || die "the app is a test build (update-test)"
[ "$(plutil -extract CFBundleShortVersionString raw "$W/x/GimmeCores.app/Contents/Info.plist")" = "$VERSION" ] \
  || die "the app's Info.plist is not version $VERSION"

echo "== Signing (type the update key's password)"
cargo build -q --locked --release -p gimmecores-release
REL="$ROOT/target/release/gmc-release"
"$REL" sign --key "$KEY" --version "$VERSION" "$ARCHIVE"
# As the installed apps will check it: the key built into them, then the archive's contents.
"$REL" verify --pubkey "$W/update-key.pub" --version "$VERSION" "$ARCHIVE" "$ARCHIVE.sig"
"$REL" manifest --version "$VERSION" --notes "$NOTES" --sig "$ARCHIVE.sig" --out "$W/out/latest.json" \
  --url "https://github.com/$REPO/releases/download/$TAG/$ARCHIVE_NAME"
(cd "$W/out" && shasum -a 256 GimmeCores.dmg "$ARCHIVE_NAME" "$ARCHIVE_NAME.sig" latest.json > SHA256SUMS-macos-app)

# The Homebrew cask points at this release's disk image.
DMG_SHA="$(shasum -a 256 "$W/out/GimmeCores.dmg" | cut -d' ' -f1)"
mkdir -p Casks
sed -e "s/@VERSION@/$VERSION/" -e "s/@SHA256@/$DMG_SHA/" packaging/homebrew/gimmecores.rb.in > Casks/gimmecores.rb

FILES=("$W/out/GimmeCores.dmg" "$ARCHIVE" "$ARCHIVE.sig" "$W/out/latest.json" "$W/out/SHA256SUMS-macos-app")
echo
echo "Release $TAG, macOS app $SOURCE:"
(cd "$W/out" && cat SHA256SUMS-macos-app)
read -r -p "Upload these to the $TAG release on GitHub (a draft until published)? [y/N] " ok
[ "$ok" = y ] || die "nothing uploaded"
if gh release view "$TAG" -R "$REPO" >/dev/null 2>&1; then
  gh release upload "$TAG" -R "$REPO" --clobber "${FILES[@]}"
else
  gh release create "$TAG" -R "$REPO" --draft --verify-tag --title "GimmeCores $TAG" --notes-file "$NOTES" "${FILES[@]}"
fi
echo
echo "Publishing makes every installed GimmeCores (in Applications) offer $VERSION when its user checks."
read -r -p "Type $VERSION to publish now, anything else to keep the draft: " ok
if [ "$ok" = "$VERSION" ]; then
  gh release edit "$TAG" -R "$REPO" --draft=false --latest
  echo "Published $TAG."
else
  echo "Kept as a draft: publish it on GitHub when ready."
fi
echo "Casks/gimmecores.rb now points at $TAG: commit it on v1 and merge it to main with a PR."
