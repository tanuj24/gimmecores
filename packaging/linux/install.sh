#!/bin/sh
# Installs GimmeCores for the current user on Linux:
#   - gmcd, gmc and gimmecores into ~/.local/bin
#   - a systemd user service for gmcd (started only with --enable)
#   - optionally (asks for sudo) the polkit policy that lets gmcd ask for your password before
#     approving anything; without it, approvals need `gmcd --no-presence` (no screen) instead
# Run from the repository after `cargo build --release`, or pass the folder holding the binaries.
set -eu
# Usage: install.sh [--enable] [folder-with-binaries]
BIN_SRC="$(dirname "$0")/../../target/release"
ENABLE=0
for a in "$@"; do
  case "$a" in
    --enable) ENABLE=1 ;;
    *) BIN_SRC="$a" ;;
  esac
done

mkdir -p "$HOME/.local/bin" "$HOME/.config/systemd/user"
for b in gmcd gmc gimmecores; do
  install -m 0755 "$BIN_SRC/$b" "$HOME/.local/bin/$b"
done
install -m 0644 "$(dirname "$0")/gmcd.service" "$HOME/.config/systemd/user/gmcd.service"
echo "Installed gmcd, gmc and gimmecores into ~/.local/bin"

if ! command -v bwrap >/dev/null 2>&1; then
  echo "Note: bubblewrap (bwrap) is not installed; the sandbox runtime needs it (e.g. apt install bubblewrap)."
fi

POLICY=/usr/share/polkit-1/actions/dev.gimmecores.policy
if [ ! -f "$POLICY" ]; then
  printf "Install the polkit policy so approvals ask for your password? (needs sudo) [y/N] "
  read -r ans || ans=n
  case "$ans" in
    y|Y) sudo install -m 0644 "$(dirname "$0")/dev.gimmecores.policy" "$POLICY" && echo "Policy installed." ;;
    *) echo "Skipped. On a machine with no screen, run gmcd with --no-presence instead." ;;
  esac
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl --user daemon-reload
  if [ "$ENABLE" = 1 ]; then
    systemctl --user enable --now gmcd.service
    echo "gmcd is running and starts at login (systemctl --user status gmcd)."
  else
    echo "Start gmcd now and at login with: systemctl --user enable --now gmcd"
  fi
fi
case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) echo "Add ~/.local/bin to your PATH to use gmc." ;; esac
