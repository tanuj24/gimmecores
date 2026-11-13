#!/bin/bash
# Builds dist/gimmecores_<version>_<arch>.deb: the desktop app, gmcd, gmc and gimmecores, the
# polkit policy (approvals ask for your password), a systemd user unit (not enabled: the app's
# "Start GimmeCores" or `systemctl --user enable --now gmcd` turns it on) and a menu entry.
# Lending stays off after install, as everywhere.
#
# Needs: Rust, dpkg-deb, and Tauri's Linux build libraries
#   (apt install libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev).
# GMC_NO_DESKTOP=1 packages only the command-line tools and the daemon (no GUI libraries).
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT="$PWD"

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' crates/gimmecores-cli/Cargo.toml | head -1)"
ARCH="$(dpkg --print-architecture)"
cargo build --release --locked -p gimmecores-cli
if [ -z "${GMC_NO_DESKTOP:-}" ]; then
  (cd apps/desktop && CARGO_TARGET_DIR="$ROOT/target" cargo build --release --locked)
fi

PKG="dist/deb/gimmecores_${VERSION}_${ARCH}"
rm -rf "$PKG" && mkdir -p "$PKG/DEBIAN" "$PKG/usr/bin" "$PKG/usr/lib/systemd/user" \
  "$PKG/usr/share/polkit-1/actions" "$PKG/usr/share/doc/gimmecores"
install -m 0755 target/release/gmcd target/release/gmc target/release/gimmecores "$PKG/usr/bin/"
# The unit runs the packaged gmcd (packaging/linux/gmcd.service points at ~/.local/bin).
sed 's#^ExecStart=.*#ExecStart=/usr/bin/gmcd#' packaging/linux/gmcd.service \
  > "$PKG/usr/lib/systemd/user/gmcd.service"
install -m 0644 packaging/linux/dev.gimmecores.policy "$PKG/usr/share/polkit-1/actions/"
install -m 0644 LICENSE "$PKG/usr/share/doc/gimmecores/copyright"

DEPENDS="libc6"
if [ -z "${GMC_NO_DESKTOP:-}" ]; then
  # The app finds gmcd and gmc next to itself (/usr/bin).
  install -m 0755 target/release/gimmecores-desktop "$PKG/usr/bin/"
  mkdir -p "$PKG/usr/share/applications" "$PKG/usr/share/icons/hicolor/128x128/apps"
  install -m 0644 apps/desktop/icons/128x128.png "$PKG/usr/share/icons/hicolor/128x128/apps/gimmecores.png"
  cat > "$PKG/usr/share/applications/gimmecores.desktop" <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=GimmeCores
Comment=Lend this computer to your paired devices, with your consent
Exec=gimmecores-desktop
Icon=gimmecores
Categories=Development;
DESKTOP
  DEPENDS="$DEPENDS, libwebkit2gtk-4.1-0, libgtk-3-0, libayatana-appindicator3-1"
fi

cat > "$PKG/DEBIAN/control" <<CONTROL
Package: gimmecores
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: GimmeCores <https://github.com/tanuj24/gimmecores>
Depends: ${DEPENDS}
Recommends: bubblewrap, polkitd | policykit-1
Suggests: docker.io
Section: utils
Priority: optional
Homepage: https://github.com/tanuj24/gimmecores
Description: Borrow CPU, RAM and GPU from machines next to you, with their owner's consent
 GimmeCores lends this computer's spare cores to your own paired devices: every use needs a
 grant you approve (with your password), tasks run sandboxed with no network, and one click
 stops everything. Lending is off after install.
CONTROL

dpkg-deb --root-owner-group --build "$PKG" "dist/gimmecores_${VERSION}_${ARCH}.deb"
echo "Built dist/gimmecores_${VERSION}_${ARCH}.deb"
