#!/bin/bash
# Creates the Windows test VM in UTM on this Mac, installed unattended: Windows 11 Pro on ARM,
# local administrator "tanuj" with no password (signed in automatically), keyboard English
# (India), User Account Control on, OpenSSH Server accepting only this Mac's test key
# (~/.ssh/gimmecores_vm, made here if missing), the VirtIO network driver, no VirtIO display
# driver (black screens), no screen sleep. Takes about 20 minutes; nothing to click.
#
#   scripts/windows/make-test-vm.sh <Windows 11 ARM64 ISO>
#
# Then: scripts/windows/test-windows.sh. Docs: docs/design/windows.md.
set -eo pipefail
cd "$(dirname "$0")"
HERE="$PWD"
die() { echo "error: $*" >&2; exit 1; }
ISO="${1:-}"; [ -f "$ISO" ] || die "give the Windows 11 ARM64 ISO (microsoft.com/software-download/windows11arm64)"
ISO="$(cd "$(dirname "$ISO")" && pwd -P)/$(basename "$ISO")"
UTMCTL=/Applications/UTM.app/Contents/MacOS/utmctl
[ -x "$UTMCTL" ] || die "install UTM first (mac.getutm.app)"
NAME="GimmeCores Windows"
"$UTMCTL" list | grep -q " $NAME$" && die "UTM already has a VM named \"$NAME\""

KEY="$HOME/.ssh/gimmecores_vm"
[ -f "$KEY" ] || ssh-keygen -q -t ed25519 -N "" -C "gimmecores-windows-test-vm" -f "$KEY"

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
mkdir -p "$W/setup/Drivers"
cp Autounattend.xml "$W/setup/"
sed "s|@SSH_KEY@|$(cat "$KEY.pub")|" gmc-setup.ps1.in > "$W/setup/gmc-setup.ps1"

echo "== OpenSSH for Windows (ARM64), checked against GitHub's checksum"
read -r URL DIGEST < <(gh api repos/PowerShell/Win32-OpenSSH/releases/latest \
  -q '.assets[] | select(.name|test("^OpenSSH-ARM64-v[0-9.]+\\.msi$")) | "\(.browser_download_url) \(.digest)"')
curl -sSL -o "$W/setup/OpenSSH-ARM64.msi" "$URL"
[ "sha256:$(shasum -a 256 "$W/setup/OpenSSH-ARM64.msi" | cut -d' ' -f1)" = "$DIGEST" ] || die "OpenSSH checksum mismatch"

echo "== VirtIO drivers from UTM's guest tools, checked against UTM's checksum"
TOOLS="$W/utm-guest-tools.iso"
curl -sSL -o "$TOOLS" https://getutm.app/downloads/utm-guest-tools-latest.iso
SUM="sha256:$(shasum -a 256 "$TOOLS" | cut -d' ' -f1)"
gh api "repos/utmapp/qemu/releases?per_page=50" -q '.[].assets[] | select(.name|test("^utm-guest-tools-[0-9.]+\\.iso$")) | .digest' \
  | grep -qx "$SUM" || die "the guest tools do not match any UTM release"
M="$W/tools"; mkdir -p "$M"
hdiutil attach -quiet -readonly -nobrowse -noverify -mountpoint "$M" "$TOOLS"
for d in NetKVM vioserial Balloon; do
  mkdir -p "$W/setup/Drivers/$d"; cp "$M/Drivers/$d/w11/ARM64/"* "$W/setup/Drivers/$d/"
done
hdiutil detach -quiet "$M"

SETUP_ISO="$HOME/Downloads/gimmecores-vm-setup.iso"
rm -f "$SETUP_ISO"
hdiutil makehybrid -quiet -iso -joliet -default-volume-name GMCSETUP -o "$SETUP_ISO" "$W/setup"

echo "== Creating and starting \"$NAME\""
osascript - "$ISO" "$SETUP_ISO" "$NAME" <<'EOF'
on run argv
	tell application "UTM"
		set vm to make new virtual machine with properties {backend:qemu, configuration:{name:(item 3 of argv), architecture:"aarch64", memory:8192, cpu cores:4, hypervisor:true, uefi:true, drives:{{removable:true, interface:USB, source:(POSIX file (item 1 of argv))}, {removable:true, interface:USB, source:(POSIX file (item 2 of argv))}, {interface:NVMe, guest size:65536}}, network interfaces:{{mode:shared}}, displays:{{hardware:"virtio-ramfb"}}}}
		start vm
		-- "Press any key to boot from CD or DVD", once.
		repeat 50 times
			delay 0.5
			try
				input keystroke vm text " "
			end try
		end repeat
	end tell
end run
EOF
echo "Installing; SSH comes up when it is done (about 20 minutes)."
echo "Then: scripts/windows/test-windows.sh"
