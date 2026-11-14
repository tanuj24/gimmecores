#!/bin/bash
# Tests approvals with the Windows password (used when Windows Hello is not set up) in the
# Windows test VM (scripts/windows/make-test-vm.sh), through UTM: it clicks and types in the VM
# like a person would, including Ctrl+Alt+Delete for the secure screen.
#
# It adds a temporary local account `gmcpw` with a password and no PIN, signs it in automatically,
# runs the presence check there (crates/gimmecores-presence/examples/check.rs), and checks that:
#   - the account's password approves;
#   - a wrong password, Cancel, and another account's valid password (the prompt's "Use a
#     different account") are refused;
#   - with Windows' blank-password rule turned off, no password is asked at all;
#   - over SSH (no desktop to ask on) it refuses at once.
# Afterwards tanuj is signed in again (with the password kept on this Mac) and the account is
# removed, whatever happened.
#
# Needs: the VM's screen at 800x600 (the clicks use fixed positions), and tanuj's password in
# ~/.ssh/gimmecores_vm_windows_password (the VM signs tanuj in with it).
#
#   scripts/windows/password-approval.sh
set -eo pipefail
cd "$(dirname "$0")/../.."
ROOT="$PWD"
UTMCTL=/Applications/UTM.app/Contents/MacOS/utmctl
VMNAME="GimmeCores Windows"
IP="${GMC_WINDOWS_VM:-$("$UTMCTL" ip-address "$VMNAME" 2>/dev/null | head -1)}"
[ -n "$IP" ] || { echo "error: the test VM is not running (scripts/windows/make-test-vm.sh)" >&2; exit 1; }
TANUJ_PW="$HOME/.ssh/gimmecores_vm_windows_password"
[ -r "$TANUJ_PW" ] || { echo "error: $TANUJ_PW is missing" >&2; exit 1; }
SSH=(-i "$HOME/.ssh/gimmecores_vm" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=10)
vm() { ssh "${SSH[@]}" "tanuj@$IP" "$@"; }
W="$(mktemp -d)"; chmod 700 "$W"

# Keys and clicks into the VM.
utm() { osascript -e "tell application \"UTM\" to $1 (virtual machine named \"$VMNAME\") $2"; }
keys() { utm "input keystroke" "text \"$1\""; sleep 0.5; }
key() { utm "input keystroke" "text (ASCII character $1)"; sleep 0.5; }   # 9 Tab, 13 Enter
scan() { utm "input scan code" "codes {$1}"; }
click() { utm "input mouse click" "at {$1, $2}"; }
ctrl_alt_del() { scan "29, 56, 224, 83, 224, 211, 184, 157"; }
esc() { scan "1, 129"; }
type_secret() { # types the contents of a file (one line) without putting it on a command line
  tr -d '\r\n' < "$1" > "$W/typing"
  osascript -e 'on run argv' -e 'set t to read (POSIX file (item 1 of argv))' \
    -e "tell application \"UTM\" to input keystroke (virtual machine named \"$VMNAME\") text t" -e 'end run' "$W/typing"
  rm -f "$W/typing"; sleep 0.5
}

echo "== Building the presence check for Windows"
docker buildx build --builder "$(docker context show)" --load -q -t gmc-windows-cross \
  -f scripts/ci/Dockerfile.windows scripts/ci >/dev/null
docker run --rm -v "$ROOT":/src -v gmc-win-target:/target -v gmc-win-cargo:/usr/local/cargo/registry \
  -v "$W":/out gmc-windows-cross sh -c \
  'cargo build -q --locked --release -p gimmecores-presence --example check --target x86_64-pc-windows-gnu &&
   cp /target/x86_64-pc-windows-gnu/release/examples/check.exe /out/'
printf '@C:\\gmc\\check.exe > C:\\gmc\\check.txt 2>&1\r\n' > "$W/check.cmd"
cat > "$W/as.ps1" <<'EOF'
# Starts a command line, without a window, in the signed-in desktop session of -User.
param([string]$User, [string]$Name, [string]$Line)
Unregister-ScheduledTask -TaskName $Name -Confirm:$false -ErrorAction SilentlyContinue
$a = New-ScheduledTaskAction -Execute "conhost.exe" -Argument ("--headless " + $Line)
$p = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive
Register-ScheduledTask -TaskName $Name -Action $a -Principal $p -Force | Out-Null
Start-ScheduledTask -TaskName $Name
EOF
vm 'New-Item -ItemType Directory -Force C:\gmc | Out-Null'
scp -q "${SSH[@]}" "$W/check.exe" "$W/check.cmd" "$W/as.ps1" "tanuj@$IP:C:/gmc/"

# `query user` exits 1 even when it lists sessions, so its status is not used.
signed_in() { local q; q="$(vm 'query user' 2>/dev/null || true)"; tr -d '\r' <<< "$q" | grep -q "^ *>*$1 "; }
restart_into() {
  vm 'shutdown /r /t 0' >/dev/null 2>&1 || true
  sleep 30
  for _ in $(seq 1 40); do signed_in "$1" && break; sleep 5; done
  signed_in "$1" || { echo "error: $1 was not signed in after a restart" >&2; return 1; }
  # A new account's first sign-in prepares its desktop for a while after the session exists.
  for _ in $(seq 1 40); do
    vm "if (Get-Process explorer -IncludeUserName -ErrorAction SilentlyContinue | Where-Object UserName -like '*\\$1') { exit 0 } else { exit 1 }" >/dev/null 2>&1 && break
    sleep 5
  done
  sleep 20
}

restore() {
  set +e
  echo "== Signing tanuj in again and removing gmcpw"
  # tanuj's automatic sign-in again, with the password kept on this Mac.
  (umask 077; cp "$TANUJ_PW" "$W/tanuj.password")
  scp -q "${SSH[@]}" "$W/tanuj.password" "tanuj@$IP:C:/gmc/"; rm -f "$W/tanuj.password"
  vm '$wl = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; $pw = Get-Content C:\gmc\tanuj.password -Raw; Remove-Item C:\gmc\tanuj.password; Set-ItemProperty $wl -Name DefaultPassword -Value $pw; Set-ItemProperty $wl -Name DefaultUserName -Value tanuj; Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LimitBlankPasswordUse -Value 1 -Type DWord; Get-ScheduledTask gmc-* -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false' >/dev/null
  signed_in tanuj || restart_into tanuj
  vm 'Remove-LocalUser gmcpw -ErrorAction SilentlyContinue; Get-CimInstance Win32_UserProfile | Where-Object { $_.LocalPath -like "*\gmcpw*" } | Remove-CimInstance; Remove-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE -Name DisablePrivacyExperience -ErrorAction SilentlyContinue; Remove-Item C:\gmc\check.txt -ErrorAction SilentlyContinue; "gmcpw removed: " + (-not (Get-LocalUser gmcpw -ErrorAction SilentlyContinue))' | tr -d '\r'
  rm -rf "$W"
}
trap restore EXIT

echo "== Adding the account gmcpw (a password, no PIN) and signing it in"
(umask 077; printf 'Gm%s7' "$(openssl rand -hex 6)" > "$W/gmcpw.password")
scp -q "${SSH[@]}" "$W/gmcpw.password" "tanuj@$IP:C:/gmc/"
vm '$pw = Get-Content C:\gmc\gmcpw.password -Raw; Remove-Item C:\gmc\gmcpw.password; $s = ConvertTo-SecureString $pw -AsPlainText -Force; if (Get-LocalUser gmcpw -ErrorAction SilentlyContinue) { Set-LocalUser gmcpw -Password $s } else { New-LocalUser -Name gmcpw -Password $s -PasswordNeverExpires -AccountNeverExpires | Out-Null; Add-LocalGroupMember -Group Users -Member gmcpw }; $wl = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; $oobe = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE"; if (-not (Test-Path $oobe)) { New-Item -Path $oobe | Out-Null }; Set-ItemProperty $oobe -Name DisablePrivacyExperience -Value 1 -Type DWord; Set-ItemProperty $wl -Name DefaultUserName -Value gmcpw; Set-ItemProperty $wl -Name DefaultPassword -Value $pw' >/dev/null
restart_into gmcpw
esc; sleep 1 # the Start menu may be open after a first sign-in

# Runs the check in gmcpw's session; `outcome` waits for and prints its answer.
start_check() {
  vm 'Stop-Process -Name check -Force -ErrorAction SilentlyContinue; Remove-Item C:\gmc\check.txt -ErrorAction SilentlyContinue; powershell -NoProfile -ExecutionPolicy Bypass -File C:\gmc\as.ps1 -User gmcpw -Name gmc-check -Line "cmd.exe /c C:\gmc\check.cmd"' >/dev/null
  sleep 6
}
outcome() {
  local o=""
  for _ in $(seq 1 15); do
    o="$(vm 'Get-Content C:\gmc\check.txt -ErrorAction SilentlyContinue' | tr -d '\r' | sed -n 's/^outcome: //p')"
    [ -n "$o" ] && break; sleep 1
  done
  echo "${o:-no answer}"
}
# Waits until Windows' credential prompt for this check is open (up to 30 s).
wait_prompt() {
  vm '$c = Get-Process check -ErrorAction SilentlyContinue; for ($i = 0; $i -lt 30; $i++) { if ($c -and (Get-Process CredentialUIBroker -ErrorAction SilentlyContinue | Where-Object { $_.StartTime -ge $c.StartTime })) { exit 0 }; Start-Sleep 1 }; exit 1' >/dev/null 2>&1 \
    || echo "(the prompt did not open)" >&2
  sleep 3
}
secure_screen() { wait_prompt; click 297 358; sleep 3; ctrl_alt_del; sleep 5; } # OK on the first prompt, then Ctrl+Alt+Delete

FAILED=0
expect() { # expect <name> <outcome prefix> <outcome>
  if [[ "$3" == "$2"* ]]; then echo "ok    $1: $3"; else echo "FAIL  $1: $3 (wanted $2...)"; FAILED=1; fi
}

echo "== Approvals with the Windows password"
start_check; secure_screen; type_secret "$W/gmcpw.password"; key 13; sleep 5
expect "the account's password approves" "Verified" "$(outcome)"

start_check; secure_screen; keys "Wrong$(openssl rand -hex 3)"; key 13; sleep 5
expect "a wrong password is refused" 'Denied("wrong password")' "$(outcome)"

start_check; wait_prompt; click 502 358; sleep 3 # Cancel on the first prompt
expect "Cancel is refused" 'Denied("cancelled")' "$(outcome)"

# More choices > Use a different account > tanuj with tanuj's real password.
start_check; secure_screen
click 238 476; sleep 3; click 400 506; sleep 2; scan "224, 80, 224, 208"; sleep 2; key 13; sleep 2
click 368 231; sleep 1; keys tanuj; key 9; type_secret "$TANUJ_PW"; key 13; sleep 6
expect "another account's password is refused" 'Denied("that password is for another account")' "$(outcome)"

vm 'Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LimitBlankPasswordUse -Value 0 -Type DWord' >/dev/null
start_check
expect "with blank passwords allowed, no password is asked" 'Unavailable("this PC lets programs sign in with blank passwords' "$(outcome)"
vm 'Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LimitBlankPasswordUse -Value 1 -Type DWord' >/dev/null

expect "over SSH it refuses at once" 'Unavailable("no desktop to ask on' \
  "$(vm 'C:\gmc\check.exe' | tr -d '\r' | sed -n 's/^outcome: //p')"

[ "$FAILED" = 0 ] && echo "== Windows password approvals: all checks passed" || { echo "== Windows password approvals: FAILED"; exit 1; }
