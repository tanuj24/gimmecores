#!/bin/bash
# Windows borrows from Linux, end to end, between two UTM VMs on this Mac: the Windows test VM
# (scripts/windows/make-test-vm.sh) and a Debian 12 lender VM. Presence checks are OFF on both
# daemons (gmcd --no-presence): this tests pairing, grants, sending work and getting results,
# not Windows Hello. Judged by what arrives on the lender and what comes back.
#
#   scripts/windows/e2e-borrow.sh <dir with gmc.exe, gmcd.exe> <dir with Linux gmc, gmcd>
#
# GMC_WINDOWS_VM / GMC_LINUX_VM override the VMs' addresses.
set -o pipefail
WINBIN="$1"; LINBIN="$2"
[ -f "$WINBIN/gmcd.exe" ] && [ -f "$LINBIN/gmcd" ] || { echo "usage: $0 <windows bin dir> <linux bin dir>" >&2; exit 2; }
UTMCTL=/Applications/UTM.app/Contents/MacOS/utmctl
WIN="${GMC_WINDOWS_VM:-$("$UTMCTL" ip-address "GimmeCores Windows" 2>/dev/null | head -1)}"
LIN="${GMC_LINUX_VM:-}"
[ -n "$WIN" ] && [ -n "$LIN" ] || { echo "error: set GMC_LINUX_VM (and start both VMs)" >&2; exit 2; }
KEY=(-i "$HOME/.ssh/gimmecores_vm" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=10)
win() { ssh "${KEY[@]}" "tanuj@$WIN" "$@"; }
lin() { ssh "${KEY[@]}" "lender@$LIN" "$@"; }
# A terminal for the CLI's "Type yes to confirm" (it refuses piped input on purpose).
win_tty() { ssh -tt "${KEY[@]}" "tanuj@$WIN" "$@"; }
lin_tty() { ssh -tt "${KEY[@]}" "lender@$LIN" "$@"; }
FAILED=0
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1${2:+ :: $2}"; FAILED=1; }
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT

LH=/tmp/gmc-e2e-lender
WH='C:\gmc\e2e-home'
WP='C:\gmc\e2e-project'

echo "== Lender (Linux $LIN): fresh daemon, lending in its sandbox"
lin "pkill -f 'gmc/gmcd' ; rm -rf $LH ~/gmc; mkdir -p ~/gmc" >/dev/null 2>&1
scp -q "${KEY[@]}" "$LINBIN/gmc" "$LINBIN/gmcd" "lender@$LIN:gmc/"
lin "chmod +x ~/gmc/gmc ~/gmc/gmcd; GMC_HOME=$LH setsid nohup ~/gmc/gmcd --listen $LIN:47630 --name LinuxLender --no-presence > /tmp/gmcd-lender.log 2>&1 < /dev/null & sleep 4; GMC_HOME=$LH ~/gmc/gmc lend on --on-battery --when-hot && GMC_HOME=$LH ~/gmc/gmc runtimes sandbox" >/dev/null 2>&1
lin "GMC_HOME=$LH ~/gmc/gmc status" | grep -q "lending:  on" && ok "lender lends in its sandbox" || bad "lender lends" "$(lin "GMC_HOME=$LH ~/gmc/gmc status; tail -5 /tmp/gmcd-lender.log" 2>&1 | tr '\n' ' ')"

echo "== Borrower (Windows $WIN): fresh daemon in the desktop session"
win 'Get-Process gmcd -ErrorAction SilentlyContinue | Stop-Process -Force; Start-Sleep 1; Remove-Item C:\gmc\e2e-home, C:\gmc\e2e-project -Recurse -Force -ErrorAction SilentlyContinue' >/dev/null 2>&1
scp -q "${KEY[@]}" "$WINBIN/gmc.exe" "$WINBIN/gmcd.exe" "tanuj@$WIN:C:/gmc/"
win "Set-Content C:\gmc\e2e-gmcd.cmd \"@set GMC_HOME=$WH`r`n@C:\gmc\gmcd.exe --listen $WIN:47631 --name WindowsVM --no-presence > C:\gmc\e2e-gmcd.log 2>&1\"; powershell -NoProfile -ExecutionPolicy Bypass -File C:\gmc\desk.ps1 -Exe cmd.exe -Arguments '/c C:\gmc\e2e-gmcd.cmd'; Start-Sleep 6" >/dev/null
win "\$env:GMC_HOME='$WH'; C:\gmc\gmc.exe status" 2>&1 | grep -q "WindowsVM" && ok "borrower daemon runs in the desktop session" || bad "borrower daemon" "$(win 'Get-Content C:\gmc\e2e-gmcd.log -Tail 5' 2>&1 | tr '\n' ' ')"

echo "== Pairing"
( (sleep 25; echo yes) | lin_tty "GMC_HOME=$LH ~/gmc/gmc pair" > "$W/lender-pair.txt" 2>&1 ) &
for _ in $(seq 1 20); do grep -q "gmc1:" "$W/lender-pair.txt" 2>/dev/null && break; sleep 1; done
TICKET="$(grep -o 'gmc1:[^[:space:]]*' "$W/lender-pair.txt" | head -1)"
[ -n "$TICKET" ] || bad "lender opens pairing" "$(tr '\r\n' '  ' < "$W/lender-pair.txt")"
(sleep 12; echo yes) | win_tty "\$env:GMC_HOME='$WH'; C:\gmc\gmc.exe pair $TICKET" > "$W/win-pair.txt" 2>&1
wait
win "\$env:GMC_HOME='$WH'; C:\gmc\gmc.exe peers" 2>&1 | grep -q "LinuxLender" && ok "Windows and Linux are paired (codes confirmed on both)" \
  || bad "pairing" "win: $(tr '\r\n' '  ' < "$W/win-pair.txt" | cut -c1-300) | lender: $(tr '\r\n' '  ' < "$W/lender-pair.txt" | cut -c1-300)"

echo "== A grant: Windows asks, Linux accepts"
win "\$env:GMC_HOME='$WH'; C:\gmc\gmc.exe grants request LinuxLender --runtime sandbox --cpus 2 --memory 1g --hours 1 --reason e2e" >/dev/null 2>&1
sleep 3
(sleep 3; echo yes) | lin_tty "GMC_HOME=$LH ~/gmc/gmc requests" > "$W/requests.txt" 2>&1
sleep 3
win "\$env:GMC_HOME='$WH'; C:\gmc\gmc.exe grants" 2>&1 | grep -qi "active" && ok "the grant is active on Windows" \
  || bad "grant" "$(tr '\r\n' '  ' < "$W/requests.txt" | cut -c1-300)"

echo "== A project with secrets in every case, an ignored folder and nested outputs"
win "New-Item -ItemType Directory -Force $WP\sub, $WP\deep\inner, $WP\ignored, $WP\keys | Out-Null
Set-Content $WP\main.txt 'the work'
Set-Content $WP\.gitignore 'ignored/'
Set-Content $WP\ignored\big.bin 'never sent'
Set-Content $WP\.env 'SECRET=1'
Set-Content $WP\sub\.env 'SECRET=2'
Set-Content $WP\deep\.ENV 'SECRET=3'
Set-Content $WP\keys\Id_Rsa 'PRIVATE KEY'
Set-Content $WP\deep\inner\Server.PEM 'CERT'
Set-Content $WP\deep\inner\notes.txt 'fine'" >/dev/null 2>&1
win "\$env:GMC_HOME='$WH'; Set-Location $WP; C:\gmc\gmc.exe run --peer LinuxLender --out out -- sh -c 'find . -type f | sort; mkdir -p out/nested; echo result > out/nested/result.txt'" > "$W/run.txt" 2>&1
ARRIVED="$(tr -d '\r' < "$W/run.txt" | grep '^\./' | sort)"
EXPECT="$(printf './.gitignore\n./deep/inner/notes.txt\n./main.txt\n')"
[ "$ARRIVED" = "$EXPECT" ] && ok "only the project's ordinary files reach the lender" \
  || bad "files that reached the lender" "$(echo "$ARRIVED" | tr '\n' ' ') (output: $(tr '\r\n' '  ' < "$W/run.txt" | cut -c1-300))"
win "Test-Path $WP\out\nested\result.txt" 2>&1 | grep -q True && ok "the declared output came back inside the project" || bad "output came back"
win "(Get-ChildItem $WP -Recurse -File | Where-Object { \$_.FullName -notmatch '\\\\(out|sub|deep|ignored|keys)\\\\|\\\\(main.txt|.gitignore|.env)\$' }).FullName" 2>&1 | grep -q . && bad "nothing else was written" || ok "nothing else was written into the project"

echo "== Stopping gmc run stops the task on the lender"
win "\$env:GMC_HOME='$WH'; Set-Location $WP; \$p = Start-Process C:\gmc\gmc.exe -ArgumentList 'run','--peer','LinuxLender','--','sleep','120' -PassThru -WindowStyle Hidden; Start-Sleep 8; Stop-Process \$p -Force" >/dev/null 2>&1
sleep 6
lin "GMC_HOME=$LH ~/gmc/gmc tasks" 2>&1 | grep -q "sleep" && bad "the task stopped on the lender" "$(lin "GMC_HOME=$LH ~/gmc/gmc tasks" 2>&1 | tr '\n' ' ')" \
  || ok "the task stopped on the lender when gmc run was stopped"

echo "== Cleaning up"
win 'Get-Process gmcd -ErrorAction SilentlyContinue | Stop-Process -Force' >/dev/null 2>&1
lin "pkill -f 'gmc/gmcd'" >/dev/null 2>&1
[ "$FAILED" = 0 ] && echo "== Windows borrows from Linux: all checks passed (presence off)" || { echo "== borrowing checks FAILED"; exit 1; }
