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
# A terminal for the CLI's "Type yes to confirm" (it refuses piped input on purpose). The input
# stays open after "yes" (ssh closes the session, killing the command, when input ends). On
# Windows, Enter is a carriage return: a bare newline ends the SSH terminal session.
win_tty() { ssh -tt "${KEY[@]}" "tanuj@$WIN" "$@"; }
lin_tty() { ssh -tt "${KEY[@]}" "lender@$LIN" "$@"; }
FAILED=0
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1${2:+ :: $2}"; FAILED=1; }
W="${GMC_E2E_KEEP:-$(mktemp -d)}"; mkdir -p "$W"; [ -n "${GMC_E2E_KEEP:-}" ] || trap 'rm -rf "$W"' EXIT

LH=/tmp/gmc-e2e-lender
WH='C:\gmc\e2e-home'
WP='C:\gmc\e2e-project'

echo "== Lender (Linux $LIN): fresh daemon, lending in its sandbox"
# `[g]mc/gmcd`: a plain `gmc/gmcd` would also match this very shell's command line, and pkill
# would end it before the old home is removed (the lender would remember earlier runs' devices).
lin "pkill -f '[g]mc/gmcd'; sleep 1; rm -rf $LH ~/gmc; mkdir -p ~/gmc" >/dev/null 2>&1
scp -q "${KEY[@]}" "$LINBIN/gmc" "$LINBIN/gmcd" "lender@$LIN:gmc/"
lin "chmod +x ~/gmc/gmc ~/gmc/gmcd; GMC_HOME=$LH setsid nohup ~/gmc/gmcd --listen $LIN:47630 --name LinuxLender --no-presence > /tmp/gmcd-lender.log 2>&1 < /dev/null & sleep 4" >/dev/null 2>&1
(sleep 2; echo yes; sleep 10) | lin_tty "GMC_HOME=$LH ~/gmc/gmc lend on --on-battery --when-hot" >/dev/null 2>&1
lin "GMC_HOME=$LH ~/gmc/gmc runtimes sandbox" >/dev/null 2>&1
lin "GMC_HOME=$LH ~/gmc/gmc status" | grep -qi "lending:  on" && ok "lender lends in its sandbox" || bad "lender lends" "$(lin "GMC_HOME=$LH ~/gmc/gmc status; tail -5 /tmp/gmcd-lender.log" 2>&1 | tr '\n' ' ')"

echo "== Borrower (Windows $WIN): fresh daemon in the desktop session"
win 'New-Item -ItemType Directory -Force C:\gmc | Out-Null; Get-Process gmcd -ErrorAction SilentlyContinue | Stop-Process -Force; Start-Sleep 1; Remove-Item C:\gmc\e2e-home, C:\gmc\e2e-project -Recurse -Force -ErrorAction SilentlyContinue' >/dev/null 2>&1
scp -q "${KEY[@]}" "$WINBIN/gmc.exe" "$WINBIN/gmcd.exe" "$(dirname "$0")/desk.ps1" "tanuj@$WIN:C:/gmc/"
printf '@set GMC_HOME=%s\r\n@C:\\gmc\\gmcd.exe --listen %s:47631 --name WindowsVM --no-presence > C:\\gmc\\e2e-gmcd.log 2>&1\r\n' "$WH" "$WIN" > "$W/e2e-gmcd.cmd"
scp -q "${KEY[@]}" "$W/e2e-gmcd.cmd" "tanuj@$WIN:C:/gmc/"
win "powershell -NoProfile -ExecutionPolicy Bypass -File C:\gmc\desk.ps1 -Exe cmd.exe -Arguments '/c C:\gmc\e2e-gmcd.cmd'; Start-Sleep 6" >/dev/null
for _ in $(seq 1 15); do win "\$env:GMC_HOME='$WH'; C:\gmc\gmc.exe status" 2>&1 | grep -q "WindowsVM" && break; sleep 2; done
win "\$env:GMC_HOME='$WH'; C:\gmc\gmc.exe status" 2>&1 | grep -q "WindowsVM" && ok "borrower daemon runs in the desktop session" || bad "borrower daemon" "$(win 'Get-Content C:\gmc\e2e-gmcd.log -Tail 5' 2>&1 | tr '\n' ' ')"

echo "== Pairing"
( (sleep 25; echo yes; sleep 20) | lin_tty "GMC_HOME=$LH ~/gmc/gmc pair" > "$W/lender-pair.txt" 2>&1 ) &
for _ in $(seq 1 20); do grep -q "gmc1:" "$W/lender-pair.txt" 2>/dev/null && break; sleep 1; done
TICKET="$(grep -o 'gmc1:[^[:space:]]*' "$W/lender-pair.txt" | head -1)"
[ -n "$TICKET" ] || bad "lender opens pairing" "$(tr '\r\n' '  ' < "$W/lender-pair.txt")"
(sleep 12; printf 'yes\r'; sleep 20) | win_tty "\$env:GMC_HOME='$WH'; C:\gmc\gmc.exe pair $TICKET" > "$W/win-pair.txt" 2>&1
wait
win "\$env:GMC_HOME='$WH'; C:\gmc\gmc.exe peers" 2>&1 | grep -q "LinuxLender" && ok "Windows and Linux are paired (codes confirmed on both)" \
  || bad "pairing" "win: $(tr '\r\n' '  ' < "$W/win-pair.txt" | cut -c1-300) | lender: $(tr '\r\n' '  ' < "$W/lender-pair.txt" | cut -c1-300)"

echo "== A grant: Windows asks, Linux accepts"
# The request waits for the owner's decision, so it runs while the lender decides.
# The owner accepts, then says no to also accepting requests like it without asking.
win "\$env:GMC_HOME='$WH'; C:\gmc\gmc.exe grants request LinuxLender --runtime sandbox --cpus 2 --memory 1g --hours 1 --reason e2e" > "$W/request.txt" 2>&1 &
REQ=$!
sleep 5
(sleep 3; echo yes; sleep 2; echo no; sleep 8) | lin_tty "GMC_HOME=$LH ~/gmc/gmc requests" > "$W/requests.txt" 2>&1
wait $REQ
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

echo "== While a task runs, Windows sees it on the lender with the lender's figures"
# One SSH session for all of it: Windows' SSH server ends a session's processes when it closes.
# Busy for 20 s with no output (arguments without spaces: Start-Process does not quote them);
# `gmc tasks` is read until the lender's figures show, then the task is stopped.
# The lender's owner shares how busy it is overall, so Windows sees that line too.
lin "GMC_HOME=$LH ~/gmc/gmc share-load on" >/dev/null 2>&1
PATTERN='LinuxLender  1 task  cpu [0-9.]+ cores? of 2 cores  memory [0-9.]+ [MG]iB of 1.0 GiB'
win "\$env:GMC_HOME='$WH'; Set-Location $WP
\$p = Start-Process C:\gmc\gmc.exe -ArgumentList 'run','--peer','LinuxLender','--','timeout','20','md5sum','/dev/zero' -PassThru -WindowStyle Hidden
\$t = ''
foreach (\$i in 1..10) { Start-Sleep 2; \$t = (C:\gmc\gmc.exe tasks) -join [char]10; if (\$t -match '$PATTERN') { break } }
\$t
Start-Sleep 4
Stop-Process \$p -Force -ErrorAction SilentlyContinue" > "$W/there.txt" 2>&1 &
THERE_JOB=$!
HERE=""
for _ in $(seq 1 10); do
  sleep 2
  HERE="$(lin "GMC_HOME=$LH ~/gmc/gmc tasks" 2>&1)"
  echo "$HERE" | grep -q "for WindowsVM" && break
done
wait $THERE_JOB
THERE="$(tr -d '\r' < "$W/there.txt")"
echo "$THERE" | grep -Eq "$PATTERN" && echo "$THERE" | grep -q "running .*timeout 20 md5sum /dev/zero" \
  && echo "$THERE" | grep -Eq "whole computer: cpu [0-9.]+ cores? of [0-9]+ in use, memory [0-9.]+ [MG]iB of" \
  && ok "gmc tasks on Windows lists the task there with the lender's figures, and the lender's whole computer" \
  || bad "the lender's figures on Windows" "$(echo "$THERE" | tr '\n' '|' | cut -c1-400)"
echo "$HERE" | grep -q "for WindowsVM" && ! echo "$HERE" | grep -q "Your tasks on other devices" \
  && echo "$HERE" | grep -q "speed   your apps first (their work yields to yours)$" \
  && ok "the lender lists it as running here for WindowsVM at its owner's default speed, and nothing of Windows' own" \
  || bad "the lender's view" "$(echo "$HERE" | tr '\n' '|' | cut -c1-300)"
sleep 4

echo "== Stopping gmc run stops the task on the lender"
win "\$env:GMC_HOME='$WH'; Set-Location $WP; \$p = Start-Process C:\gmc\gmc.exe -ArgumentList 'run','--peer','LinuxLender','--','sleep','120' -PassThru -WindowStyle Hidden; Start-Sleep 8; Stop-Process \$p -Force" >/dev/null 2>&1
sleep 6
# The lender's audit log says the task started, then ended cancelled (not left running).
ENDED="$(lin "grep -A3 'starting for WindowsVM: sleep 120' $LH/audit.log | grep -o 'finished: [A-Za-z]*' | head -1")"
lin "grep -q 'starting for WindowsVM: sleep 120' $LH/audit.log" && [ "$ENDED" = "finished: Cancelled" ] \
  && ok "the task started on the lender and was cancelled when gmc run was stopped" \
  || bad "stopping gmc run cancels the task" "ended: ${ENDED:-no record}; running: $(lin "GMC_HOME=$LH ~/gmc/gmc tasks" 2>&1 | tr '\n' ' ')"

echo "== Containers from a Windows without Docker: the lender's own image, nothing sent"
# Most Windows borrowers have no Docker. Under a grant that allows images, gmc run --image first
# looks for the image in this computer's Docker; with none here it names the lender's copy, as it
# does under a grant without images. Each grant is the only one held when its task runs.
lin "docker image inspect alpine:3.20 >/dev/null 2>&1 || docker pull -q alpine:3.20 >/dev/null" >/dev/null 2>&1
lin "GMC_HOME=$LH ~/gmc/gmc runtimes sandbox container" >/dev/null 2>&1
win "[bool](Get-Command docker -ErrorAction SilentlyContinue)" 2>&1 | tr -d '\r' | grep -qx False \
  && ok "Windows has no Docker" || bad "these checks need a Windows without Docker"
revoke_all() {
  for G in $(lin "GMC_HOME=$LH ~/gmc/gmc grants" 2>&1 | awk '/ lent /{print $1}'); do
    (sleep 2; echo yes; sleep 6) | lin_tty "GMC_HOME=$LH ~/gmc/gmc revoke $G" >/dev/null 2>&1
  done
}
for IMAGES in 0 1g; do
  revoke_all
  win "\$env:GMC_HOME='$WH'; C:\gmc\gmc.exe grants request LinuxLender --runtime container --cpus 1 --memory 1g --hours 1 --images $IMAGES --reason e2e" > "$W/request-$IMAGES.txt" 2>&1 &
  REQ=$!
  sleep 5
  (sleep 3; echo yes; sleep 2; echo no; sleep 8) | lin_tty "GMC_HOME=$LH ~/gmc/gmc requests" > "$W/requests-$IMAGES.txt" 2>&1
  wait $REQ
  if [ "$IMAGES" = 0 ]; then WHAT="a grant without images"; ! grep -q "Images:" "$W/requests-$IMAGES.txt"
  else WHAT="a grant with images"; grep -q "Images:   may send its own container images, up to 1.0 GB" "$W/requests-$IMAGES.txt"; fi \
    && ok "the request for $WHAT says so" || bad "request text ($WHAT)" "$(tr '\r\n' '  ' < "$W/requests-$IMAGES.txt" | cut -c1-400)"
  OUT="$(win "\$env:GMC_HOME='$WH'; Set-Location $WP; C:\gmc\gmc.exe run --peer LinuxLender --image alpine:3.20 -- cat /etc/alpine-release" 2>&1 | tr -d '\r')"
  echo "$OUT" | tail -1 | grep -q '^3\.20\.' && ok "under $WHAT, the task ran in the lender's alpine:3.20" \
    || bad "container task under $WHAT" "$(echo "$OUT" | tr '\n' ' ' | cut -c1-300)"
done
LOADED="$(lin "grep -c 'loaded the container image' $LH/audit.log")"
[ "$LOADED" = 0 ] && ok "the lender loaded no image from Windows" || bad "images loaded from Windows" "$LOADED"
revoke_all

# 0.1.1: what a Windows borrower gained. `wg ARGS` runs gmc.exe ARGS in the project (PowerShell
# syntax: single quotes keep `$` and `{}` for the lender's shell).
wg() { win "\$env:GMC_HOME='$WH'; Set-Location $WP; C:\gmc\gmc.exe $*" 2>&1 | tr -d '\r'; }
ask_sandbox() { # $1: extra request options; the Linux owner accepts (and says no to "always")
  win "\$env:GMC_HOME='$WH'; C:\gmc\gmc.exe grants request LinuxLender --runtime sandbox --cpus 2 --memory 1g --hours 1 --reason e2e $1" > "$W/ask.txt" 2>&1 &
  local req=$!
  sleep 5
  (sleep 3; echo yes; sleep 2; echo no; sleep 8) | lin_tty "GMC_HOME=$LH ~/gmc/gmc requests" > "$W/asked.txt" 2>&1
  wait $req
}
start_windows_gmcd() {
  win "powershell -NoProfile -ExecutionPolicy Bypass -File C:\gmc\desk.ps1 -Exe cmd.exe -Arguments '/c C:\gmc\e2e-gmcd.cmd'; Start-Sleep 6" >/dev/null
  for _ in $(seq 1 15); do wg status | grep -q "WindowsVM" && return; sleep 2; done
}

echo "== 0.1.1: a sandbox grant again, the lender's version and tools"
ask_sandbox
wg grants | grep -qi "active" && ok "the grant is active" || bad "grant" "$(tr '\r\n' '  ' < "$W/asked.txt" | cut -c1-300)"
OUT="$(wg peers)"
echo "$OUT" | grep -q "runs GimmeCores 0.1.1" && ok "Windows sees the lender's version" || bad "the lender's version" "$OUT"
OUT="$(wg doctor --peer LinuxLender)"
echo "$OUT" | grep -q "^python3 " && ok "gmc doctor on Windows lists the lender's tools" || bad "gmc doctor" "$OUT"

echo "== --shards, --cache and --where from Windows"
OUT="$(wg run --peer LinuxLender --shards 2 -- sh -c "'echo part-{shard}-of-\$GMC_SHARDS'")"
echo "$OUT" | grep -q "part-1/2-of-2" && echo "$OUT" | grep -q "part-2/2-of-2" \
  && ok "--shards 2 runs both shards there" || bad "--shards" "$(echo "$OUT" | tr '\n' '|')"
KEEP="'if test -f c/x; then echo WARM; else mkdir -p c; touch c/x; echo COLD; fi'"
A="$(wg run --peer LinuxLender --cache c -- sh -c "$KEEP")"
B="$(wg run --peer LinuxLender --cache c -- sh -c "$KEEP")"
echo "$A" | grep -qx COLD && echo "$B" | grep -qx WARM && ok "--cache keeps a folder there between tasks" \
  || bad "--cache" "first: $(echo "$A" | tr '\n' '|') second: $(echo "$B" | tr '\n' '|')"
win "Test-Path $WP\c" 2>&1 | grep -q False && ok "the cache stays there (nothing written here)" || bad "the cache came back"
OUT="$(wg run --where local -- cmd /c echo here-on-windows)"
echo "$OUT" | grep -q "here-on-windows" && ok "--where local runs it on Windows" || bad "--where local" "$(echo "$OUT" | tr '\n' '|')"
# (It says where only in a terminal.) Windows has 4 idle cores and the grant 2: here, usually.
OUT="$(wg run --where auto -- hostname)"
[ -n "$(echo "$OUT" | grep -v '^gmc:')" ] && ok "--where auto runs it (on $(echo "$OUT" | grep -v '^gmc:' | head -1))" \
  || bad "--where auto" "$(echo "$OUT" | tr '\n' '|')"

echo "== --no-wait: the request waits for the owner, across a restart of Windows' gmcd"
OUT="$(wg grants request LinuxLender --runtime sandbox --cpus 1 --memory 512m --hours 1 --no-wait --reason queued)"
wg grants | grep -qi "waiting" && ok "the request is left with the owner ($(echo "$OUT" | head -1 | cut -c1-80))" \
  || bad "--no-wait" "$(echo "$OUT" | tr '\n' '|') :: $(wg grants | tr '\n' '|')"
win "(Get-Acl $WH\requests.json).AreAccessRulesProtected" 2>&1 | tr -d '\r' | grep -qx True \
  && ok "the waiting requests file is private (protected DACL)" || bad "requests.json DACL"
win 'Get-Process gmcd -ErrorAction SilentlyContinue | Stop-Process -Force' >/dev/null 2>&1
start_windows_gmcd
wg grants | grep -qi "waiting" && ok "it is still waiting after gmcd restarts" || bad "waiting after a restart" "$(wg grants | tr '\n' '|')"
(sleep 3; echo yes; sleep 2; echo no; sleep 8) | lin_tty "GMC_HOME=$LH ~/gmc/gmc requests" > "$W/asked.txt" 2>&1
ACTIVE=0
for _ in $(seq 1 45); do ACTIVE="$(wg grants | grep -ci 'active')"; [ "$ACTIVE" -ge 2 ] && break; sleep 2; done
[ "$ACTIVE" -ge 2 ] && ok "the owner's answer reaches Windows: a second grant" \
  || bad "the answer to a waiting request" "$(wg grants | tr '\n' '|') :: $(tr '\r\n' '  ' < "$W/asked.txt" | cut -c1-300)"

echo "== Standing grants"
OUT="$(lin "GMC_HOME=$LH ~/gmc/gmc standing set WindowsVM --runtime sandbox --cpus 1 --memory 1g --hours 1" 2>&1)"
echo "$OUT" | grep -q "accepted without asking" && ok "the Linux owner sets a standing grant for Windows" || bad "standing set" "$OUT"
win "\$env:GMC_HOME='$WH'; C:\gmc\gmc.exe grants request LinuxLender --runtime sandbox --cpus 1 --memory 512m --hours 1 --reason standing" > "$W/standing.txt" 2>&1 &
REQ=$!
for _ in $(seq 1 15); do grep -q "Granted" "$W/standing.txt" && break; sleep 2; done
kill $REQ 2>/dev/null; wait $REQ 2>/dev/null
grep -q "Granted" "$W/standing.txt" && lin "GMC_HOME=$LH ~/gmc/gmc grants" 2>&1 | grep -q "(standing)" \
  && ok "Windows' next request is accepted without asking, and marked on the lender" \
  || bad "a request under the standing grant" "$(tr '\r\n' '  ' < "$W/standing.txt" | cut -c1-300)"
OUT="$(wg standing set LinuxLender)"
echo "$OUT" | grep -q "does not lend" && ok "Windows refuses a standing grant of its own (it does not lend)" || bad "standing set on Windows" "$OUT"
lin "GMC_HOME=$LH ~/gmc/gmc standing off WindowsVM" >/dev/null 2>&1

echo "== Wake-on-LAN, allowed per device"
OUT="$(wg allow-wake LinuxLender on)"
echo "$OUT" | grep -q "may now wake this computer" && ok "Windows lets the lender wake it" || bad "allow-wake on Windows" "$OUT"
lin "GMC_HOME=$LH ~/gmc/gmc link-test WindowsVM" >/dev/null 2>&1
OUT="$(lin "GMC_HOME=$LH ~/gmc/gmc wake WindowsVM" 2>&1)"
echo "$OUT" | grep -Eq "\(([1-9][0-9]*) packets\)" && ok "the lender can wake Windows ($(echo "$OUT" | grep -o '([0-9]* packets)'))" || bad "wake Windows" "$OUT"
lin "GMC_HOME=$LH ~/gmc/gmc allow-wake WindowsVM on" >/dev/null 2>&1
wg link-test LinuxLender >/dev/null
OUT="$(wg wake LinuxLender)"
echo "$OUT" | grep -Eq "\(([1-9][0-9]*) packets\)" && ok "Windows can wake the lender ($(echo "$OUT" | grep -o '([0-9]* packets)'))" || bad "wake from Windows" "$OUT"
wg allow-wake LinuxLender off >/dev/null

echo "== gmc bench from Windows"
# It runs the same Python program here and there. Without Python it says what to install; with
# Python's embeddable build unpacked in C:\gmc\py (on PATH for this command only) it measures.
OUT="$(wg bench LinuxLender)"
echo "$OUT" | grep -q "found no Python 3 on this computer" && ok "without Python, gmc bench says to install it" \
  || bad "gmc bench without Python" "$(echo "$OUT" | tr '\n' '|')"
if win 'Test-Path C:\gmc\py\python.exe' 2>&1 | grep -q True; then
  OUT="$(win "\$env:PATH='C:\gmc\py;'+\$env:PATH; \$env:GMC_HOME='$WH'; Set-Location $WP; C:\gmc\gmc.exe bench LinuxLender" 2>&1 | tr -d '\r')"
  echo "$OUT" | grep -q "verdict:" && echo "$OUT" | grep -q "(python3)" \
    && ok "with Python, gmc bench measures the lender against Windows ($(echo "$OUT" | grep 'one core:' | sed 's/^ *//'))" \
    || bad "gmc bench with Python" "$(echo "$OUT" | tr '\n' '|')"
else
  echo "skip gmc bench with Python (no C:\gmc\py\python.exe: unpack Python's embeddable build there)"
fi
revoke_all

echo "== Cleaning up"
win 'Get-Process gmcd -ErrorAction SilentlyContinue | Stop-Process -Force' >/dev/null 2>&1
lin "pkill -f '[g]mc/gmcd'" >/dev/null 2>&1
[ "$FAILED" = 0 ] && echo "== Windows borrows from Linux: all checks passed (presence off)" || { echo "== borrowing checks FAILED"; exit 1; }
