#!/bin/bash
# Sending a container image between two GimmeCores services, end to end, with two separate
# Dockers: in the Debian test VM (UTM), the borrower's service talks to a second Docker daemon,
# so the lender's Docker has none of the borrower's layers (a test with one Docker cannot tell
# whether an archive may leave layers out). Both services listen on 127.0.0.1; presence checks
# are off (gmcd --no-presence). Judged by what the lender's Docker and audit log show.
#
#   scripts/linux/e2e-images.sh <dir with Linux gmc, gmcd>
#
# GMC_LINUX_VM overrides the VM's address (default: UTM's "GimmeCores Linux lender").
# GMC_E2E_STORE=classic runs the lender's Docker on its classic image store instead of the
# containerd one (Docker 29's default; Docker before 25 has only the classic store, so use
# GMC_E2E_STORE=classic there). Tested with Docker 29 (docker-ce) and 20.10 (Debian's docker.io).
set -o pipefail
BIN="$1"
[ -f "$BIN/gmcd" ] && [ -f "$BIN/gmc" ] || { echo "usage: $0 <dir with Linux gmc, gmcd>" >&2; exit 2; }
UTMCTL=/Applications/UTM.app/Contents/MacOS/utmctl
LIN="${GMC_LINUX_VM:-$("$UTMCTL" ip-address "GimmeCores Linux lender" 2>/dev/null | head -1)}"
[ -n "$LIN" ] || { echo "error: start the Linux VM or set GMC_LINUX_VM" >&2; exit 2; }
KEY=(-i "$HOME/.ssh/gimmecores_vm" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=10)
lin() { ssh "${KEY[@]}" "lender@$LIN" "$@"; }
# A terminal for the CLI's "Type yes to confirm" (it refuses piped input on purpose).
lin_tty() { ssh -tt "${KEY[@]}" "lender@$LIN" "$@"; }
FAILED=0
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1${2:+ :: $2}"; FAILED=1; }
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT

LH=/tmp/gmc-img-lender
BH=/tmp/gmc-img-borrower
BD="unix:///run/docker-borrower.sock"
L="GMC_HOME=$LH ~/gmc/gmc"
B="GMC_HOME=$BH ~/gmc/gmc"
BDOCKER="DOCKER_HOST=$BD docker"

echo "== Two Dockers in the VM ($LIN): the lender's (${GMC_E2E_STORE:-containerd} store) and the borrower's"
# `[g]` and pid files: a pattern must not match the remote shell running the command itself.
lin "pkill -f '[g]mc/gmcd'; sleep 1; rm -rf $LH $BH ~/gmc; mkdir -p ~/gmc" >/dev/null 2>&1
scp -q "${KEY[@]}" "$BIN/gmc" "$BIN/gmcd" "lender@$LIN:gmc/"
lin "chmod +x ~/gmc/gmc ~/gmc/gmcd"
STORE=true; [ "${GMC_E2E_STORE:-}" = classic ] && STORE=false
lin "printf '{\"features\":{\"containerd-snapshotter\":%s}}\n' $STORE | sudo tee /etc/docker/daemon.json >/dev/null; sudo systemctl restart docker; sleep 2; docker pull -q alpine:3.20 >/dev/null"
lin "docker info --format '{{.Driver}} {{json .DriverStatus}}'" | grep -q "$([ $STORE = true ] && echo io.containerd.snapshotter || echo overlay2)" \
  && ok "the lender's Docker runs the ${GMC_E2E_STORE:-containerd} store" || bad "lender's Docker store" "$(lin "docker info --format '{{.Driver}}'")"
# Its own containerd too: with the containerd image store, images live in containerd, so a
# second dockerd on the system's containerd would see the lender's images.
lin "for p in /run/docker-borrower.pid /run/containerd-borrower.pid; do [ -f \$p ] && sudo kill \$(cat \$p); done; sleep 2
  sudo rm -rf /var/lib/docker-borrower /var/lib/containerd-borrower /run/containerd-borrower
  sudo mkdir -p /var/lib/docker-borrower /var/lib/containerd-borrower /run/containerd-borrower
  sudo setsid nohup containerd --root /var/lib/containerd-borrower --state /run/containerd-borrower \
    --address /run/containerd-borrower/containerd.sock > /tmp/containerd-borrower.log 2>&1 < /dev/null &
  echo \$! | sudo tee /run/containerd-borrower.pid >/dev/null
  for i in \$(seq 1 20); do [ -S /run/containerd-borrower/containerd.sock ] && break; sleep 1; done
  sudo setsid nohup dockerd --data-root /var/lib/docker-borrower --exec-root /run/docker-borrower \
    --containerd /run/containerd-borrower/containerd.sock \
    -H $BD --pidfile /run/docker-borrower.pid --bridge none --iptables=false --ip6tables=false \
    > /tmp/dockerd-borrower.log 2>&1 < /dev/null &
  for i in \$(seq 1 30); do $BDOCKER info >/dev/null 2>&1 && break; sleep 1; done
  docker save alpine:3.20 | $BDOCKER load -q >/dev/null" >/dev/null 2>&1
lin "docker image rm -f e2e/v1:1 e2e/v2:1 e2e/p:1 e2e/q:1 >/dev/null 2>&1; $BDOCKER image inspect alpine:3.20 >/dev/null" \
  && ok "the borrower has its own Docker" || bad "borrower's Docker" "$(lin 'tail -5 /tmp/dockerd-borrower.log')"

echo "== The borrower's images: a base, a rebuild, and one listing a layer twice"
lin "set -e; d=\$(mktemp -d)
  mk() { c=\$($BDOCKER create \$1 true); echo \$3 > \$d/v; mkdir -p \$d/app; cp \$d/v \$d/app/v; $BDOCKER cp \$d/app \$c:/ >/dev/null; $BDOCKER commit \$c \$2 >/dev/null; $BDOCKER rm \$c >/dev/null; }
  mk alpine:3.20 e2e/v1:1 one; mk e2e/v1:1 e2e/v2:1 two" >/dev/null
cat > "$W/craft.py" <<'EOF'
# base + extra layers ("" = the empty layer, always the same), loaded into the borrower's Docker.
import gzip, hashlib, io, json, os, subprocess, sys, tarfile
base, tag, extra = sys.argv[1], sys.argv[2], sys.argv[3].split(",")
env = dict(os.environ, DOCKER_HOST="unix:///run/docker-borrower.sock")
saved = subprocess.run(["docker", "save", base], env=env, capture_output=True, check=True).stdout
t = tarfile.open(fileobj=io.BytesIO(saved))
m = json.load(t.extractfile("manifest.json"))[0]
config = json.load(t.extractfile(m["Config"]))
layers = []
for p in m["Layers"]:
    raw = t.extractfile(p).read()
    layers.append(gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw)
for v in extra:
    if not v:
        layers.append(b"\0" * 1024)
        continue
    b = io.BytesIO(); a = tarfile.open(fileobj=b, mode="w", format=tarfile.GNU_FORMAT)
    data = (v + "\n").encode(); ti = tarfile.TarInfo("app/v"); ti.size = len(data); ti.mtime = 0
    a.addfile(ti, io.BytesIO(data)); a.close(); layers.append(b.getvalue())
ids = ["sha256:" + hashlib.sha256(l).hexdigest() for l in layers]
config["rootfs"]["diff_ids"] = ids; config.pop("history", None)
out = io.BytesIO(); a = tarfile.open(fileobj=out, mode="w")
def add(n, d):
    ti = tarfile.TarInfo(n); ti.size = len(d); a.addfile(ti, io.BytesIO(d))
names = [i[7:] + ".tar" for i in ids]
add("manifest.json", json.dumps([{"Config": "c.json", "RepoTags": [tag], "Layers": names}]).encode())
add("c.json", json.dumps(config).encode())
for n, l in dict(zip(names, layers)).items():
    add(n, l)
a.close()
subprocess.run(["docker", "load", "-q"], env=env, input=out.getvalue(), check=True, capture_output=True)
EOF
scp -q "${KEY[@]}" "$W/craft.py" "lender@$LIN:gmc/craft.py"
lin "python3 ~/gmc/craft.py alpine:3.20 e2e/p:1 ',plain' && python3 ~/gmc/craft.py alpine:3.20 e2e/q:1 ',twice,'" \
  && ok "images made in the borrower's Docker" || bad "making the borrower's images"
lin "docker image inspect e2e/v1:1 >/dev/null 2>&1 || docker images -q --filter reference='e2e/*' | grep -q ." \
  && bad "the lender's Docker sees the borrower's images" || ok "the lender's Docker does not see them"

echo "== Two services, paired, a grant that lets the borrower send images"
lin "GMC_HOME=$LH setsid nohup ~/gmc/gmcd --listen 127.0.0.1:47641 --name Lender --no-presence > /tmp/gmcd-img-lender.log 2>&1 < /dev/null &
  DOCKER_HOST=$BD GMC_HOME=$BH setsid nohup ~/gmc/gmcd --listen 127.0.0.1:47642 --name Laptop --no-presence > /tmp/gmcd-img-borrower.log 2>&1 < /dev/null &
  sleep 4" >/dev/null 2>&1
(sleep 2; echo yes; sleep 8) | lin_tty "$L lend on --on-battery --when-hot" >/dev/null 2>&1
( (sleep 12; echo yes; sleep 15) | lin_tty "$L pair" > "$W/lender-pair.txt" 2>&1 ) &
for _ in $(seq 1 20); do grep -q "gmc1:" "$W/lender-pair.txt" 2>/dev/null && break; sleep 1; done
TICKET="$(grep -o 'gmc1:[^[:space:]]*' "$W/lender-pair.txt" | head -1)"
(sleep 6; echo yes; sleep 12) | lin_tty "$B pair $TICKET" > "$W/borrower-pair.txt" 2>&1
wait
lin "$B peers" 2>&1 | grep -q Lender && ok "paired" || bad "pairing" "$(tr '\r\n' '  ' < "$W/borrower-pair.txt" | cut -c1-300)"
lin "$B grants request Lender --runtime container --cpus 2 --memory 1g --hours 1 --images 1g --reason e2e" > "$W/request.txt" 2>&1 &
REQ=$!
sleep 4
(sleep 3; echo yes; sleep 8) | lin_tty "$L requests" > "$W/requests.txt" 2>&1
wait $REQ
grep -q "Images:   may send its own container images, up to 1.0 GB of your disk" "$W/requests.txt" \
  && ok "the request names the image allowance" || bad "request text" "$(tr '\r\n' '  ' < "$W/requests.txt" | cut -c1-400)"
grep -q "can run any Docker image on this computer and read what is inside it" "$W/requests.txt" \
  && ok "the request says a container can run any image here" || bad "container wording" "$(tr '\r\n' '  ' < "$W/requests.txt" | cut -c1-400)"
lin "$B grants" 2>&1 | grep -q "images up to 1.0 GB" && ok "the borrower holds the grant, images included" \
  || bad "grant" "$(lin "$B grants" 2>&1 | tr '\n' ' ')"

run() { lin "cd ~ && $B run --peer Lender --image $1 -- cat /app/v" 2>&1; }
loads() { lin "grep -c 'loaded the container image' $LH/audit.log" 2>/dev/null; }
received() { lin "grep 'loaded the container image $1' $LH/audit.log | tail -1 | grep -o '[0-9]* of [0-9]* layers received'"; }

echo "== Sending: the whole image, then only a rebuild's new layer, then nothing"
OUT="$(run e2e/v1:1)"
[ "$(echo "$OUT" | tr -d '\r' | tail -1)" = one ] && ok "the borrower's image ran on the lender" || bad "first run" "$OUT"
R="$(received e2e/v1:1)"; read -r GOT _ ALL _ <<< "$R"
[ -n "$GOT" ] && [ "$GOT" = "$ALL" ] && ok "every layer was sent the first time ($R)" || bad "first send" "$R"
lin "docker images --format '{{.Repository}}' | grep -cE '^gimmecores.local/[0-9a-f]{64}/from-'" | grep -qx 1 \
  && ok "the lender holds it under its own name" || bad "lender's tag" "$(lin "docker images --format '{{.Repository}}:{{.Tag}}'")"
lin "docker image inspect e2e/v1:1 >/dev/null 2>&1" && bad "the borrower's name was used on the lender" || ok "the borrower's name was not used"
OUT="$(run e2e/v2:1)"
[ "$(echo "$OUT" | tr -d '\r' | tail -1)" = two ] && ok "the rebuild ran" || bad "rebuild run" "$OUT"
R="$(received e2e/v2:1)"; [[ "$R" == "1 of "* ]] && ok "only the rebuild's new layer was sent ($R)" || bad "rebuild send" "$R"
BEFORE="$(loads)"; OUT="$(run e2e/v2:1)"
[ "$(echo "$OUT" | tr -d '\r' | tail -1)" = two ] && [ "$(loads)" = "$BEFORE" ] \
  && ok "running it again sent nothing" || bad "third run" "$OUT (loads $BEFORE -> $(loads))"

echo "== A layer the image lists twice, also beneath what the lender has"
OUT="$(run e2e/p:1)"; [ "$(echo "$OUT" | tr -d '\r' | tail -1)" = plain ] && ok "base + empty layer + app" || bad "p" "$OUT"
OUT="$(run e2e/q:1)"; [ "$(echo "$OUT" | tr -d '\r' | tail -1)" = twice ] \
  && ok "the empty layer again above the app was sent and loaded ($(received e2e/q:1))" || bad "q" "$OUT"

echo "== The grant ends: the lender's names go, the borrower's images stay"
G="$(lin "$L grants" 2>&1 | awk '/ lent /{print $1; exit}')"
(sleep 2; echo yes; sleep 6) | lin_tty "$L revoke $G" >/dev/null 2>&1
for _ in $(seq 1 15); do lin "docker images --format '{{.Repository}}' | grep -qE '^gimmecores.local/[0-9a-f]{64}/from-'" || break; sleep 1; done
lin "docker images --format '{{.Repository}}' | grep -qE '^gimmecores.local/[0-9a-f]{64}/from-'" \
  && bad "removed on revoke" "$(lin "docker images --format '{{.Repository}}:{{.Tag}}'")" || ok "the lender removed the images it loaded"
lin "$BDOCKER image inspect e2e/v1:1 e2e/q:1 >/dev/null" && ok "the borrower's own images are untouched" || bad "borrower's images"

echo "== Cleaning up"
lin "pkill -f '[g]mc/gmcd'; for p in /run/docker-borrower.pid /run/containerd-borrower.pid; do [ -f \$p ] && sudo kill \$(cat \$p); sleep 3; done
  sudo rm -rf /var/lib/docker-borrower /var/lib/containerd-borrower /run/containerd-borrower /run/containerd-borrower.pid
  rm -rf $LH $BH; docker image prune -f >/dev/null" >/dev/null 2>&1
[ "$FAILED" = 0 ] && echo "== Sending images between two Dockers: all checks passed (presence off)" || { echo "== image checks FAILED"; exit 1; }
