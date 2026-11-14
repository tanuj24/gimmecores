#!/bin/bash
# CI on your own machine, for free: the same checks as .github/workflows/ci.yml, run natively
# on this Mac and in a Linux container (Docker Desktop, or any Docker). Nothing is uploaded.
#
#   scripts/ci-local.sh            mac + linux + deps (the whole of ci.yml, except fuzzing)
#   scripts/ci-local.sh quick      fmt + clippy on this Mac (a few seconds once built)
#   scripts/ci-local.sh mac        the macOS jobs: workspace, Python SDK, desktop app
#   scripts/ci-local.sh linux      the Linux jobs, in a bookworm container (this Mac's CPU type)
#   scripts/ci-local.sh linux-amd64  the same on x86_64, emulated (slow)
#   scripts/ci-local.sh deps       cargo-deny for both workspaces, actionlint for the workflows
#   scripts/ci-local.sh fuzz [s]   every fuzz target for s seconds each (default 60)
#   scripts/ci-local.sh deb        build the .deb in the container and install it on clean Debian
#
# Several legs can be given: `scripts/ci-local.sh quick linux`. Logs go to target/ci-local/.
# Needs: Rust, uv, Docker for the Linux legs, cargo-deny for deps, nightly + cargo-fuzz for fuzz.
# macOS ships bash 3.2: no `set -u` (empty arrays), no newer features.
set -o pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
LOGS="$ROOT/target/ci-local"
mkdir -p "$LOGS"
export PATH="$HOME/.cargo/bin:$PATH"
OS="$(uname -s)"
# If the selected Xcode cannot compile (say, its licence was never accepted), use the
# Command Line Tools instead.
if [ "$OS" = Darwin ] && [ -z "${DEVELOPER_DIR:-}" ] && [ -d /Library/Developer/CommandLineTools ] \
   && ! cc --version >/dev/null 2>&1; then
  export DEVELOPER_DIR=/Library/Developer/CommandLineTools
fi

# Failed steps are collected in a file, since each leg's output is piped through tee.
FAILED="$(mktemp "$LOGS/failed.XXXXXX")"
failed() { echo "$1" >> "$FAILED"; echo "FAILED: $1"; }
step() {
  local name="$1"; shift
  printf '\n==> %s\n' "$name"
  "$@" || { failed "$name"; return 1; }
}
desktop() { (cd apps/desktop && CARGO_TARGET_DIR="$ROOT/target" "$@"); }
insecure_check() {
  if cargo tree -q "$@" -e normal,build,features | grep -q insecure-test-executor; then
    echo "insecure-test-executor is enabled in a shipped dependency graph" >&2
    return 1
  fi
}

quick() {
  step "fmt" cargo fmt --all -- --check
  step "clippy" cargo clippy -q --workspace --all-targets -- -D warnings
  step "desktop app: fmt" desktop cargo fmt -- --check
}

mac() {
  [ "$OS" = Darwin ] || { failed "mac (not macOS)"; return; }
  quick
  # With Docker here, the container-runner tests run too (and must not skip). The runner itself
  # never downloads images, so the test images are pulled first, as CI does.
  local docker=0
  if command -v docker >/dev/null && docker info >/dev/null 2>&1; then
    step "test images for the container runner" \
      sh -c 'docker pull -q alpine:3.20 >/dev/null && docker pull -q python:3.12-slim >/dev/null' && docker=1
  fi
  local need_container=""; [ "$docker" = 1 ] && need_container=1
  # As in CI: the sandbox and loopback-discovery tests must run, never skip.
  step "tests (sandbox and discovery required)" \
    env GMC_REQUIRE_SANDBOX=1 GMC_REQUIRE_MDNS=1 GMC_REQUIRE_DOCKER=$docker cargo test -q --workspace
  step "shipped binaries exclude the insecure test executor" insecure_check -p gimmecores-cli
  step "build gmcd for the Python tests" cargo build -q -p gimmecores-cli
  # Against the working tree, not the last commit, so it holds before a commit too.
  step "generated stubs match spec/proto" proto_stubs_match
  # Python 3.11 here, so it differs from the lender's: a pool that built packages for this
  # device instead of the lender would fail the targeting tests.
  step "Python SDK against two real daemons" \
    sh -c "cd python && GMC_BIN_DIR='$ROOT/target/debug' GMC_REQUIRE_DISTINCT_PYTHON=1 \
           GMC_REQUIRE_CONTAINER=$need_container \
           uv run -q --python 3.11 --group dev pytest -q -rs"
  step "trusted mode, with the lender's Python" mac_trusted
  step "desktop app: clippy" desktop cargo clippy -q --all-targets -- -D warnings
  step "desktop app: tests" desktop cargo test -q
  step "desktop app excludes the insecure test executor" desktop insecure_check
}
proto_stubs_match() {
  local before; before="$(mktemp -d)"
  (cd python && cp -R src/gimmecores/_proto "$before/" && ./scripts/gen_proto.sh >/dev/null \
    && diff -r -x __pycache__ "$before/_proto" src/gimmecores/_proto)
  local rc=$?
  rm -rf "$before"
  return $rc
}
mac_trusted() {
  (cd python && export GMC_BIN_DIR="$ROOT/target/debug" GMC_REQUIRE_TRUSTED=1 \
    && GMC_LENDER_PYTHON_OUT="$LOGS/lender-python" uv run -q --group dev pytest -q \
         tests/test_trusted.py -k report_the_lenders_python \
    && PY="$(cat "$LOGS/lender-python")" && echo "lender Python: $PY ($("$PY" --version))" \
    && UV_PROJECT_ENVIRONMENT=.venv-lender uv run -q --python "$PY" --group dev pytest -q tests/test_trusted.py)
}

# On macOS, the container downloads (Python packages, crates, Python itself) go through a
# short-lived HTTPS tunnel on this Mac (scripts/ci/proxy.py: loopback only, port 443 only, TLS end
# to end): some Docker Desktop setups fetch from PyPI's CDN at a few KB/s, the Mac does not.
# GMC_CI_NO_PROXY=1 turns it off.
PROXY_PID=""
PROXY_ENV=()
start_proxy() {
  [ "$OS" = Darwin ] && [ -z "${GMC_CI_NO_PROXY:-}" ] || return 0
  local portfile="$LOGS/proxy.port"; rm -f "$portfile"
  python3 -I scripts/ci/proxy.py > "$portfile" & PROXY_PID=$!
  local i; for i in 1 2 3 4 5 6 7 8 9 10; do [ -s "$portfile" ] && break; sleep 0.5; done
  [ -s "$portfile" ] || { failed "start the download proxy"; return 1; }
  local url="http://host.docker.internal:$(cat "$portfile")"
  PROXY_ENV=(-e "HTTPS_PROXY=$url" -e "https_proxy=$url")
}
stop_proxy() { [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null; PROXY_PID=""; PROXY_ENV=(); }
trap 'stop_proxy; rm -f "$FAILED"' EXIT

linux_image() {
  local platform="$1"
  # The current context's own builder, which loads the image into it (a builder selected with
  # `docker buildx use` for other work may not).
  docker buildx build --builder "$(docker context show)" --load -q --platform "$platform" \
    -t "gimmecores-ci:${platform#linux/}" -f scripts/ci/Dockerfile.linux scripts/ci >/dev/null
}
linux() {
  local platform="${1:-}"
  if [ -z "$platform" ]; then
    case "$(uname -m)" in arm64|aarch64) platform=linux/arm64 ;; *) platform=linux/amd64 ;; esac
  fi
  command -v docker >/dev/null || { failed "linux (Docker is needed)"; return; }
  local arch="${platform#linux/}"
  step "Linux image ($arch)" linux_image "$platform" || return
  # --privileged only so bubblewrap can create its namespaces inside the container (as it can
  # on a real Linux machine). The repository is mounted read-only; build output and caches
  # live in named volumes so the next run is incremental.
  start_proxy || return
  step "Linux jobs ($arch)" docker run --rm --privileged --platform "$platform" \
    ${PROXY_ENV[@]+"${PROXY_ENV[@]}"} -v "$ROOT:/src:ro" \
    -v "gimmecores-ci-target-$arch:/work/target" \
    -v "gimmecores-ci-desktop-target-$arch:/work/apps/desktop/target" \
    -v "gimmecores-ci-cargo-$arch:/cargo-home" \
    -v "gimmecores-ci-cache-$arch:/home/tester/.cache" \
    "gimmecores-ci:$arch" bash /src/scripts/ci/linux.sh
  stop_proxy
}

deps() {
  command -v cargo-deny >/dev/null || { failed "deps (cargo install cargo-deny --locked)"; return; }
  step "dependency policy" cargo deny --log-level error check
  step "desktop app dependency policy" cargo deny --log-level error --manifest-path apps/desktop/Cargo.toml check
  if command -v actionlint >/dev/null; then
    step "workflow files (actionlint)" actionlint
  elif command -v docker >/dev/null; then
    step "workflow files (actionlint)" docker run --rm -v "$ROOT:/repo:ro" --workdir /repo \
      rhysd/actionlint:1.7.7 -color=false
  fi
}

fuzz() {
  local secs="${1:-60}"
  if [ "$OS" = Darwin ]; then
    # libFuzzer's C++ needs the SDK's headers on macOS (see fuzz/README.md).
    local sdk; sdk="$(xcrun --show-sdk-path 2>/dev/null || echo /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk)"
    export CXXFLAGS="-isysroot $sdk -I$sdk/usr/include/c++/v1"
  fi
  step "fuzz seeds" cargo test -q -p gimmecores-node --test fuzz_smoke write_fuzz_seeds -- --ignored
  local t
  for t in $(cd fuzz && cargo +nightly fuzz list); do
    step "fuzz $t (${secs}s)" cargo +nightly fuzz run "$t" -- \
      -max_total_time="$secs" -rss_limit_mb=2048
  done
}

deb() {
  local arch; case "$(uname -m)" in arm64|aarch64) arch=arm64 ;; *) arch=amd64 ;; esac
  step "Linux image ($arch)" linux_image "linux/$arch" || return
  rm -rf "$LOGS/deb" && mkdir -p "$LOGS/deb"
  start_proxy || return
  step "build the .deb" docker run --rm --platform "linux/$arch" \
    ${PROXY_ENV[@]+"${PROXY_ENV[@]}"} -v "$ROOT:/src:ro" -v "$LOGS/deb:/out" \
    -v "gimmecores-ci-target-$arch:/work/target" \
    -v "gimmecores-ci-cargo-$arch:/cargo-home" \
    "gimmecores-ci:$arch" bash -c '
      set -e
      (cd /src && git -c safe.directory=/src ls-files -z -co --exclude-standard) \
        | while IFS= read -r -d "" f; do [ -e "/src/$f" ] && printf "%s\0" "$f"; done \
        | tar -C /src --null -T - -cf - | tar -C /work -xf -
      bash packaging/linux/build-deb.sh && cp dist/*.deb /out/'
  stop_proxy
  step "install the .deb on clean Debian" docker run --rm --platform "linux/$arch" \
    -v "$LOGS/deb:/deb:ro" debian:bookworm bash -c '
      set -e
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq >/dev/null
      apt-get install -y -qq /deb/gimmecores_*.deb desktop-file-utils >/dev/null
      gmc --help >/dev/null && gmcd --help >/dev/null
      desktop-file-validate /usr/share/applications/gimmecores.desktop
      grep -qx "ExecStart=/usr/bin/gmcd" /usr/lib/systemd/user/gmcd.service
      test -f /usr/share/polkit-1/actions/dev.gimmecores.policy
      ! ldd /usr/bin/gimmecores-desktop | grep "not found"
      echo "installs and runs on clean Debian"'
}

run_leg() {
  local leg="$1"; shift
  local log="$LOGS/$leg${1:+-${1#linux/}}.log"
  echo "### $leg $* (log: $log)"
  local before; before="$(wc -l < "$FAILED")"
  "$leg" "$@" 2>&1 | tee "$log"
  if [ "$(wc -l < "$FAILED")" -eq "$before" ]; then echo "### $leg passed"; else echo "### $leg had failures"; fi
}

[ $# -eq 0 ] && set -- mac linux deps
while [ $# -gt 0 ]; do
  case "$1" in
    quick|mac|deps|deb) run_leg "$1" ;;
    linux) run_leg linux ;;
    linux-amd64) run_leg linux linux/amd64 ;;
    fuzz)
      if [[ "${2:-}" =~ ^[0-9]+$ ]]; then run_leg fuzz "$2"; shift; else run_leg fuzz; fi ;;
    *) echo "unknown leg: $1 (see the top of $0)"; exit 2 ;;
  esac
  shift
done

echo
if [ ! -s "$FAILED" ]; then echo "CI (local): everything passed"; exit 0; fi
echo "CI (local): $(wc -l < "$FAILED" | tr -d ' ') step(s) failed:"; sed 's/^/  - /' "$FAILED"
exit 1
