#!/bin/bash
# The Linux leg of scripts/ci-local.sh. Runs inside the container built from Dockerfile.linux,
# with the repository mounted read-only at /src. Mirrors the Linux jobs of
# .github/workflows/ci.yml, step for step, and adds the desktop app (CI builds that on macOS).
set -uo pipefail
FAILED=()
step() {
  local name="$1"; shift
  printf '\n==> %s\n' "$name"
  "$@" || { FAILED+=("$name"); echo "FAILED: $name"; }
}

# The working tree, not the last commit: tracked files as they are now, plus new files that are
# not ignored, so uncommitted changes are tested too.
(cd /src && git -c safe.directory=/src ls-files -z -co --exclude-standard) \
  | while IFS= read -r -d '' f; do [ -e "/src/$f" ] && printf '%s\0' "$f"; done \
  | tar -C /src --null -T - -cf - | tar -C /work -xf -
cd /work

insecure_check() {
  if cargo tree -q "$@" -e normal,build,features | grep -q insecure-test-executor; then
    echo "insecure-test-executor is enabled in a shipped dependency graph" >&2
    return 1
  fi
}
bwrap_works() { bwrap --unshare-all --ro-bind / / true && echo "bwrap works"; }
proto_stubs_match() {
  (cd python && cp -r src/gimmecores/_proto /tmp/proto-before && ./scripts/gen_proto.sh >/dev/null \
    && diff -r /tmp/proto-before src/gimmecores/_proto)
}
python_tests() {
  # The lender's sandbox runs bookworm's python3 (3.11); the borrower uses 3.12, so a pool that
  # built packages for this device instead of the lender fails the targeting tests.
  (cd python && GMC_BIN_DIR=/work/target/debug GMC_REQUIRE_DISTINCT_PYTHON=1 \
    uv run -q --python 3.12 --group dev pytest -q -rs -p no:cacheprovider)
}
trusted_tests() {
  (cd python && export GMC_BIN_DIR=/work/target/debug GMC_REQUIRE_TRUSTED=1 \
    && GMC_LENDER_PYTHON_OUT=/tmp/lender-python uv run -q --python 3.12 --group dev \
         pytest -q -p no:cacheprovider tests/test_trusted.py -k report_the_lenders_python \
    && PY="$(cat /tmp/lender-python)" && echo "lender Python: $PY ($("$PY" --version))" \
    && UV_PROJECT_ENVIRONMENT=.venv-lender uv run -q --python "$PY" --group dev \
         pytest -q -p no:cacheprovider tests/test_trusted.py)
}
desktop() { (cd apps/desktop && "$@"); }

step "fmt" cargo fmt --all -- --check
step "clippy" cargo clippy -q --workspace --all-targets -- -D warnings
step "bubblewrap works here" bwrap_works
step "install script parses" sh -n packaging/linux/install.sh
# No Docker inside this container: the container-runner tests skip here (they run in GitHub's
# Linux runners and on a Mac with Docker Desktop). Everything else must run, never skip.
step "tests (sandbox required)" env GMC_REQUIRE_SANDBOX=1 cargo test -q --workspace
step "shipped binaries exclude the insecure test executor" insecure_check -p gimmecores-cli
step "build gmcd for the Python tests" cargo build -q -p gimmecores-cli
step "generated stubs match spec/proto" proto_stubs_match
step "Python SDK against two real daemons" python_tests
step "trusted mode, with the lender's Python" trusted_tests
step "desktop app: fmt" desktop cargo fmt -- --check
step "desktop app: clippy" desktop cargo clippy -q --all-targets -- -D warnings
step "desktop app: tests" desktop cargo test -q
step "desktop app excludes the insecure test executor" desktop insecure_check

echo
if [ ${#FAILED[@]} -eq 0 ]; then echo "LINUX: all steps passed"; exit 0; fi
echo "LINUX: ${#FAILED[@]} step(s) failed:"; printf '  - %s\n' "${FAILED[@]}"; exit 1
