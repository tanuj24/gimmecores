#!/bin/sh
# Regenerates the gRPC stubs from spec/proto into src/gimmecores/_proto (committed).
set -eu
cd "$(dirname "$0")/.."
OUT=src/gimmecores/_proto
rm -rf "$OUT" && mkdir -p "$OUT"
uv run --group dev python -m grpc_tools.protoc -I ../spec/proto --python_out="$OUT" --grpc_python_out="$OUT" \
  gimmecores/peer/v1/peer.proto gimmecores/local/v1/local.proto
# Make the generated imports package-relative.
python3 - "$OUT" <<'PY'
import pathlib, re, sys
for f in pathlib.Path(sys.argv[1]).rglob("*.py"):
    t = f.read_text()
    t = re.sub(r"^from gimmecores\.(peer|local)\.v1 import", r"from gimmecores._proto.gimmecores.\1.v1 import", t, flags=re.M)
    f.write_text(t)
PY
for d in "$OUT" "$OUT/gimmecores" "$OUT/gimmecores/peer" "$OUT/gimmecores/peer/v1" "$OUT/gimmecores/local" "$OUT/gimmecores/local/v1"; do
  touch "$d/__init__.py"
done
