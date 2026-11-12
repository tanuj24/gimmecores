"""The program that runs on the lender. It is sent as source text (`python3 -c`), so the
lender needs nothing installed but Python. It calls one function by its import name for each
argument set and prints the results as one tagged JSON line. Nothing is ever unpickled."""

#: Printable prefix of the result line; each task adds a random tag (`spec["tag"]`) so output
#: printed by the function itself can never be taken for the result. (The daemon strips control
#: characters from a lender's output, so the marker must be printable.)
MARK = "GMC-RESULT-"

SOURCE = r'''
import base64, importlib, json, sys, traceback
spec = json.loads(base64.b64decode(sys.argv[1]).decode("utf-8"))
sys.path.insert(0, ".")
base = spec.get("base", ".")
if base not in (".", "") and not base.startswith("/") and ".." not in base.split("/"):
    sys.path.insert(0, base)
# User modules import gimmecores for @gmc.task; the lender need not have it installed.
try:
    import gimmecores
except ImportError:
    import types
    g = types.ModuleType("gimmecores")
    def task(fn=None, **options):
        return fn if fn is not None else (lambda f: f)
    class _NotHere:
        def __init__(self, *a, **k):
            raise RuntimeError("GimmeCores pools cannot be used inside a remote task")
    class GimmeCoresError(Exception):
        pass
    g.task, g.Pool, g.Executor = task, _NotHere, _NotHere
    g.GimmeCoresError = g.RemoteError = GimmeCoresError
    sys.modules["gimmecores"] = g
fn = importlib.import_module(spec["module"])
for part in spec["qualname"].split("."):
    fn = getattr(fn, part)
out = []
for args, kwargs in spec["calls"]:
    try:
        r = fn(*args, **kwargs)
        try:
            json.dumps(r)
        except (TypeError, ValueError):
            raise TypeError(
                "the result (%s) is not JSON-serializable; Standard mode returns results as JSON"
                % type(r).__name__
            ) from None
        out.append({"ok": r})
    except Exception as e:
        out.append({"error": {"type": type(e).__name__, "message": str(e),
                              "traceback": traceback.format_exc()}})
sys.stdout.flush()
sys.stdout.write("GMC-RESULT-" + spec["tag"] + " " + json.dumps(out) + "\n")
sys.stdout.flush()
'''
