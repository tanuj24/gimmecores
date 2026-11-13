"""The programs that run on the lender. They are sent as source text (`python3 -c`), so the
lender needs nothing installed but Python.

Standard mode (`SOURCE`) calls one function by its import name for each argument set and prints
the results as one tagged JSON line. Nothing is ever unpickled, on either side.

Trusted mode (`TRUSTED_SOURCE`) loads the function and arguments the borrower pickled (in
`.gmc-sdk/`, with the borrower's own copy of cloudpickle) and prints the results pickled. The
borrower decodes them only when its own daemon confirms Trusted mode (see `Pool(trusted=True)`).
"""

#: Printable prefix of the result line; each task adds a random tag (`spec["tag"]`) so output
#: printed by the function itself can never be taken for the result. (The daemon strips control
#: characters from a lender's output, so the marker must be printable.)
MARK = "GMC-RESULT-"

#: Where an SDK's own files arrive in the task folder (the daemon's `.gmc-sdk/`).
SDK_DIR = ".gmc-sdk"

# User modules import gimmecores for @gmc.task; the lender need not have it installed.
_STANDIN = r'''
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
'''

SOURCE = r'''
import base64, importlib, json, sys, traceback
spec = json.loads(base64.b64decode(sys.argv[1]).decode("utf-8"))
sys.path.insert(0, ".")
base = spec.get("base", ".")
if base not in (".", "") and not base.startswith("/") and ".." not in base.split("/"):
    sys.path.insert(0, base)
''' + _STANDIN + r'''
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

TRUSTED_SOURCE = r'''
import base64, json, os, sys, traceback
d = ".gmc-sdk"
with open(os.path.join(d, "spec.json")) as f:
    spec = json.load(f)
def emit(text):
    sys.stdout.flush()
    sys.stdout.write("GMC-RESULT-" + spec["tag"] + " " + text + "\n")
    sys.stdout.flush()
want = tuple(spec["python"])
if tuple(sys.version_info[:2]) != want:
    # Checked before loading anything: pickles do not move between Python versions.
    emit(json.dumps({"refused": "Python %d.%d here, but %d.%d on your device; Trusted mode "
                     "needs the same Python version on both" % (sys.version_info[:2] + want)}))
    sys.exit(0)
sys.path.insert(0, os.path.join(d, "lib"))  # the borrower's cloudpickle (same version)
sys.path.insert(1, ".")
base = spec.get("base", ".")
if base not in (".", "") and not base.startswith("/") and ".." not in base.split("/"):
    sys.path.insert(1, base)
''' + _STANDIN + r'''
import pickle
import cloudpickle
with open(os.path.join(d, "call.pkl"), "rb") as f:
    fn, calls = pickle.load(f)
out = []
for args, kwargs in calls:
    try:
        out.append(("ok", fn(*args, **kwargs)))
    except Exception as e:
        tb = traceback.format_exc()
        try:
            cloudpickle.dumps(e)
            out.append(("error", e, tb))
        except Exception:
            out.append(("error", RuntimeError("%s: %s" % (type(e).__name__, e)), tb))
try:
    data = cloudpickle.dumps(out)
except Exception as e:
    err = TypeError("a result could not be pickled: %s" % e)
    data = cloudpickle.dumps([("error", err, "")] * len(calls))
emit(base64.b64encode(data).decode())
'''
