"""The programs that run on the lender. They are sent as source text (`python3 -c`), so the
lender needs nothing installed but Python.

Standard mode (`SOURCE`) calls one function by its import name for each argument set (from
`.gmc-sdk/spec.json`, never the command line, which other accounts on the lender could list) and
prints the results as one tagged JSON line. Nothing is ever unpickled, on either side.

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

import os as _os

#: gmc.File / gmc.Dir, run on the lender from source (it may not have gimmecores installed).
FILES_SOURCE = open(_os.path.join(_os.path.dirname(__file__), "_files.py"), encoding="utf-8").read()

_FILES = r'''
import types as _types
_gf = _types.ModuleType("_gmc_files")
exec(''' + repr(FILES_SOURCE) + r''', _gf.__dict__)
'''

# After the stand-in: the classes user code sees as gmc.File / gmc.Dir.
_FILE_CLASSES = r'''
_gm = sys.modules.get("gimmecores")
_F, _D = getattr(_gm, "File", _gf.File), getattr(_gm, "Dir", _gf.Dir)
def _arrived(path, is_dir):
    if is_dir:
        os.makedirs(path, exist_ok=True)  # only files travel: an empty folder arrives as none
    return (_D if is_dir else _F)(os.path.abspath(path))
def _args(calls):
    out = _gf.unwalk(calls, _arrived, _gf.secret_arrived)
    # Read once; child processes of the function do not inherit them.
    for k in [k for k in os.environ if k.startswith(_gf.SECRET_ENV)]:
        del os.environ[k]
    return out
'''

# The project's packages, installed on the borrower for this lender (`.gmc-sdk/env`). The
# interpreter then runs with -S, so the lender's own site-packages stay out of the way; the
# packages come after the standard library and the project, as site-packages normally do.
_PACKAGES = r'''
if spec.get("env"):
    import os, site
    if not os.path.isdir(os.path.join(".gmc-sdk", "env")):
        raise SystemExit("the project's packages did not arrive")
    site.addsitedir(os.path.abspath(os.path.join(".gmc-sdk", "env")))
'''

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
    g.File, g.Dir = _gf.File, _gf.Dir
    sys.modules["gimmecores._files"] = _gf
    g.GimmeCoresError = g.RemoteError = GimmeCoresError
    sys.modules["gimmecores"] = g
'''

SOURCE = r'''
import importlib, json, os, sys, traceback
with open(os.path.join(".gmc-sdk", "spec.json"), encoding="utf-8") as _f:
    spec = json.load(_f)
sys.path.insert(0, ".")
base = spec.get("base", ".")
if base not in (".", "") and not base.startswith("/") and ".." not in base.split("/"):
    sys.path.insert(0, base)
''' + _PACKAGES + _FILES + _STANDIN + _FILE_CLASSES + r'''
fn = importlib.import_module(spec["module"])
for part in spec["qualname"].split("."):
    fn = getattr(fn, part)
out = []
for i, (args, kwargs) in enumerate(_args(spec["calls"])):
    try:
        r = _gf.returned(fn(*args, **kwargs), i)
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
''' + _PACKAGES + _FILES + _STANDIN + _FILE_CLASSES + r'''
import pickle
import cloudpickle
with open(os.path.join(d, "call.pkl"), "rb") as f:
    fn, calls = pickle.load(f)
out = []
for i, (args, kwargs) in enumerate(_args(calls)):
    try:
        out.append(("ok", _gf.returned(fn(*args, **kwargs), i)))
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
