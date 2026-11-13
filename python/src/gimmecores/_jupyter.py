"""Jupyter: `%load_ext gimmecores`, then `%gmc` shows your devices, Trusted mode and grants.

Functions defined in notebook cells travel by value, so they need Trusted mode:

    %load_ext gimmecores
    import gimmecores as gmc
    with gmc.Pool(trusted=True) as pool:
        pool.map(lambda x: x * x, range(10))

Trusted mode cannot be turned on from a notebook (it needs your Touch ID or password, and the
SDK has no way to ask for it); `%gmc` says what to run instead.
"""

from __future__ import annotations

import datetime as _dt

from . import _daemon
from ._proto.gimmecores.local.v1 import local_pb2 as l
from ._proto.gimmecores.peer.v1 import peer_pb2 as pb


def status_text(home=None) -> str:
    try:
        stub = _daemon.client(_daemon.home(home))
        peers = [p for p in stub.ListPeers(l.ListPeersRequest()).peers if p.paired]
        grants = [
            g
            for g in stub.ListGrants(l.ListGrantsRequest(include_inactive=False)).grants
            if not g.as_lender and g.state == pb.GRANT_STATE_ACTIVE
        ]
    except Exception as e:  # noqa: BLE001 (shown to the user)
        return (
            f"GimmeCores: no daemon ({e.__class__.__name__}). Start it with `gmcd` or the "
            "GimmeCores app; until then pools run on this computer."
        )
    if not peers:
        return "GimmeCores: no paired devices yet (`gmc pair` on both, or the app)."
    lines = ["GimmeCores devices:"]
    for p in sorted(peers, key=lambda p: p.device_name.lower()):
        if p.trusted_mode_local and p.trusted_mode_remote:
            until = _dt.datetime.fromtimestamp(p.trusted_until.seconds).strftime("%Y-%m-%d")
            trust = f"Trusted mode on both sides (here until {until})"
        elif p.trusted_mode_local:
            trust = f"Trusted mode on here only (on {p.device_name}: gmc trust <this device> on)"
        else:
            trust = "Trusted mode off (notebook functions need it: gmc trust "
            trust += f"{p.device_name} on, on both devices)"
        mine = [g for g in grants if g.peer_fingerprint == p.fingerprint]
        if mine:
            parts = []
            for g in mine:
                lim = g.grant.limits
                kind = "Trusted" if g.grant.trust == pb.TRUST_LEVEL_TRUSTED else "standard"
                parts.append(f"{lim.cpu_millis / 1000:g} cores, {lim.memory_bytes >> 30} GiB ({kind})")
            have = "grants: " + "; ".join(parts)
        else:
            have = f"no grant (gmc grants request {p.device_name} --trusted)"
        state = "online" if p.online else "offline"
        lines.append(f"  {p.device_name} [{state}]: {have}; {trust}")
    return "\n".join(lines)


def _magic(line: str = "") -> None:
    arg = line.strip()
    if arg in ("", "status"):
        print(status_text())
    else:
        print("usage: %gmc [status]")


def load_ipython_extension(ipython) -> None:
    ipython.register_magic_function(_magic, magic_kind="line", magic_name="gmc")
    print(status_text())


def unload_ipython_extension(ipython) -> None:  # nothing to undo beyond the magic
    pass
