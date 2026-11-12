"""Finding and talking to the local gmcd (owner-only Unix sockets)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import grpc

from ._proto.gimmecores.local.v1 import local_pb2_grpc


def home(override: str | os.PathLike | None = None) -> Path:
    """The daemon's state folder: `override`, GMC_HOME, or the platform default."""
    if override:
        return Path(override)
    if os.environ.get("GMC_HOME"):
        return Path(os.environ["GMC_HOME"])
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "GimmeCores"
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "gimmecores"


def client(home_dir: Path) -> local_pb2_grpc.ClientStub:
    sock = home_dir / "run" / "client.sock"
    if not sock.exists():
        from ._api import GimmeCoresError

        raise GimmeCoresError("gmcd is not running (start it with `gmcd` or the GimmeCores app)")
    return local_pb2_grpc.ClientStub(channel(sock))


def channel(sock: Path) -> grpc.Channel:
    # gRPC would send the socket path as the HTTP/2 authority, which the daemon's HTTP/2 server
    # rejects as malformed; name a plain one.
    return grpc.insecure_channel(
        f"unix://{sock}", options=[("grpc.default_authority", "gmcd.local")]
    )
