"""A minimal HTTPS (CONNECT) proxy for scripts/ci-local.sh's Linux container.

Some Docker Desktop setups download from certain hosts (PyPI's CDN, for one) at a few KB/s while
the Mac itself is fast. The container then reaches the internet through this proxy, which runs
on the Mac. It listens on 127.0.0.1 only (Docker Desktop forwards host.docker.internal to it),
tunnels only to port 443 (TLS stays end to end: the proxy sees host names, never contents), and
lives only as long as the CI run. Prints the port it listens on, then serves until killed.
"""

import asyncio
import sys


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        writer.close()


async def handle(client_r: asyncio.StreamReader, client_w: asyncio.StreamWriter) -> None:
    try:
        head = await asyncio.wait_for(client_r.readuntil(b"\r\n\r\n"), 30)
        method, target, _ = head.split(b"\r\n", 1)[0].decode("latin-1").split(" ", 2)
        host, _, port = target.rpartition(":")
        if method != "CONNECT" or port != "443" or not host:
            client_w.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            await client_w.drain()
            client_w.close()
            return
        up_r, up_w = await asyncio.wait_for(asyncio.open_connection(host, 443), 30)
    except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError,
            asyncio.LimitOverrunError):
        client_w.close()
        return
    client_w.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
    await client_w.drain()
    await asyncio.gather(pipe(client_r, up_w), pipe(up_r, client_w))


async def main() -> None:
    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    print(server.sockets[0].getsockname()[1], flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
