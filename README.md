# GimmeCores

**Borrow CPU, RAM and GPU from machines next to you, with their owner's consent.**

GimmeCores lets a developer run builds, tests, scripts, containers and GPU jobs on another
machine on the same Wi-Fi/LAN or connected by a Thunderbolt/USB4/Ethernet cable. Work is
bundled into tasks, sent to a peer whose owner granted access, and the results come back.

The command is `gimmecores`, with the short alias `gmc` used throughout these docs.

> **Status: design phase (M0).** There is no code yet. The specifications in `docs/` and `spec/`
> are drafts open for review. See the [roadmap](docs/ROADMAP.md).

## How it will work

```console
$ gmc pair                      # both screens show the same 6-digit code; both confirm
$ gmc grants request "Desktop" --cpus 8 --memory 16g --for 4h
  (the desktop's owner sees exactly what is asked and accepts, edits or declines)
$ gmc run -- pytest -n 8        # runs on the desktop, logs stream back
```

```python
import gimmecores as gmc

@gmc.task(cpus=2, memory="4g")
def render(frame: int) -> dict: ...

if __name__ == "__main__":
    with gmc.Pool() as pool:
        results = pool.map(render, range(500))
```

## Trust and security first

Lending your machine is a big deal. GimmeCores is built so that:

- **Nothing runs without consent.** Lending is off by default. Every use needs a grant the
  owner accepted, with limits on CPU, RAM, GPU, disk, network and time.
- **The lender enforces the limits**, not the borrower.
- **Jobs are sandboxed** in containers with no access to the owner's files and no network by default.
- **Everything is encrypted and authenticated** device-to-device; pairing defeats impostors on
  the same Wi-Fi.
- **One click stops everything.** Revoking ends running jobs within seconds.
- **Everything is logged** on both machines.
- **We say what we cannot protect.** For example: a lender can see the code and data you send it.

Read the full [threat model](docs/design/threat-model.md).

## What GimmeCores is not

It does not make another machine's RAM or GPU appear as part of yours to arbitrary programs —
the network is 10–1000× too slow for that (about 10× for Thunderbolt 5 RDMA, 60× for Thunderbolt networking, 1000× for Wi-Fi). It moves *work* to where the resources are. See
[feasibility](docs/design/feasibility.md).

## Documentation

- [Architecture overview](docs/design/overview.md)
- [Threat model](docs/design/threat-model.md)
- [Pairing](docs/design/pairing.md)
- [Consent and grants](docs/design/consent-and-grants.md)
- [Python SDK](docs/design/python-sdk.md)
- [Links and performance](docs/design/links-and-performance.md)
- [Feasibility](docs/design/feasibility.md)
- [`gmc.toml` spec](spec/gmc-toml.md)
- Protocol drafts: [`peer.proto`](spec/proto/gimmecores/peer/v1/peer.proto), [`local.proto`](spec/proto/gimmecores/local/v1/local.proto)

## Contributing and security

- [Contributing](CONTRIBUTING.md) (DCO sign-off required)
- [Security policy](SECURITY.md) — please report vulnerabilities privately

## Licence

[Apache License 2.0](LICENSE).
