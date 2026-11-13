# GimmeCores

**Borrow CPU, RAM and GPU from machines next to you, with their owner's consent.**

GimmeCores lets a developer run builds, tests, scripts, containers and GPU jobs on another
machine on the same Wi-Fi/LAN or connected by a Thunderbolt/USB4/Ethernet cable. Work is
bundled into tasks, sent to a peer whose owner granted access, and the results come back.

The command is `gimmecores`, with the short alias `gmc` used throughout these docs.

> **Status: early development (M1, branch `v1`).** Pairing, grants, remote runs, the audit log
> and laptop protections work end to end **between two daemons on one machine over loopback**.
> Tasks run in a container (real Docker, tested on macOS and in Linux CI) or in the OS sandbox
> (Seatbelt on macOS, bubblewrap on Linux), each with its own attack tests. Not yet verified:
> two physical machines over Wi-Fi or a cable. Approvals (pairing, accepting a
> request, turning lending on) are checked by the daemon with Touch ID / your password on macOS
> and polkit on Linux; the macOS prompt has been checked by hand, the Linux one not yet. Not yet built: automatic discovery, Windows. Do not lend to devices you don't fully
> trust yet. See the [roadmap](docs/ROADMAP.md).

## Try it (macOS / Linux, from source)

```console
$ cargo build --release            # binaries: target/release/{gmc,gimmecores,gmcd}

# On the machine that lends (container tasks need Docker; `gmc runtimes sandbox` needs none):
$ gmc daemon                       # or gmcd; listens on port 47474
$ gmc lend on                      # lending is off until you turn it on
$ gmc pair                         # prints a ticket and waits

# On the machine that borrows:
$ gmc daemon
$ gmc pair gmc1:…                  # paste the ticket; both screens show the same 6-digit code
$ gmc grants request <lender-name> --cpus 4 --memory 8g --hours 2

# Back on the lender: review and accept
$ gmc requests

# On the borrower, from your project folder:
$ gmc run --image python:3.12-slim --out reports -- python -m pytest
```

On macOS the first `gmcd` start shows a firewall prompt asking to accept incoming network
connections: allow it on machines that should lend or pair. Use `GMC_HOME=/some/dir` to run
more than one node on a machine.

### Install

**Homebrew** builds everything from source on your machine, so there is no pre-built binary
for macOS to warn about. (Not yet: `brew tap` reads the repository's default branch, and the
formula is on `v1` for now. Linux Homebrew builds are untested.)

```sh
brew tap tanuj24/gimmecores https://github.com/tanuj24/gimmecores
brew install --HEAD gimmecores          # gmc, gmcd and (on macOS) GimmeCores.app
brew services start gimmecores          # or use the app's "Start GimmeCores", not both
brew upgrade --fetch-HEAD gimmecores    # to update later
```

On macOS, `ln -sfn "$(brew --prefix)/opt/gimmecores/GimmeCores.app" ~/Applications/` puts the
app in Launchpad and Spotlight. Only one `gmcd` runs per user: a second one (from another
service, or a terminal) says so and exits.

Without Homebrew:

- **macOS:** `./packaging/macos/build-app.sh` builds `dist/GimmeCores.app` (and a `.dmg`). Open
  it and click **Start GimmeCores**: `gmcd` then runs in the background and starts at login
  (turn that off in the app). **Install** under "This computer" puts `gmc` on your PATH. The
  build is ad-hoc signed, so other Macs will warn until it is signed with a Developer ID.
- **Linux:** `cargo build --release && packaging/linux/install.sh --enable` installs `gmcd`,
  `gmc` and `gimmecores` into `~/.local/bin` and a systemd user service, and offers to
  install the polkit policy used for approvals. The sandbox runtime needs `bubblewrap`.

### Desktop app (macOS)

A window and a menu-bar icon for everything that needs your consent: the lending switch and
laptop protections, incoming requests (accept / decline), what is using your computer (revoke),
Stop all lending, paired devices, and pairing with ticket + code comparison. It notifies you
when a device asks to use your computer. It connects to a running `gmcd` and never starts it;
approvals still go through `gmcd`'s Touch ID / password check.

```console
$ gmcd                                   # in one terminal
$ cd apps/desktop && cargo run --release # in another
```

Closing the window keeps the menu-bar icon; quit from its menu.

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
- **Your device's identity stays put.** On macOS its key lives in your login Keychain (moved
  there from its file the first time `gmcd` starts), so other programs cannot copy it to pose
  as this device; after upgrading GimmeCores, macOS may ask once whether `gmcd` may use it.
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
