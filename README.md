# GimmeCores

**Borrow CPU, RAM and GPU from machines next to you, with their owner's consent.**

GimmeCores lets a developer run builds, tests, scripts, containers and GPU jobs on another
machine on the same Wi-Fi/LAN or connected by a Thunderbolt/USB4/Ethernet cable. Work is
bundled into tasks, sent to a peer whose owner granted access, and the results come back.

The command is `gimmecores`, with the short alias `gmc` used throughout these docs.

> **Status: early development (M1, branch `v1`).** Pairing, grants, remote runs, the audit log
> and laptop protections work end to end **between two daemons on one machine over loopback**,
> and Windows borrowing from Linux works between two virtual machines on one Mac. Paired
> devices find each other on the local network (mDNS). Tasks run in a container (real Docker,
> tested on macOS and in Linux CI) or in the OS sandbox (Seatbelt on macOS, bubblewrap on
> Linux), each with its own attack tests. Not yet verified: two physical machines over Wi-Fi or
> a cable. Approvals (pairing, accepting a request, turning lending on) are checked by the
> daemon with Touch ID / your password on macOS, polkit on Linux, and Windows Hello / your
> Windows password on Windows; the macOS prompt has been checked by hand and the Windows ones
> in a Windows 11 VM, the Linux one not yet. **On Windows this version borrows only:** lending
> a Windows PC is refused until it is tested on a real PC ([Windows](docs/design/windows.md)).
> Do not lend to devices you don't fully trust yet. See the [roadmap](docs/ROADMAP.md).

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

**macOS app (Apple silicon):** once a release is published, install GimmeCores in your
Applications folder, from the release's `GimmeCores.dmg` (drag it onto Applications) or with
Homebrew:

```sh
brew tap tanuj24/gimmecores https://github.com/tanuj24/gimmecores
brew install --cask gimmecores           # GimmeCores.app in Applications; gmc and gmcd on PATH
```

It is not signed with an Apple Developer ID yet: the first time, macOS blocks it, and
**Open Anyway** in System Settings > Privacy & Security lets it run. After that it updates
itself: **Settings > Updates > Check for updates** (it goes online only then). Every update
must be signed with the GimmeCores update key, which the app checks before replacing itself
([how](docs/RELEASING.md)).

**Windows 10 and 11** (x64; Windows on ARM through its x64 emulation): once a release is
published, run its `GimmeCores-<version>-x64-setup.exe`. It is not signed yet, so SmartScreen
asks once: **More info > Run anyway**. It installs the app, the background service (started at
sign-in from the app) and `gmc` on the PATH; approvals use Windows Hello, or where it is not set up
the Windows password on Windows' secure screen (after Ctrl+Alt+Delete). On Windows this version
**borrows**: it runs your work on your other computers. Lending a Windows PC comes in a later
version (`gmcd` refuses it until it is tested). Details: [Windows](docs/design/windows.md).

**Homebrew from source** builds everything on your machine, so there is no pre-built binary
for macOS to warn about; `brew upgrade` updates it, not the app. Use this or the cask, not
both. (Linux Homebrew builds are untested.)

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
- **Linux (Debian/Ubuntu):** `packaging/linux/build-deb.sh` builds `dist/gimmecores_<version>_<arch>.deb`
  with the desktop app, `gmcd`, `gmc`, `gimmecores`, the polkit policy used for approvals and a
  systemd user unit (not enabled). Install it with `sudo apt install ./dist/gimmecores_*.deb`,
  then open GimmeCores and click **Start GimmeCores** (or `systemctl --user enable --now gmcd`).
  `GMC_NO_DESKTOP=1` builds it without the app (servers, Raspberry Pi).
- **Linux, any distribution:** `cargo build --release && packaging/linux/install.sh --enable`
  installs into `~/.local/bin` with a systemd user service, and offers to install the polkit
  policy. The sandbox runtime needs `bubblewrap`.

### Desktop app (macOS, Linux, Windows)

A window and a menu-bar (tray) icon for everything that needs your consent. Requests to use your
computer (accept / decline) and pairing codes stay at the top; below them, three views:

- **Activity**: every task other devices run on this computer, live: the command (arguments
  that look like secrets hidden), which device, what it asked for against what it uses (CPU,
  memory, its folder's size, time), **Stop task** for one task, and what finished recently and
  how it ended. Figures that were not measured say so; they are never shown as zero.
- **Devices**: each paired device with what it may use here (revoke) and what you may use there;
  pairing; Trusted mode; unpair.
- **Settings**: the lending switch, laptop protections, ways of running tasks, and this
  computer's options.

It notifies you when a device asks to use your computer. It connects to a running `gmcd` and
never starts it; approvals still go through `gmcd`'s own check (Touch ID, Windows Hello or your
password). In a terminal, `gmc tasks` shows the same live list (`--all` adds finished tasks,
`--watch` redraws it) and `gmc tasks stop <id>` stops one task.

```console
$ gmcd                                   # in one terminal
$ cd apps/desktop && cargo run --release # in another
```

Closing the window keeps the menu-bar icon; quit from its menu.

On macOS, tasks from other devices run as fast as programs you start yourself. While one of
them uses every core, your own heavy work shares the cores with it; *Pause on battery*, *Pause
when hot* and *Only while I'm away* are your controls. Stopping GimmeCores (the app's switch,
`brew services stop`, logging out) stops every task it was running.

### AI agents (MCP)

`gmc mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server, so an agent
(Claude Code, Claude Desktop, other MCP clients) can run test suites, builds and other heavy
work on your devices that granted this one resources. Its tools: `devices`, `run`, `job`,
`jobs`, `cancel`. What it cannot do: ask for or approve access (you and the person at the other
device still do that), send folders outside its root, override the secret scan, send
environment variables, give tasks network access, or use Trusted mode. When the agent session
ends, its running tasks are stopped.

```console
$ cd ~/code/my-project
$ claude mcp add gimmecores -- gmc mcp --root "$PWD"     # Claude Code
```

For Claude Desktop (or another client that starts servers itself), give the full path and the
project folder:

```json
{ "mcpServers": { "gimmecores": {
    "command": "/opt/homebrew/bin/gmc",
    "args": ["mcp", "--root", "/Users/you/code/my-project"] } } }
```

The root defaults to the folder the server starts in; your home folder and `/` are refused.
Agents that can already run shell commands can also simply use `gmc run`.


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
- **Your apps come first.** By default, borrowed tasks use what your own apps leave (`gmc speed`
  or Settings: full speed, your apps first, or background); a faster level needs you present.
  See [task speed](docs/design/task-speed.md).
- **Everything is logged** on both machines.
- **Your device's identity stays put.** Its key is an owner-only file; on macOS you can move it
  into your login Keychain (`gmcd --identity-store keychain`), where other programs get a
  Keychain prompt instead of the key. That is opt-in for now: until releases are signed, macOS
  asks again after every upgrade of `gmcd`.
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
- [Activity: what runs, what it asked for, what it uses](docs/design/activity.md)
- [GPU lending (design)](docs/design/gpu-lending.md)
- [Task speed: how lent tasks share the lender's cores](docs/design/task-speed.md)
- [Links and performance](docs/design/links-and-performance.md)
- [Feasibility](docs/design/feasibility.md)
- [`gmc.toml` spec](spec/gmc-toml.md)
- Protocol drafts: [`peer.proto`](spec/proto/gimmecores/peer/v1/peer.proto), [`local.proto`](spec/proto/gimmecores/local/v1/local.proto)

## Contributing and security

- [Contributing](CONTRIBUTING.md) (DCO sign-off required)
- [Security policy](SECURITY.md) — please report vulnerabilities privately

## Licence

[Apache License 2.0](LICENSE).
