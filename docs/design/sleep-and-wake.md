# Sleep and wake

Status: built on `v2` (issue #30). Wake-on-LAN is opt-in, off by default (owner's decision,
2026-11-16).

## Staying awake while tasks run

A lender that goes to idle sleep mid-task stalls or loses the task. While at least one task
from another device runs, and lending is not paused (battery, heat), `gmcd` holds off idle
sleep with the system's own tool, as a child process in its own process group:

| System | Tool | Ends when |
|---|---|---|
| macOS | `caffeinate -i -w <gmcd pid>` | the last task ends, the owner turns it off, or `gmcd` exits |
| Linux | `systemd-inhibit --what=idle:sleep --mode=block ... tail --pid=<gmcd pid> -f /dev/null` | the same |
| Windows | none (Windows does not lend yet) | — |

It is checked every 2 seconds. On by default; `gmc keep-awake off` or the Settings switch turns
it off, and turning it back on needs presence (like loosening any laptop protection).
`gmc status` says whether the computer is being kept awake now. **A closed laptop lid still
sleeps the laptop**: no tool here prevents that, and none should.

## Wake-on-LAN

A desktop that sleeps cannot be reached at all. Wake-on-LAN wakes it with a "magic packet":
six `0xFF` bytes, then the network card's address (MAC) sixteen times, sent as a UDP broadcast
on the local network.

- **The owner of the computer to be woken allows it, per device**: `gmc allow-wake <device> on`
  or "Let it wake this computer…" on the device's card in the app. Allowing needs presence and
  is audited; stopping needs nothing.
- **Only then are the addresses shared**: this computer's network cards that are up and on a
  local network (at most 4) go to that device only, in the `Hello` the two devices swap over
  their encrypted connection (`Hello.wake_macs`). That happens at once when it is allowed (if
  the device is reachable), and again on every grant request and link test. An empty list tells
  the device to forget them; stopping sends that. Unpairing deletes them on both sides. Older
  versions never send addresses.
- **Waking**: `gmc wake <device>` or "Wake it" in the app sends the packet now. `gmc run` (and
  the SDK and MCP tools through the service) and `gmc grants request` also send it by
  themselves when the device does not answer, then try again for up to 45 seconds. Packets go
  only to the broadcast address of the network the device was last seen on (port 9, three
  times), and only while this computer is on that network: a laptop in a café never sends its
  home desktop's address there, and does not wait for a computer that is not nearby.
- Whether the computer wakes is up to its hardware and settings: on a Mac, System Settings >
  Energy (or Battery > Options) > "Wake for network access"; many computers wake this way only
  on wired Ethernet.

### Why opt-in

A magic packet carries no secret: anyone on the local network who knows a card's address can
send one, and that address is visible on the local network anyway. What the opt-in controls is
which devices **keep** this computer's hardware identifier, which could be used to recognise it
elsewhere: only devices its owner chose.
