# Task speed: how lent tasks share the lender's cores

Status: **built** for the sandbox on macOS and Linux (2026-11-15). Containers do not apply
levels yet, and say so wherever a level is shown. Windows does not lend yet.

## What the owner chooses

Three levels, from the owner's point of view:

| Level | What it means | macOS (sandbox) | Linux (sandbox) |
|---|---|---|---|
| **Your apps first** (default) | Borrowed work uses what the owner's apps leave | QoS clamp `utility` (`taskpolicy -c utility`) | `nice 10` |
| **Background** | Idle time only; the owner barely notices it | darwin background (`taskpolicy -b`): efficiency cores, throttled I/O | `nice 19` and `SCHED_IDLE` (`chrt --idle 0`; nice 19 alone without `chrt`) |
| **Full speed** | Like the owner's own apps | no clamp (the service runs `Interactive`) | `nice 0` |

`nice` does nothing on macOS (tasks inherit the service's scheduling), which is why levels use
the QoS clamp there. Before this, Linux tasks always ran at `nice 10` and macOS tasks at full
speed.

### Measured on an M2 Max (8 + 4 cores), 2026-11-15

The owner's work: 8 processes of fixed CPU work (3.50 s alone). Borrowed work: 12 busy
processes in the real task sandbox profile, for 14 s.

| Level | Owner's work while lending | Borrowed work done meanwhile | Borrowed work, Mac otherwise idle |
|---|---|---|---|
| Full speed | 6.39 s (+83%) | 5,553 units | 4,031 units / 8 s |
| Your apps first | 3.98 s (+14%) | 3,575 | 2,268 (56% of full) |
| Background | 3.56 s (+2%) | 771 | 406 (10% of full) |

So "your apps first" costs borrowed work about half its speed even when the Mac is idle (macOS
keeps clamped work off part of the cores), and "background" about nine tenths.

## Who decides

- **The lender's owner sets a level** (Settings, `gmc speed`). Default: your apps first. A
  faster level needs presence (Touch ID / Windows Hello / password), as loosening any lending
  protection does; a slower one never does. Every change is audited.
- **A grant may name a level.** The borrower can ask for one (`gmc grants request --speed`);
  the lender sees it in the request ("FASTER than your setting" when it is), and approving the
  request (which always needs presence) fixes it for that grant. The approval prompt names it.
  The lender may accept with a lower level, never a higher one (reduce-only, like every limit).
- **A grant that names no level** follows the owner's setting when each task starts, so
  lowering the setting applies to the next task at once, without approval.
- **A task may ask for a slower level** than its grant (`gmc run --speed`,
  `gmc.Pool(speed=...)`), never a faster one: the lender takes the slower of the two.
- **The lender computes the level itself** (`speed::effective`): the grant's, or the setting
  for grants that name none, lowered to the task's ask. `0` on the wire is "not stated"; a value
  a device does not know reads as the slowest, never as full.
- Standing rules (not built yet) must never approve a request that asks for more than the
  owner's setting.

## A task cannot lift its level

Checked by a test on each OS (`sandbox_hostile::a_task_runs_at_its_level_and_cannot_lift_it`)
and by hand on this Mac: inside the sandbox, `renice`, `taskpolicy -B -p $$`, `chrt -o` and
Python's `os.setpriority` are all refused (the macOS profile denies `setpriority`; on Linux an
unprivileged process cannot lower its niceness or leave `SCHED_IDLE`). The level is seen from
outside: macOS priority 20 (your apps first) or 4 (background); Linux niceness 10, or 19 and
class `IDL`.

## Containers

Not applied yet, and shown as "not applied to containers yet":
- macOS: containers run inside Docker Desktop's VM, so no host-side level reaches them.
- Linux: Docker's `--cpu-shares` competes with other system services' cgroups, not with the
  owner's own apps in their user session, so it would not protect the owner. Containers are
  still hard-capped at the grant's cores (`--cpus`).

## Shown on both sides

Each task's level travels in `TaskUsage.task_speed` (and whether it was applied), separate from
`ServiceSpeed`, which stays the warning that the system holds the whole service back. The
lender's Activity cards, `gmc tasks`, and the borrower's view of its tasks elsewhere show it.

The borrower also sees the level before a task runs:
- A signed grant carries `lender_speed`, the owner's setting when it was signed (for display;
  a grant naming no level follows the setting at each task's start). `gmc grants request`
  prints it with the grant, `gmc grants` lists it, and the MCP `devices` tool reports it per
  grant. When a grant does not fix full speed, the confirmation suggests `--speed full` for
  lending between your own devices.
- `Started` carries the level the task really runs at and whether it is applied. `gmc run`
  prints it on stderr when that is a terminal, and the MCP `job` result includes it.
Lenders older than these fields send neither; borrowers then show "the owner's setting".

## Upgrading

Lenders upgraded from 0.1.0 start at "your apps first", and grants that named no level follow
it: borrowed work on a Mac runs at about half the speed it did. The owner chooses "full speed"
to get the old behaviour.
