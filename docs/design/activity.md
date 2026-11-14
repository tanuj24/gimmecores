# Activity: what runs, what it asked for, what it uses

Status: **stage 1 built** (this computer's side). Stages 2 and 3 are planned and marked as
such below.

## Why

A lender should see exactly what other devices run on it, what each task asked for and what it
really uses, and be able to stop one task without ending the grant. A borrower should see the
same about its own tasks elsewhere, as the lender reports them. Before this, the lender kept
only `task id -> (device, cancel handle)`, the borrower kept nothing, and CPU was measured
nowhere, so a complaint like "tasks ran slowly on that Mac" could not be checked by either side.

## Rules

- **Unknown is never zero.** Every figure is either measured or "not measured" (`optional` in
  the protocol, `null` in the app, the words "not measured" on screen).
- **Command text is untrusted.** Arguments are shown one by one (boundaries kept), control and
  invisible characters escaped (never deleted, so words never merge), each cut to 64
  characters, at most 12 shown; likely secrets (`--token=…`, `API_KEY=…`, a bare `--password`
  followed by its value, known token shapes) are hidden first. Variables: names only.
  Hiding is a heuristic, and the screens say so (`activity.rs`, also run by the `text` fuzz
  target).
- **History is in memory only**, bounded, and per device: at most 8 groups of finished tasks
  per device and 32 in all (a device's own oldest goes first, so one device cannot push out
  another's), gone when the service stops, a device's history gone when it is unpaired.
  Nothing per task is added to the audit log, and history is never rebuilt from it.
- **Listings are on the Control socket only.** Rows carry text other devices chose, so the
  Client socket (SDKs, `gmc run`, `gmc mcp` for AI agents) never sees them.
- **Live figures are read, not pushed.** `WatchEvents` sends `activity_changed` when a task
  appears, ends or changes phase; never for figures. A view that shows live rows calls
  `ListActivity` once a second while it is visible.
- **Stopping one task is reduce-only**: no presence check, the grant and the device's other
  tasks are untouched, the borrower is told why, and the stop is audited.

## What the lender measures (stage 1)

| Runner | CPU now / CPU time | Memory now / peak | Processes | Disk |
|---|---|---|---|---|
| macOS sandbox | `ps -o time=` over the task's process tree, every 500 ms (the same `ps` call that already enforces the memory limit, one more column). CPU time is a lower bound: a process that starts and ends between two samples is not seen | sum of RSS over the tree; peak is the highest sample | tree size | the folder walk that enforces the grant's disk limit, every 1–5 s |
| Linux sandbox | `/proc/<pid>/stat` (utime + stime + children's), held so it never decreases | as macOS | as macOS | as macOS |
| Container (Docker) | **not measured yet** (stage 3: the runtime's stats) | not measured yet | not measured yet | as above |

If the time column cannot be read, the sampler falls back to the exact `ps` call used before,
and CPU reads "not measured": enforcement never depends on the new column.

"Frozen" is shown only when the task's own runner confirmed it froze the task.

## How a task ended

One function (`activity::outcome`) decides, from what the runner returned and the first stop
reason recorded while it ran. The protocol's status values are unchanged (older borrowers read
what they always did); a cause is added: exited, own time limit, grant expired, grant revoked,
lending off, unpaired, Trusted mode ended, stopped by the owner, paused too long, memory limit,
disk limit, cancelled by the borrower, borrower gone, could not start, results not stored,
service stopping. The lender also sends its final figures with the result (`TaskResult.cause`
and `final_usage`, additive). For a stop by the owner, a pause that lasted too long, or the
service stopping, the borrower's user also reads one line on the task's error output.

## Interfaces (stage 1)

- `Control.ListActivity` → running tasks here (command, device, phase, asked, grant, figures)
  and finished groups; `Control.StopTask`.
- `gmc tasks [--all] [--watch]`, `gmc tasks stop <id>`; 80 columns, plain text.
- The desktop app: three views (Activity, Devices, Settings); requests, pairing codes and
  warnings stay above them on every view; live task cards update in place.

## Planned

- **Stage 2, the borrower's side:** the lender sends its figures while a task runs
  (`TaskEvent.usage`, rate and size bounded by the borrower); the borrower keeps a record per
  job with its own phases (checking files, uploading, waiting, running, fetching results) and
  shows the lender's figures labelled as the lender's report; `CancelJob` works from any
  client; the lender's speed level reaches the borrower.
- **Stage 3:** the Devices view with reachability (last authenticated contact) and grants that
  cannot look usable once dead on the other side; container figures from the runtime's stats.
