# Activity: what runs, what it asked for, what it uses

Status: **stage 1 built** (this computer's side), with the "This computer" bars; **stage 2
partly built**: the borrower sees its tasks on other devices with each lender's figures, and
bars per lender; **a lender's whole-machine load** is built, shared only if its owner turns it
on. The rest of stages 2 and 3, and stage 4, are planned, marked as such below.

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

## This computer as a whole

Above the task cards, the Activity view (and the top of `gmc tasks`) shows this computer's CPU,
memory and GPUs: what is in use, and how much of it tasks from other devices use. It answers
"is lending slowing me down?" without a separate tool.

| Figure | macOS | Linux | Windows |
|---|---|---|---|
| CPU in use, all programs | sysinfo: the system's CPU counters, between two readings at least 200 ms apart | the same (`/proc/stat`) | the same |
| Memory in use | total minus what the system calls available | the same | the same |
| GPUs | `ioreg` (`IOAccelerator`): name, "Device Utilization %" | `nvidia-smi` (name, memory, use); amdgpu in `/sys` (memory, `gpu_busy_percent`); Intel listed, use not measured | DXGI: name and own memory; use not measured; the software renderer is left out |
| Tasks from other devices | the sum of their own figures (above) | the same | lending is not available |

- **Measured only while it is read.** The Control handler takes the readings when
  `ListActivity` is called (the app calls it once a second while the Activity view is visible),
  never in the background. The first reading after a pause waits 200 ms for a CPU baseline;
  two windows reading at once share one reading.
- **A borrower's use is never shown as the owner's.** While any running task's figures are not
  measured (tasks in containers, until stage 3), the share of other devices is "not measured"
  and the bar is shown striped, credited to nobody, instead of "you" = total minus zero.
- **GPUs are never lent yet**, so a GPU bar is always the owner's own use, and the view says so.
- Local only: these figures are on the Control socket (`Activity.machine`), never sent to
  another device.

## Your tasks on other devices (stage 2, built so far)

- The borrower asks for figures when it sends a task (`SubmitTask.report_usage`, additive: an
  older borrower never asks, an older lender never sends). The lender then sends the task's
  figures (`TaskEvent.usage`, the same `TaskUsage` as the final report) every 2 s while it
  runs; a send blocked longer than that does not cause a burst afterwards.
- Every figure is the lender's claim, bounded on arrival (`remote::accept_report`): memory and
  disk at most the grant's (the lender enforces those); CPU kept above the grant (the sandbox
  does not cap it, and the lender's own screen shows it as over) but dropped above a fixed
  ceiling of 4096 cores; process counts above a million dropped; run and frozen time at most
  what the borrower itself saw elapse; unknown enum values read as unspecified. A report is
  kept for the task whose stream it arrived on, never the one named inside it, and stops
  counting 7 s after it arrived ("not reported", never the last figure frozen).
- The borrower keeps a record of each of its tasks elsewhere from the moment it is sent until
  its outputs are fetched (or it fails, or is cancelled): waiting, running, fetching results.
- `ListActivity` lists them only to clients that ask (`include_there`), as `DIRECTION_THERE`
  rows (at most 64) and one `BorrowedLoad` per grant held, summed in gmcd over every task
  there (not only the listed rows). Older clients read every row as running here, so they
  never get these.
- The app shows, under "You can use", each lender's grant with bars for what this device's
  tasks use there and the tasks themselves; `gmc tasks` lists them per lender. Neither can
  stop them yet (`CancelJob`, below); `gmc tasks stop` matches only tasks running here.
- Checked between two machines (`scripts/windows/e2e-borrow.sh`): Windows, borrowing from a
  Debian VM, lists its running task there with the lender's CPU and memory figures, and the
  lender lists the same task as running for Windows.

## A lender's whole computer, if its owner shares it

It tells a borrower whether a lender is busy before or while it sends work there, and it also
tells the borrower when the lender's owner is using their computer. So it is the owner's choice:

- **Off by default.** `gmc share-load on` or the app's Settings ("Let devices I lend to see how
  busy this computer is") turns it on; that needs presence and is audited. Turning it off
  needs nothing.
- **Only to holders of a live grant.** A borrower asks (`LoadRequest`, naming a grant it holds);
  the lender answers with figures only if sharing is on and the asker holds that grant, active
  or paused and not expired. Anyone else, and everyone while it is off, gets `shared = false`
  and nothing more.
- **Numbers only:** CPU, memory and each GPU's use for the whole computer, its owner's own
  programs included. No programs, no other borrowers' tasks, no per-task split.
- **Asked only while someone looks.** A borrower asks while a listing that includes its tasks
  elsewhere is read (the app's Activity view, `gmc tasks`), at most every 2 s per lender, one
  question at a time; a first answer is waited for up to 1.5 s. The lender reads itself at
  most about once a second however many ask.
- **A claim, bounded on arrival** (`load_share::accept_load`): at most 4096 cores, use at most
  what it has, memory at most 64 TiB, at most 8 GPUs with names cleaned and cut, busy at most
  100 %. An answer older than 10 s is not shown.
- Shown under the lender's grant in "You can use" ("Studio overall (its owner shares this)")
  and in `gmc tasks` ("whole computer: ...").

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

- **Stage 2, the rest of the borrower's side:** the phases before a task is sent (checking
  files, uploading); finished tasks there in the history; `CancelJob` from any client, and a
  Stop button for them; the lender's speed level shown.
- **Stage 3:** the Devices view with reachability (last authenticated contact) and grants that
  cannot look usable once dead on the other side; container figures from the runtime's stats.
- **Stage 4, GPU lending:** a design and threat-model section first (the Seatbelt profile would
  have to open the GPU driver to tasks on macOS; CUDA in containers on Linux), then the build.
