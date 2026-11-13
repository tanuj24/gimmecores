# Guest accounts for sandboxed tasks (macOS) — proposal

Status: **proposal, not built**. It needs a one-time administrator step that changes the system
(new hidden user accounts and a sudoers rule), so it waits for the owner's decision.

## The gap it closes

On macOS the sandbox runner starts tasks with Seatbelt (deny by default), **as the lender's own
user**. Two weaknesses remain (ROADMAP M1, threat model 5.1):

1. A process that deliberately detaches (double fork + `setsid`) can outlive its task. It stays
   inside the Seatbelt profile, but it keeps running and holding memory until the lender reboots
   or kills it.
2. If a task ever escaped Seatbelt (a macOS sandbox bug), it would hold the lender's own
   privileges: their files, their Keychain, their other programs.

Linux does not have the first problem (bubblewrap's PID namespace ends every process with the
task) and runs tasks in user namespaces.

## Proposal

Run each macOS sandbox task as a **dedicated, unprivileged guest account**, in addition to
Seatbelt:

- `gmc guest setup` (asks for an administrator password once) creates a small pool of hidden
  system accounts, `_gmcguest1` … `_gmcguest8`: no login shell, no password, no home folder
  contents, UIDs below 500 so they never appear on the login screen or in System Settings.
- It writes one sudoers rule, validated with `visudo -c` before it is installed:
  `<lender> ALL=(_gmcguest1,…,_gmcguest8) NOPASSWD: /usr/bin/sandbox-exec`.
  This lets the lender's daemon start a program **as a guest, never as root**. It is a
  privilege reduction: anything that can already run as the lender can only become a less
  privileged account.
- Each running task gets its own guest account from the pool (one task per account at a time).
  When the task ends, the daemon kills **every process of that account** (`pkill -9 -u`), so
  nothing detached survives, then makes the account's leftovers in shared places (`/tmp`,
  `/Users/Shared`) go away.
- The task folder is shared with that one guest through an ACL (read/write, inherited), so
  outputs are still readable by the daemon and the folder is still deleted after the task.
- Seatbelt stays in front: the guest is a second wall, not a replacement.

## What it gives

| Threat | Today | With guest accounts |
|---|---|---|
| Detached process outlives its task | Survives, sandboxed | Killed with every other process of its account |
| Sandbox escape reads the lender's files | Has the lender's permissions | Has a guest's: no access to the lender's home (0700), Keychain or processes |
| One borrower's task affects another's | Separate Seatbelt profiles, same user | Separate accounts too |

## What it costs

- One administrator prompt at setup; accounts and the rule stay until `gmc guest remove`
  (which deletes them and the rule).
- Commands run under `sudo -u _gmcguestN`, which macOS logs in its unified log.
- The sandbox runner needs the pool to exist; without setup it behaves as today, and the
  request screen keeps saying "runs as you, inside the sandbox".

## Alternatives considered

- **A root helper (SMAppService launch daemon) with an XPC interface.** More flexible, but a
  long-running root process whose caller check depends on code signing, which Homebrew builds
  do not have (ad-hoc signatures change with every build). Rejected while distribution is
  Homebrew-only.
- **A single guest account.** Killing "all of its processes" after one task would kill other
  borrowers' running tasks. Rejected in favour of a pool.

## Decision needed

Build `gmc guest setup/remove` and the guest runner as above? Until then the gap stays
documented in the threat model and on the request screen.
