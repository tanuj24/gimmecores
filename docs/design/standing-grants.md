# Standing grants

Status: built on `v2` (issue #22). Defaults decided by the owner, 2026-11-16.

## Why

Coding agents and overnight jobs work while nobody sits at the other computer, but every grant
needs its owner present (Touch ID) and lasts a couple of hours. A request then fails only
because nobody was there to say yes. Between your own devices that is friction without
protection.

## What it is

A standing grant is a rule the lender's owner creates once, with presence, for **one** paired
device: requests from that device that stay within its limits are accepted without asking.

```console
$ gmc standing set "Laptop" --cpus 8 --memory 16g --runtime sandbox
  (Touch ID: let "Laptop" use this computer up to 8 cores, 16.0 GiB memory, 10.0 GiB disk, in
   this computer's sandbox, each time for up to 8 hours without asking you, for 30 days)
$ gmc standing                       # the standing grants on this computer
$ gmc standing off "Laptop"          # ends it, and revokes the grants it accepted
```

The app and `gmc requests` offer the same when accepting a request: "Always accept requests
like this from Laptop for 30 days" creates a standing grant with exactly that request's terms
(each grant as long as that one, at most 8 hours). The one presence prompt names both. The
device's card in the app shows the standing grant, with **Stop accepting automatically**.

## Rules

- **Created only by the owner, with presence** (I13 already lists "add a standing rule"), on the
  Control socket. Agents (`gmc mcp`), SDKs and scripts use the Client socket, which has no way
  to create, widen or renew one. Every change is audited.
- **Limits**: cores, memory, disk, the ways tasks may run (container, sandbox), the fastest
  speed it approves, the image allowance (none unless included), and the longest grant it
  accepts: at most **8 hours**. A request outside any limit goes to the owner as today; it is
  never cut down silently.
- **Standard grants only.** A request for a Trusted grant always goes to the owner.
- **Speed**: a request naming a level faster than the rule's goes to the owner. A rule made
  without a speed approves no level faster than the owner's own setting.
- **Lapses after 30 days** unless the owner sets it again (with presence), like Trusted mode.
  Grants it accepted before then run to their own end (at most 8 hours).
- **Everything else still applies**: lending must be on, the ways of running tasks must still be
  lent, laptop protections pause grants as usual, revoke and Stop all lending work as always.
- **Each auto-accepted grant** is audited as "accepted by standing grant", carries a mark in the
  signed grant (`Grant.by_standing_rule`, field 18, so it survives a restart and the borrower
  can show it), and the app notifies the owner (while it runs; one accepted while it was closed
  is announced when it starts); `gmc grants` marks it "(standing)".
- **Turning a rule off** needs no presence (it reduces access) and revokes the live grants it
  accepted. Unpairing the device deletes its rule.
- **Its limits are for all its grants together**: what the live grants it accepted hold counts
  against it, checked one request at a time, so many small requests cannot add up past it.
- **Signed**: the rule is kept with the paired device (`peers.json`, owner-only) and signed with
  this device's key over the label, both devices' keys and the rule, so editing the file cannot
  create or widen one; a rule whose signature does not verify is ignored and removed (audited,
  tested by widening one in the file). It does not stop someone who can write that file from
  putting back an older copy of a rule (removed or narrowed since) within its 30 days; whoever
  can do that already acts as this user.

## Renewing while in use

So an overnight job or an agent keeps going (the owner's decision, 2026-11-16), the borrower
asks again by itself for a grant a standing grant gave it, with the same terms and length, when:

- it ends within 15 minutes, and
- a task ran under it within the last hour.

One try per grant. The request names the grant it renews (`GrantRequest.renews`, field 10), and
the lender then accepts it **only by the standing grant**, with the renewed grant's share not
counted, or declines at once: a renewal never becomes a prompt for the owner (nobody is woken at
3 a.m. by an agent). The old grant runs to its own end, so for up to 15 minutes both exist. Both
devices audit the renewal; the lender's app announces it like any grant its standing grant
accepts. A task running when its grant ends is still stopped (I3): long tasks should fit in one
grant. Lenders older than this field ignore it, but they never mark a grant as given by a
standing grant, so the borrower never asks them.

## Threat model changes

- I1 now reads: "... a valid, unexpired grant that the lender's user accepted, **directly or
  through a standing grant they created with presence** ...".
- New row in 5.1, "Use the lender while its owner is away": the controls above. Residual: within
  its limits, a standing grant lets that device run work with nobody watching; the owner chose
  that for one device, for 30 days at most, and is told each time.

## Not in this version

- Schedules ("nights only"): needs local-time rules; later.
- Rules for more than one device at once, or for devices not yet paired: never.
