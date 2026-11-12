# Security policy

GimmeCores lets people run code on each other's machines. We take every report seriously.

## Reporting a vulnerability

Please report privately through **GitHub private vulnerability reporting** ("Report a
vulnerability" on the repository's Security tab). Do not open a public issue, pull request or
discussion.

Include what you can: affected version or commit, platform, steps to reproduce, impact, and
whether you believe it is being exploited.

What to expect:
- Acknowledgement within 3 business days.
- An initial assessment within 10 business days.
- Coordinated disclosure: we aim to release a fix within 90 days and will credit you unless you
  prefer otherwise.

## Scope

In scope: `gmcd`, the `gimmecores`/`gmc` CLI, the dashboard and desktop app, official SDKs, the
protocol specifications, release and update infrastructure.

Especially interesting:
- Running code on a lender without an active grant, or beyond its limits
- Escaping the task sandbox or reaching the lender's files or LAN
- Pairing or impersonation attacks
- Code execution on a borrower from returned results outside Trusted mode
- Attacks on the local API or dashboard from other local users or from web pages
- Bypassing secret exclusion

Known, documented limitations (see [threat model section 7](docs/design/threat-model.md#7-residual-risks-we-cannot-remove))
are not vulnerabilities by themselves, but ways to make them worse are.

## Supported versions

Until 1.0, only the latest release receives security fixes.
