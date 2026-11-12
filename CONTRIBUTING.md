# Contributing to GimmeCores

Thanks for helping. GimmeCores runs code on other people's machines, so we hold changes to a
high bar for safety and clarity.

## Developer Certificate of Origin (DCO)

Every commit must be signed off, certifying the [DCO](DCO):

```console
$ git commit -s -m "Describe the change"
```

This adds a line like `Signed-off-by: Your Name <you@example.com>`. Pull requests with unsigned
commits cannot be merged. Contributions are licensed under the [Apache License 2.0](LICENSE).

## Before you start

- For anything larger than a small fix, open an issue first so we can agree on the approach.
- Changes to the protocol (`spec/proto`), `gmc.toml`, pairing, grants or sandboxing need a
  design note in the pull request and must update [`docs/design/threat-model.md`](docs/design/threat-model.md)
  if they affect any security invariant.

## Security-sensitive code

These areas require review by a maintainer designated as a security reviewer (the list will be published in `MAINTAINERS.md` before the first release):
pairing, identity and key storage, grant enforcement, the executor/sandbox, protocol decoding,
the local API and dashboard, serialization, the updater, release tooling.

Rules:
- No `unsafe` in GimmeCores' own crates.
- Every new message decoder gets a fuzz target.
- Every security invariant change gets a test.
- Never log secrets, file contents or environment variables.

## Reporting vulnerabilities

Do **not** open public issues for security problems. See [SECURITY.md](SECURITY.md).
