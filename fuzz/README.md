# Fuzzing

Every decoder that reads bytes another device controls has a target here; each must never
panic and checks the invariants its callers rely on (`crates/gimmecores-node/src/fuzzing.rs`).

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz
cargo +nightly fuzz run frames -- -max_total_time=300     # peer protocol frames
cargo +nightly fuzz list                                  # all targets
```

On macOS with only the Command Line Tools, the C++ part of libFuzzer may not find the
standard headers; point it at the SDK:

```sh
SDK=$(xcrun --sdk macosx --show-sdk-path)
CXXFLAGS="-isysroot $SDK -I$SDK/usr/include/c++/v1" cargo +nightly fuzz build
```

| Target | Input | Invariant |
|---|---|---|
| `frames` | length-prefixed `PeerMessage`s from a QUIC stream | no panic; nothing over the 4 MiB frame limit decodes |
| `directory` | a directory listing (lender's inputs, borrower's returned outputs) | names are single, valid path parts; only declared outputs are accepted; the size budget only shrinks |
| `record` | a package `RECORD` file | paths are relative, never `..` |
| `ticket` | a pasted pairing ticket | no panic |
| `grant` | a `SignedGrant` from a peer | never verifies without the lender's key |
| `advert` | an mDNS advert from anyone nearby | names are cleaned, at most 64 characters |
| `text` | peer-supplied display text; any file's text for the secret scan | control and bidi characters removed; no panic or runaway regex |

The same entry points run on stable in `crates/gimmecores-node/tests/fuzz_smoke.rs` (random and
mutated inputs), so ordinary test runs catch regressions too.
