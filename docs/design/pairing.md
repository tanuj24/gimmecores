# Pairing

Status: draft (M0).

Pairing makes two devices trust each other's public keys. After pairing, either device can
*request* resources from the other, but nothing runs until the lender accepts a grant
(see [`consent-and-grants.md`](consent-and-grants.md)).

## Identity

- Each device has one long-term **Ed25519 key pair**, created on first run.
- The public key is the device's identity and its TLS identity on every connection (iroh).
- The secret key is stored in the OS keychain (macOS Keychain, Windows Credential Manager/DPAPI,
  Linux Secret Service), with a `0600` file fallback when no keychain exists (headless Pi).
- **Fingerprint** shown to users: first 16 bytes of `SHA-256(public_key)`, Base32, grouped:
  `K7QX-2M4P-…`.

## Why a short code is needed

TLS proves a peer holds *some* key. It does not prove that the key belongs to the laptop in
front of you: an attacker on the same Wi-Fi could answer the discovery request first. Both
users comparing a short code shown on each screen closes that gap.

## Protocol: commit-then-reveal short authentication string (SAS)

Same idea as Bluetooth "numeric comparison" and ZRTP. `A` is the device that starts pairing,
`B` the device being paired with. Both run over an iroh connection that already authenticates
`pkA` and `pkB`.

```
Precondition: B's user has opened pairing mode (2-minute window).

A: nA = random(32 bytes)
A → B: PairRequest   { commitment = SHA-256("gimmecores-pair-commit-v1" ‖ nA), device_name_A }
B: nB = random(32 bytes)
B → A: PairChallenge { nB, device_name_B }
A → B: PairReveal    { nA }
B: check SHA-256("gimmecores-pair-commit-v1" ‖ nA) == commitment, else abort

Both: sas = SHA-256("gimmecores-pair-sas-v1" ‖ pkA ‖ pkB ‖ nA ‖ nB)
      code = (first 4 bytes of sas as big-endian u32) mod 1,000,000 → 6 digits

Both screens: "Confirm this code matches on the other device: 482 913"
Both users press Confirm → each side sends PairConfirm { accepted = true }
Both store the other's public key, name and fingerprint in the trust list.
```

**Why the commitment matters:** `A` commits to `nA` before seeing `nB`, and `B` chooses `nB`
before seeing `nA`. A man-in-the-middle cannot search for nonces that make the two codes match;
each attempt succeeds with probability 1/1,000,000.

**Rate limits:** max 3 pairing attempts per pairing-mode window; after a mismatch or a reject the
window closes and the user must reopen it.

## Test vectors

Every implementation must reproduce these (checked in Rust by `gimmecores-core` and
independently with Python's `hashlib`):

| Input | Value |
|---|---|
| `pkA` (initiator) | bytes `00 01 02 … 1f` |
| `pkB` (responder) | bytes `20 21 22 … 3f` |
| `nA` | 32 × `a1` |
| `nB` | 32 × `b2` |
| `commitment(nA)` | `39fdad7668f8c557b9557b9c0e98db8aa7996ec2668c9e1d9832e10a7f89b2ce` |
| first 4 bytes of the SAS hash | `1b4c999e` |
| code | **`004 894`** (always six digits; leading zeros kept) |
| code with `pkA`/`pkB` swapped | `309 733` (key order is part of the input) |

## Rules

- A pairing request is accepted only while the **receiving** user has pairing mode open.
- Both users must confirm. A one-sided confirm does nothing.
- The incoming-request screen shows device name **and** fingerprint, and warns if a different
  key previously used the same name.
- When two paired devices share a name, a command that takes a device name (`gmc grants
  request`, `gmc standing set`, `gmc allow-wake`, `gmc trust`, …) refuses it and asks for the
  fingerprint (`gmc peers`), so nothing is granted to whichever one happens to come first.
- Pairing never grants resources. It only lets devices ask.
- Pairing never enables Trusted mode. That is a separate, two-sided step.
- Unpairing on either side removes the key and revokes all grants in both directions; the other
  side is notified if reachable.

## Future pairing methods (not v1)

- **QR code** (for phones): `B` shows a QR code with `pkB` and a one-time 128-bit secret; `A`
  scans it. No code comparison needed, since the secret travels out of band.
- **Team enrollment** (premium): devices enrolled by an admin trust each other per team policy.
