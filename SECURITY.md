# Security Policy

`bitlocker-forensic` is designed to parse **untrusted Windows BitLocker (BDE)
structures** — including images acquired from compromised or actively hostile
systems. Hostile input is the expected case, not an edge case. Robustness
against crafted volume-header and FVE-metadata structures is a core design goal, and we take
reports of crashes, hangs, or memory-safety issues seriously.

The security posture below is the standard the crates are built and held to.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x   | ✅ — current development line |
| < 0.1   | ❌ — pre-release, unsupported |

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Report privately, by either:

- **GitHub Security Advisories** — open a private advisory on the
  [`bitlocker-forensic` repository](https://github.com/SecurityRonin/bitlocker-forensic/security/advisories/new), or
- **Email** — [albert@securityronin.com](mailto:albert@securityronin.com).

Please include:

- the affected version and target triple,
- a minimal reproducing BitLocker image or byte buffer (a fuzz corpus entry is ideal),
- the observed behaviour (panic, hang, excessive allocation, mis-parse) and the
  expected behaviour.

We aim to acknowledge a report within a few business days and to coordinate
disclosure once a fix is available.

## Security posture

`bitlocker-forensic` is being hardened against adversarial input by construction:

- **`#![forbid(unsafe_code)]`** across the whole workspace — no `unsafe`, anywhere.
- **No panics on malicious input** — every length and offset is validated
  against both the structure's declared size and the actual buffer; arithmetic
  is checked or saturating.
- **Bounded reads** — catalog entries, store descriptors, and block-list records
  are length-checked before use, so a crafted length field cannot drive an
  out-of-bounds read or an allocation bomb.
- **Pure auditor** — the analyzer will be a side-effect-free function of
  already-decoded records: no I/O, no allocation surprises.

Continuous fuzzing with [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz)
will back this hardening once the parser lands, with one target per parsed
structure plus a full-pipeline target; each target's invariant is "must not
panic," and any panic found is fixed and pinned as a regression test.
