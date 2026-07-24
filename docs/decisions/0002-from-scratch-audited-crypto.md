# 2. From-scratch pure-Rust decryptor over audited RustCrypto primitives

Date: 2026-07-24
Status: Accepted

## Context

Reading a BitLocker volume has historically meant shelling out to `dislocker` (a
C tool that mounts the volume via FUSE) or binding `libbde`. Both drag a C
dependency, a build toolchain, and — for a mount — root/FUSE into a forensic
workstation. The fleet wants a single pure-Rust library that unlocks a volume
from a credential and hands back plaintext, with no C, no FUSE, no mount.

Cryptography is the hazard. The global discipline is emphatic: *never hand-roll a
cryptographic primitive; use a mature, audited crate; never ship placeholder
crypto* (`CLAUDE.core.md`, "Robustness"). BitLocker's sector transform is built
from standard primitives — AES-CBC, AES-XTS, AES-CCM (key unwrap), and
SHA-256 (password derivation) — all of which have audited RustCrypto crates. The
one exception is the **Elephant Diffuser**, a BitLocker-specific pre/post-CBC
diffusion stage for which no ecosystem crate exists.

## Decision

Implement the decryptor from scratch in pure Rust, but source every standard
primitive from an audited RustCrypto crate — never re-derive the math. The
workspace pins them once (`Cargo.toml` `[workspace.dependencies]`): `aes 0.8`,
`cbc 0.1`, `ccm 0.5`, `sha2 0.10`, and `xts-mode 0.5` for the XTS methods. The
crypto layer (`core/src/crypto.rs`) composes these; `password_hash` and
`stretch_key_n` follow the documented BDE derivation.

The single primitive with no crate — the Elephant Diffuser — is the *only*
hand-written cryptographic routine. Per the fleet "prefer our own crates" rule it
was extracted from this repo into its own publishable crate,
**`elephant-diffuser`** (commit `c531283` "refactor(crypto): move Elephant
Diffuser to the elephant-diffuser crate"; `051943d` "release(bde): use published
elephant-diffuser 0.1.0 (registry dep)"), and depended on via
`[workspace.dependencies] elephant-diffuser = "0.1"`. It is validated **in situ**
against the independent `pybde` oracle on the real dfvfs `bdetogo.raw` image —
never a self-authored round-trip, which would prove only self-consistency (the
"LZNT1 trap"; see `docs/validation.md`).

`xts-mode` is deliberately held at `0.5.x`: `Cargo.toml` notes that `0.6+` jumps
to `cipher 0.5 / aes 0.9`, incompatible with the `aes 0.8` stack this repo shares
across all methods.

## Consequences

- The library is a single static Rust artifact: no `dislocker`, no FUSE, no
  mount, no C toolchain (README: "No `dislocker` C dependency, no FUSE, no
  mounting").
- The attack surface for the crypto is the audited crate ecosystem plus one
  small, oracle-validated diffuser — not a bespoke cipher stack.
- `elephant-diffuser` is reusable by any other fleet consumer that meets the
  same BitLocker CBC-diffuser case, and its correctness rides on an external
  oracle rather than an internal fixture.
