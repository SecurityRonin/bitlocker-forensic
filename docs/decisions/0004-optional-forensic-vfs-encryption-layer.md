# 4. Optional forensic-vfs EncryptionLayer behind the `vfs` feature

Date: 2026-07-24
Status: Accepted

## Context

The fleet composes evidence stacks (`E01 → GPT → BitLocker → NTFS`) through
`forensic-vfs`: a BitLocker-encrypted volume should present itself as a decrypted
`ImageSource` that a normal filesystem reader mounts unchanged, so no consumer
special-cases the encryption (ronin-issen `CLAUDE.md`, "VFS & Universal Container
Abstraction"). `forensic-vfs` defines an `EncryptionLayer` contract for exactly
this.

But wiring that contract into `bitlocker-core` unconditionally would pull the
whole `forensic-vfs` dependency graph — and its higher MSRV — into every consumer
that only wants to read a volume from a password. `forensic-vfs`'s MSRV is 1.85;
the bare reader's low-MSRV promise is 1.81 (`.github/workflows/ci.yml` MSRV job
comment; see ADR-0007).

## Decision

Ship the adapter, but behind a non-default Cargo feature. `core/Cargo.toml`
declares `vfs = ["dep:forensic-vfs"]` (`default = []`), and the adapter lives in
`core/src/vfs.rs` compiled only under `#[cfg(feature = "vfs")]`
(`core/src/lib.rs`). `BitlockerLayer` implements `forensic_vfs::EncryptionLayer`:
it wraps the encrypted `DynSource`, pulls a `Credential` from the
`CredentialSource`, calls the matching `unlock_*`, and exposes the decrypted
result as a positioned-read source. A bad key or bad header maps to a loud
`VfsError::Decode`, never silent wrong output.

The decryption itself is entirely `bitlocker-core`'s own (audited RustCrypto
ciphers + the `elephant-diffuser` crate, ADR-0002); this module only wires the
contract — the standard's "one small, honest seam," not a re-implementation.

The adapter has tracked `forensic-vfs` across its evolving contract: `6dfd9ae`
(GREEN — `BitlockerLayer` implements the `CryptoLayer` contract), `6b625cb`
(migrate to the 0.4.2 `EncryptionLayer` API), and successive bumps through
`9021948` (`forensic-vfs 0.7`). This ADR is the target of the "(ADR 0004)"
reference already embedded in `core/Cargo.toml`.

## Consequences

- The zero-feature path stays a lean, low-MSRV reader for third-party reuse; the
  VFS dependency graph and its 1.85 floor are opt-in.
- CI validates both surfaces: the default-features MSRV job builds the bare
  reader at 1.81, while the test/coverage jobs run `--all-features` to exercise
  the adapter (`d5ca747`).
- An examiner mounting an evidence stack gets transparent BitLocker decryption
  without any consumer knowing BitLocker from LUKS — the abstraction, not an
  `if bitlocker { … }` branch.
