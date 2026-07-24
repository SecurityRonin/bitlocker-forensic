# bitlocker-forensic — Design, Purpose & Scope

This is a **library-tier** repo: two crates that other code links, not a tool an
examiner runs. It therefore carries a design/scope doc, not a PRD (fleet PRD &
ADR standard). Load-bearing decisions are recorded in
[`docs/decisions/`](decisions/); this doc states what the library is, who links
it, and where its scope ends.

## Purpose

Unlock a BitLocker Drive Encryption (BDE) volume from a credential and read the
plaintext, in pure Rust, with no `dislocker`, no FUSE, and no mount. The library
parses the FVE metadata, derives the keys from a password or recovery password
(or a clear-key / startup-key protector), and decrypts sectors — exposing a
plaintext `Read + Seek` view. A companion crate audits the volume's metadata for
forensic anomalies without any credential.

## Who links it

- **DFIR/forensics developers** embedding BitLocker decryption in a larger Rust
  tool — link `bitlocker-core` and call `BitLockerVolume::unlock_with_password`.
- **The forensic-vfs evidence-stack composers** — enable the `vfs` feature so a
  BitLocker volume presents as a decrypted `ImageSource` inside a
  `E01 → GPT → BitLocker → NTFS` stack (ADR-0004).
- **Fleet analyzers / orchestration** consuming graded findings — link
  `bitlocker-forensic` for `forensicnomicon::report` `Finding`s over the
  protector/cipher metadata.

## The two crates

| Crate | Role | Emits |
|---|---|---|
| `bitlocker-core` (imports as `bitlocker`) | reader/decryptor over audited RustCrypto + the `elephant-diffuser` crate | plaintext `Read + Seek` view + typed FVE metadata |
| `bitlocker-forensic` | anomaly auditor over the metadata | graded `forensicnomicon::report` `Finding`s |

See ADR-0001 for the split, naming, and dependency direction.

## In scope

- **Unlock protectors** (four of five): password (`0x2000`), recovery password
  (`0x0800`), clear key (`0x0000`, no credential), startup key (`0x0200`, a
  `.BEK` external key).
- **Ciphers** (five of six, each validated against a `pybde` oracle):
  AES-128-CBC ± Elephant Diffuser (`0x8000`/`0x8002`), AES-256-CBC (`0x8003`),
  XTS-AES-128/256 (`0x8004`/`0x8005`).
- **Three on-disk layouts**: Windows Vista, Windows 7+, BitLocker To Go on FAT
  (ADR-0006).
- **Metadata audit** without a credential: clear-key presence, protector
  inventory, weak-cipher, BitLocker To Go (findings are observations, never
  verdicts).

## Out of scope / non-goals

- **TPM protector unlock.** The TPM protector is out of scope for *unlock*; the
  parser still reports it in the protector inventory.
- **AES-256-CBC + Elephant Diffuser (`0x8001`).** Recognised but refused with a
  named error (`BdeError::UnvalidatedEncryptionMethod`) — never decrypted until
  it has an independent oracle (ADR-0005).
- **Mounting / FUSE / a runnable CLI.** This is a library; mounting is
  `4n6mount`'s job via the `vfs` feature, and any front-end lives elsewhere.
- **Hand-rolled cryptography.** Every standard primitive comes from an audited
  RustCrypto crate; the sole exception, the Elephant Diffuser, is its own
  oracle-validated crate (ADR-0002).

## Validation approach

Correctness rides on an **independent** oracle, never a self-authored round-trip.
Decrypted sectors are compared byte-for-byte against `pybde` on real images
(dfvfs `bdetogo.raw`, picoCTF `bitlocker-1.dd`, BelkaCTF6 `vault`) for the Tier-1
methods, with self-minted Tier-2 images cross-checked against `pybde` for the
rest. The metadata parser is fuzzed (`core/fuzz`) and both crates keep 100% line
coverage. Details in [`docs/validation.md`](validation.md); format references in
[`docs/RESEARCH.md`](RESEARCH.md).
