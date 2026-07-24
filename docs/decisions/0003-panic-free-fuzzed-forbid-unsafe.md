# 3. forbid(unsafe), panic-free bounds-checked parsing, and fuzzing

Date: 2026-07-24
Status: Accepted

## Context

Both crates parse untrusted, attacker-controllable input: a BitLocker volume
header and FVE metadata block whose length, offset, and count fields cannot be
trusted. A length field that lies, a truncated metadata entry, or a malformed
header must never crash the tool or read out of bounds. This is the fleet
"Paranoid Gatekeeper" standard (ronin-issen `CLAUDE.md`, "Security & Robustness
Standard") and the global panic-free lint recipe (`CLAUDE.core.md`, "Rust Lint
Posture").

Unlike the mmap-based container readers (`ewf`, `memory-forensic`) that must
downgrade to `unsafe_code = "deny"` for one bounded `Mmap::map`, this decryptor
does positioned reads over a `Read + Seek` source and needs no `unsafe` at all.

## Decision

Enforce a panic-free posture statically and dynamically.

Statically, the workspace sets the strict tier (`Cargo.toml`
`[workspace.lints]`): `unsafe_code = "forbid"` (no bounded-allow exception is
taken — both `core/src/lib.rs` and `forensic/src/lib.rs` carry
`#![forbid(unsafe_code)]`), and `clippy::unwrap_used` / `expect_used` are `deny`
in production code. Tests opt out via `#![cfg_attr(test,
allow(clippy::unwrap_used, clippy::expect_used))]` plus `clippy.toml`
`allow-unwrap-in-tests`. Integer fields are read through a bounds-checked helper
(`core/src/bytes.rs` — `le_u16`/`le_u64`/`read_guid`) that returns a defined
value rather than panicking out of range, and offset/length fields from the image
are range-checked before use.

Dynamically, the metadata parser carries a `cargo-fuzz` target
(`core/fuzz/fuzz_targets/fuzz_metadata.rs`, added in `3cbecba` "fuzz target + 100%
line coverage + clippy/fmt clean"), with the invariant that no input may panic.

## Consequences

- Malformed evidence degrades to a named `BdeError` (e.g. `NotBitLocker`
  carrying the offending signature bytes, `NoValidMetadata`), never a crash or a
  raw-pointer path — the "show the unrecognized value" discipline.
- Because there is no `unsafe`, the repo earns the `unsafe forbidden` README
  badge honestly (unlike the mmap readers, which skip it).
- The static lints occasionally require more verbose bounds-checked code than a
  quick `unwrap` would; the fuzz target is part of the maintained CI surface.
