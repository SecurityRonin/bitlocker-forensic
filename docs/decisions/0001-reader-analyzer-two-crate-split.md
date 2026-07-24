# 1. Reader/analyzer two-crate split, naming, and dependency direction

Date: 2026-07-24
Status: Accepted

## Context

BitLocker work splits cleanly into two jobs an examiner does separately: (1)
*unlock and read* a volume — parse the FVE metadata, derive keys, decrypt
sectors; and (2) *audit* the metadata for anomalies (a clear-key protector, a
weak cipher) without any credential. These have different consumers, different
MSRV needs, and different failure modes.

The fleet Crate-structure standard (ronin-issen `CLAUDE.md`, "Crate-structure
standard — reader/analyzer split") mandates, for a single-format repo, exactly
two crates: `<x>-core` (the raw reader) and `<x>-forensic` (the anomaly auditor
emitting `forensicnomicon::report` findings). It also fixes the naming grammar:
the bare `<x>` import path is preserved via `[lib] name`, and the analyzer keeps
the `<x>-forensic` name.

## Decision

The repo is a Pattern-A single-format workspace (`Cargo.toml` `members = ["core",
"forensic"]`) with two published crates:

- **`bitlocker-core`** (`core/Cargo.toml`) — the reader/decryptor. It is
  published as `bitlocker-core` but sets `[lib] name = "bitlocker"`, so consumers
  write `use bitlocker::BitLockerVolume` (`core/src/lib.rs`). It emits a plaintext
  `Read + Seek` view plus typed FVE metadata; it produces no findings.
- **`bitlocker-forensic`** (`forensic/Cargo.toml`) — the anomaly auditor. It
  depends *down* on the reader (`workspace.dependencies` `bitlocker = { path =
  "core", package = "bitlocker-core" }`) and on `forensicnomicon`, and converts
  its own `AnomalyKind` into canonical `Finding`s via `impl Observation`
  (`forensic/src/lib.rs`).

Dependency direction is one-way: `bitlocker-forensic → bitlocker-core →
forensicnomicon` (KNOWLEDGE leaf). The analyzer audits the metadata the reader
already parses (`audit_reader` calls `BitLockerVolume::read_metadata`), so it does
not re-parse the raw format — the reader's metadata API exposes the protector
inventory and cipher it needs.

The workspace was scaffolded in this shape from the first commit (`5c18192`
"scaffold bitlocker-forensic workspace (core + forensic)").

## Consequences

- A third-party developer who only needs to read a BitLocker volume links
  `bitlocker-core` alone and never pulls the `forensicnomicon` reporting graph.
- The analyzer stays thin: it owns the anomaly taxonomy (`BDE-CLEAR-KEY-PRESENT`,
  `BDE-PROTECTOR-INVENTORY`, `BDE-WEAK-CIPHER`, `BDE-TO-GO`) and delegates all
  format knowledge to the reader.
- Because the analyzer's needs are satisfied by `bitlocker-core`'s metadata API,
  it depends on `-core` rather than dropping to raw bytes — the default the
  standard prescribes when `-core` exposes everything the audit requires.
