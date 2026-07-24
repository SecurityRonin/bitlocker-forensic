# 7. Low MSRV floor for the published reader; release-plz PR-based publishing

Date: 2026-07-24
Status: Accepted

## Context

Both crates are published libraries that third parties link. The fleet MSRV
policy (`CLAUDE.core.md`, "Rust MSRV & Toolchain Policy") separates the *dev
toolchain* (pinned to current stable, for fmt/clippy consistency) from the
*declared MSRV* (a downstream-facing promise that must stay low and CI-verified
for published libraries). Publishing itself is bookkeeping the fleet standard
routes through release-plz, not hand-cut version bumps (`CLAUDE.core.md`,
"Releases are automated and reviewed").

## Decision

**MSRV.** The dev toolchain is pinned to current stable (`rust-toolchain.toml`
`channel = "1.96.0"`), while the declared MSRV floor is **1.81**
(`Cargo.toml` `[workspace.package] rust-version = "1.81"`), verified by a
dedicated CI job (`.github/workflows/ci.yml` `msrv: MSRV (1.81)`,
`dtolnay/rust-toolchain@1.81`). That job builds **default-features only** — the
low-MSRV promise covers the bare reader for third-party reuse; the optional `vfs`
feature (ADR-0004) pulls `forensic-vfs`, whose 1.85 floor is deliberately higher
and validated by the `--all-features` jobs.

**Publishing.** Library releases go through release-plz (`release-plz.toml`,
`.github/workflows/release-plz.yml`; adopted in `13f9bda` "chore(release): adopt
release-plz for library publishing"). It computes per-crate SemVer bumps from
conventional-commit types and opens a release PR whose merge publishes. Per the
fleet gotcha, `git_tag_name` is set to the `<crate>-vX.Y.Z` form to avoid
colliding with binary `v[0-9]*` tags (`2d84d74`). `Cargo.lock` is committed
(`b8fde5b`) to stabilise `cargo-vet` against the freshness treadmill.

## Consequences

- A downstream crate can depend on `bitlocker-core` on any toolchain ≥ 1.81
  without the VFS graph; opting into `vfs` accepts the 1.85 floor.
- Raising the 1.81 floor is a near-breaking change requiring an explicit reason,
  not a drift to match the 1.96 dev pin.
- Releases are a reviewed, one-click merge with a generated changelog, not a
  hand-typed version bump.

## Note on recovered rationale

The *policy* behind a low, CI-verified MSRV floor is grounded in the fleet
standard and the code. The specific choice of **1.81** (rather than the fleet's
usual 1.75/1.80) is not explained in any commit message or comment; it is most
plausibly the floor imposed by a dependency in the default graph, but that
driver was not recovered from available history. Rationale for the exact number
is reconstructed from structure; original intent not recovered in available
history.
