# Test data provenance

Large binary artifacts are **gitignored** and downloaded manually. Tests read
them in place, env-gated, and skip cleanly when absent. This file is the
committed record so the corpus is reproducible. The single fleet-wide index is
`issen/docs/corpus-catalog.md` — cross-referenced here, not duplicated.

## Tier-1 oracle (REAL-ext, not committed)

#### bdetogo.raw

- **Source**: [log2timeline/dfvfs](https://github.com/log2timeline/dfvfs) test
  corpus — Joachim Metz / the dfVFS project.
- **Download**: <https://raw.githubusercontent.com/log2timeline/dfvfs/main/test_data/bdetogo.raw>
- **md5**: `fcba22f9363388101ae66c741588bc45`
- **Size**: 64 MiB
- **License / redistribution**: Apache-2.0 (dfVFS). Redistributable with
  attribution; **not committed here** (size) — documented for provenance only.
- **Identity / contents**: BitLocker To Go volume on FAT, whole-file BDE volume
  at partition offset 0. Encryption method `0x8000` (AES-128-CBC + Elephant
  Diffuser). Protectors: password (`0x2000`) and recovery password (`0x0800`).
- **Published key**: password `bde-TEST`.
- **Used by**: `core/tests/oracle_bdetogo.rs` (env var `BDE_ORACLE_IMAGE`).
  Ground-truth SHA-256 digests of decrypted sectors were produced by `pybde`
  (libbde 20240502) — see `docs/validation.md`.

To run the Tier-1 test:

```bash
curl -L -o /tmp/bdetogo.raw \
  https://raw.githubusercontent.com/log2timeline/dfvfs/main/test_data/bdetogo.raw
BDE_ORACLE_IMAGE=/tmp/bdetogo.raw \
  cargo test -p bitlocker-core --test oracle_bdetogo -- --nocapture
```
