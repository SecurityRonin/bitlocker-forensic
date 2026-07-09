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

#### bitlocker-1.dd

- **Source**: picoCTF 2025, challenge *Bitlocker-1* (CMU picoCTF). Forensics
  challenge image distributed with the competition.
- **md5**: `22c3492cbc26ff648df066e1ed5329a7`
- **Size**: 100 MiB
- **License / redistribution**: picoCTF challenge artifact; **not committed
  here** (size) — documented for provenance only.
- **Identity / contents**: bare BitLocker volume at offset 0 (no partition
  table), method `0x8002` (AES-128-CBC, no Elephant Diffuser). Decrypted sector
  0 is a valid NTFS boot sector. Protector: password (`0x2000`).
- **Published key**: password `jacqueline` (the challenge solution).
- **Used by**: `core/tests/oracle_bitlocker1.rs` (env var `BDE_CBC2_ORACLE`).
  Ground-truth SHA-256 digests of decrypted sectors were produced by `pybde` —
  see `docs/validation.md`.

To run the method-`0x8002` Tier-1 test:

```bash
BDE_CBC2_ORACLE=/path/to/bitlocker-1.dd \
  cargo test -p bitlocker-core --test oracle_bitlocker1 -- --nocapture
```

#### vault.raw (BelkaCTF6)

- **Source**: BelkaCTF #6 "Bogus Bill" (2024, Belkasoft + TODO:security). The
  BitLocker `vault.vhdx` is stored as an NTFS alternate data stream
  `\Users\phorger\Documents\desktop.ini:vault.vhdx` on the challenge laptop image
  (`BelkaCTF_6_CASE240405_LAPTOP.E01`..`.E06`); `qemu-img convert` → `vault.raw`.
- **Download**: <https://dl.ctf.do/BelkaCTF_6_CASE240405_FILE2.zip> (9.07 GB,
  archive password `RJtWAZfsB1wMCNDebVWY` → nested zip → 6-segment LAPTOP E01).
- **md5** (`vault.raw`): `faac779e252ee133b48f26c878168467`
- **Size**: 2 GiB (GPT disk); BitLocker volume at **byte offset 16777216**.
- **License / redistribution**: Belkasoft CTF material — **treat as NOT freely
  redistributable**. Provenance + re-download steps only; bytes **not committed**.
- **Identity / contents**: method `0x8004` (XTS-AES-128). Protectors: password
  (`0x2000`, value unpublished) + recovery password (`0x0800`). Decrypted sector 0
  is a valid NTFS boot sector.
- **Published key**: recovery password
  `590238-514580-359986-088242-029766-319495-410509-636911` (official write-up).
- **Used by**: `core/tests/oracle_vault.rs` (env var `BDE_XTS_ORACLE` = path to
  `vault.raw`). Ground-truth SHA-256 digests self-derived with `pybde` 20240502 —
  see `docs/validation.md`.

#### m8003.raw / m8004.raw / m8005.raw (self-minted Tier-2)

- **Source**: SELF-MINTED on a Parallels "Windows 11" Pro guest with `manage-bde`
  (`-UsedSpaceOnly -SkipHardwareTest -RecoveryPassword`, recovery-password
  protector only), one 128 MiB fixed VHDX per remaining cipher; `qemu-img
  convert` → raw. Independently decrypted by `pybde` on the host (Tier-2 oracle).
- **md5**: m8003 `8dd5d8713474aaf1e627aea1de5ac66f`, m8004
  `37abadef78b7988ce2c838fc517afbd8`, m8005 `409ec5dc12e144978c7b97842079089f`.
- **Size**: 128 MiB each (MBR, one NTFS partition at **byte offset 65536**).
- **License / redistribution**: we authored them ⇒ redistributable, but **not
  committed** (size) — documented for provenance; re-mint per the ground-truth
  notes in `/tmp/bde-mint-oracle/GROUND-TRUTH.md`.
- **Identity / contents**: `m8003` = method `0x8003` (AES-256-CBC); `m8004` =
  `0x8004` (XTS-AES-128); `m8005` = `0x8005` (XTS-AES-256). Each decrypts to a
  valid NTFS volume.
- **Published keys** (recovery passwords): m8003
  `068002-479633-277629-623568-540826-435039-327756-375705`; m8004
  `435743-601942-557051-719587-168388-130592-218053-447194`; m8005
  `031174-056914-397793-502348-055847-196306-284306-262174`.
- **Used by**: `core/tests/oracle_m8003.rs` / `oracle_m8004.rs` /
  `oracle_m8005.rs` (env var `BDE_MINT_ORACLE_DIR` = the directory holding them).

#### clearkey.raw (self-minted Tier-2, clear-key / suspended)

- **Source**: SELF-MINTED — a BitLocker volume with protection **suspended**
  (`manage-bde -protectors -disable`), which adds a **clear-key protector**
  (`0x0000`) storing the VMK unprotected; `qemu-img convert` → raw. Independently
  decrypted by `pybde` on the host with **no credential** (Tier-2 oracle).
- **md5**: `425e6fe34b91fb68e0026fa7d794480c`.
- **Size**: 256 MiB (MBR, one NTFS partition at **byte offset 65536**).
- **License / redistribution**: we authored it ⇒ redistributable, but **not
  committed** (size) — documented for provenance; re-mint per the notes in
  `/tmp/bde-clearkey-oracle/` (`prove.py` / `verify.py`).
- **Identity / contents**: method `0x8004` (XTS-AES-128). Protectors: recovery
  password (`0x0800`) + **clear key** (`0x0000`). `pybde` reports
  `is_locked = False` with no credential.
- **Published key**: none needed — the clear-key protector unlocks with no
  credential (`unlock_clear_key`).
- **Used by**: `core/tests/oracle_clearkey.rs` (env var `BDE_CLEARKEY_ORACLE` =
  path to `clearkey.raw`). Ground-truth SHA-256 digests self-derived with `pybde`
  20240502, no credential — see `docs/validation.md`.

#### sk8004.raw + `<GUID>.BEK` (self-minted Tier-2, startup-key)

- **Source**: SELF-MINTED on the Parallels "Windows 11" Pro guest — `manage-bde
  -on -EncryptionMethod xts_aes128 -RecoveryPassword` then `manage-bde -protectors
  -add -StartupKey`, which writes the external-key `.BEK`; `qemu-img convert` →
  raw. Independently decrypted by `pybde` `read_startup_key` on the host (Tier-2
  oracle), cross-checked against the recovery password.
- **md5**: `sk8004.raw` `d12f27801f52256cc3a900820cc1466d`; `.BEK`
  (`F8A2B017-3D39-40C6-BBB4-6CCAC663B2C5.BEK`, 180 bytes) is the external key.
- **Size**: 128 MiB (MBR, one NTFS partition at **byte offset 65536**).
- **License / redistribution**: we authored it ⇒ redistributable, but **not
  committed** (size) — documented for provenance; re-mint per the notes in
  `/tmp/bde-startupkey-oracle/GROUND-TRUTH.md`.
- **Identity / contents**: method `0x8004` (XTS-AES-128). Protectors: **startup
  key** (`0x0200`, external-key GUID `F8A2B017-…`) + recovery password (`0x0800`,
  safety net `154583-453959-209385-373417-403502-206052-478808-073667`). `pybde`
  reports `is_locked = False` after `read_startup_key(.BEK)`.
- **Published key**: the `.BEK` file itself (the 256-bit external key).
- **Used by**: `core/tests/oracle_startupkey.rs` (env var `BDE_STARTUPKEY_ORACLE`
  = path to `sk8004.raw`; the `.BEK` is auto-located beside it). Ground-truth
  SHA-256 digests self-derived with `pybde` 20240502 — see `docs/validation.md`.

To run the AES-256-CBC / XTS / clear-key / startup-key Tier-1/2 tests:

```bash
BDE_XTS_ORACLE=/tmp/bde-xts-oracle/vault.raw \
  cargo test -p bitlocker-core --test oracle_vault -- --nocapture
BDE_MINT_ORACLE_DIR=/tmp/bde-mint-oracle \
  cargo test -p bitlocker-core --test oracle_m8003 --test oracle_m8004 --test oracle_m8005
BDE_CLEARKEY_ORACLE=/tmp/bde-clearkey-oracle/clearkey.raw \
  cargo test -p bitlocker-core --test oracle_clearkey -- --nocapture
```
