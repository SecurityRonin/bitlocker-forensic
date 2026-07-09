# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0]

### Added

- `bitlocker-core`: sector decryption for **AES-128-CBC without the Elephant
  Diffuser** (method `0x8002`) — the FVEK-keyed CBC core with no diffuser stage
  and no TWEAK key. Tier-1 validated against `pybde` on the picoCTF 2025
  `bitlocker-1.dd` image. Methods `0x8000` and `0x8002` are now both decrypted.
- `bitlocker-core`: the encryption-method dispatch now **decodes all six
  ciphers** (`0x8000`–`0x8005`) into their three axes — key size, CBC/XTS mode,
  and diffuser — and ships a decrypt for each once a `pybde` oracle validates it.
- `bitlocker-core`: **recovery-password unlock** —
  `BitLockerVolume::unlock_with_recovery_password` over the recovery protector
  (`0x0800`), with `recovery_key_hash` (48 digits → eight `÷11` words → SHA-256).
- `bitlocker-core`: **AES-256-CBC** (`0x8003`), **XTS-AES-128** (`0x8004`), and
  **XTS-AES-256** (`0x8005`) sector decryption. XTS keys the data unit off the
  sector number (`byte_offset / 512`), matching CBC's physical-offset handling in
  the relocated volume-header region. XTS is provided by the `xts-mode` crate
  (0.5.x — cipher 0.4 / aes 0.8). Validated: `0x8003` vs self-minted `m8003`
  (Tier-2); `0x8004` vs BelkaCTF6 `vault` (Tier-1) and `m8004` (Tier-2); `0x8005`
  vs `m8005` (Tier-2).
- Only AES-256-CBC + Elephant Diffuser (`0x8001`) is still recognized-but-refused
  with a named `UnvalidatedEncryptionMethod` (no oracle yet); a value outside the
  `0x8000`–`0x8005` range stays `UnsupportedEncryptionMethod`.

### Changed

- `bitlocker-core`: the `NoPasswordProtector` error is generalized to
  `NoUnlockProtector { protector, found }` (names the attempted protector), so
  both password and recovery-password unlock report a missing protector uniformly
  (breaking vs 0.1.0).

## [0.1.0]

### Added

- `bitlocker-core`: from-scratch BitLocker (BDE) reader and password decryptor.
  - Volume-header parsing for BitLocker Vista/7/10 (`-FVE-FS-`) and BitLocker To
    Go (FAT) layouts.
  - FVE metadata block/header/entry parsing; key-protector inventory.
  - Password unlock: double-SHA-256 → 0x100000-iteration stretch → AES-CCM VMK
    unwrap → FVEK/TWEAK.
  - Sector decryption for AES-128-CBC + Elephant Diffuser (method `0x8000`),
    honouring BitLocker volume-header relocation.
  - `BitLockerVolume::unlock_with_password` → plaintext `Read + Seek` view.
  - Tier-1 validated against `pybde` on the dfvfs `bdetogo.raw` image.
- `bitlocker-forensic`: anomaly auditor emitting `BDE-*`
  `forensicnomicon::report` findings (clear-key, protector inventory, weak
  cipher, BitLocker To Go).
