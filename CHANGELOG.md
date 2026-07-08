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
  `bitlocker-1.dd` image. Methods `0x8000` and `0x8002` are now both decrypted;
  AES-256-CBC (`0x8003`) and AES-XTS (`0x8004`/`0x8005`) remain out of scope.

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
