# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1]

### Added

- `bitlocker-core`: **`forensic-vfs` `CryptoLayer` adapter** behind the optional
  `vfs` feature. `bitlocker::vfs::BitlockerLayer` wraps an encrypted BitLocker
  volume (a `forensic-vfs` `ImageSource`) and, given a `Credential`, presents the
  **decrypted** volume as a `DynSource` a normal filesystem mounts unchanged. It
  pulls a credential from the `CredentialSource`, calls the matching `unlock_*`,
  and exposes the plaintext as a positioned-read source; offered-but-failing
  credentials surface as a loud `VfsError::Decode`, no credentials as
  `VfsError::NeedCredentials` — never a silent guess. The decryption is
  bitlocker-core's own audited RustCrypto + the `elephant-diffuser` crate; this
  module only wires the contract. Bare-reader consumers are unaffected: the `vfs`
  dependency graph is off by default. Validated against the real dfVFS
  `bdetogo.raw` image (Tier-1) and by hermetic synthetic-volume tests.

### Changed

- `forensic-vfs` dependency `0.1` → `0.2` (published registry). The optional
  `vfs` feature raises that path's effective MSRV to forensic-vfs's `1.85`; the
  bare reader keeps its `1.81` floor (the MSRV job builds default features only).

## [0.3.0]

### Added

- `bitlocker-core`: **startup-key (`.BEK`) unlock** —
  `BitLockerVolume::unlock_with_startup_key(reader, bek_bytes)` decrypts a volume
  protected by a startup key on removable media. The `.BEK` is a 48-byte FVE
  metadata header followed by an external-key entry (value type `0x0009`) whose
  nested KEY property (`0x0001`) holds a raw 256-bit key; that key AES-CCM-unwraps
  the VMK directly — no stretch — via the startup-key protector (`0x0200`), then
  the existing FVEK → sector path. The `.BEK` parse is bounds-checked (loud error,
  never panic). Tier-2 validated against `pybde` `read_startup_key` on a self-minted
  `0x8004` volume: all sectors match byte-for-byte, and the `.BEK`-decrypted
  plaintext equals the recovery-password-decrypted plaintext (independent VMK
  confirmation). With password / recovery / clear-key, this is **4 of 5** unlock
  protectors.
- `bitlocker-core`: **clear-key (no-credential) unlock** —
  `BitLockerVolume::unlock_clear_key(reader)` decrypts a volume whose protection
  is *suspended*. A clear-key protector (`0x0000`) stores the VMK unprotected; the
  clear key held in the VMK's KEY property (value type `0x0001`: `method(u32)@0`,
  then the 32-byte key) AES-CCM-unwraps the VMK directly — no stretch, no
  credential — then the existing FVEK → sector path. `derive_cipher` is
  generalized over an internal `VmkUnwrap` (stretch a credential, or read the
  clear key); the password/recovery paths are unchanged. Tier-2 validated against
  `pybde` (which reports `is_locked = False` with no credential) on a self-minted,
  suspended `0x8004` volume — `unlock_clear_key` reproduces its decrypted sectors
  byte-for-byte.

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
