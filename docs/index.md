# bitlocker-forensic

A from-scratch, pure-Rust **BitLocker (BDE) reader and decryptor** — unlock a
volume from its password and read the plaintext, plus an anomaly auditor over the
key-protector metadata.

!!! info "Scope"
    This build decrypts the **password** protector (`0x2000`) over two ciphers,
    each Tier-1 validated by `pybde`: **AES-128-CBC + Elephant Diffuser**
    (method `0x8000`, dfvfs `bdetogo.raw`) and **AES-128-CBC** with no diffuser
    (method `0x8002`, picoCTF `bitlocker-1.dd`). AES-256-CBC, AES-XTS, and
    recovery-password / startup-key / TPM protectors are out of scope here; the
    metadata parser still reports their presence. See
    [Format Research](RESEARCH.md) and [Validation](validation.md).

## What it does

BitLocker encrypts a whole volume behind a Full Volume Encryption Key (FVEK),
itself wrapped by a Volume Master Key (VMK) that each *protector* (password,
recovery key, TPM, …) can unwrap. `bitlocker-core`:

- parses the `-FVE-FS-` / BitLocker To Go volume header and the FVE metadata
  block (key protectors, cipher, volume GUID),
- derives the VMK from a password (double-SHA-256 → 0x100000-iteration stretch →
  AES-CCM unwrap), then the FVEK + TWEAK from the VMK,
- decrypts sectors with AES-128-CBC (with the Elephant Diffuser for method
  `0x8000`, without it for `0x8002`), honouring BitLocker's volume-header
  relocation, and
- exposes a plaintext `Read + Seek` view (`read_at`).

`bitlocker-forensic` grades the protector metadata into
`forensicnomicon::report` findings (clear-key present, protector inventory,
weak cipher, BitLocker To Go).

## The two-crate split

| Crate | Role | Depends on | Emits |
|---|---|---|---|
| `bitlocker-core` | reader / decryptor | `aes`, `cbc`, `ccm`, `sha2`, `thiserror` | plaintext view + typed metadata |
| `bitlocker-forensic` | anomaly analyzer | `bitlocker-core`, `forensicnomicon` | graded `Finding`s |

## Trust but verify

Every primitive is an audited RustCrypto crate; the only hand-written cryptographic
routine is the Elephant Diffuser (no crate exists), validated **only** against the
independent `pybde` oracle on real data — never a self-authored round-trip.
Panic-free, bounds-checked parsing; `unwrap`/`expect` denied in production code;
fuzzed metadata parser.

[Privacy Policy](https://securityronin.github.io/bitlocker-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/bitlocker-forensic/terms/) · © 2026 Security Ronin Ltd
