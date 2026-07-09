# bitlocker-forensic

A from-scratch, pure-Rust **BitLocker (BDE) reader and decryptor** — unlock a
volume from its password and read the plaintext, plus an anomaly auditor over the
key-protector metadata.

!!! info "Scope"
    This build decrypts the **password** (`0x2000`) and **recovery-password**
    (`0x0800`) protectors over **five of the six** BitLocker ciphers, each
    validated by `pybde`: AES-128-CBC ± Elephant Diffuser (`0x8000` / `0x8002`),
    AES-256-CBC (`0x8003`), and XTS-AES-128/256 (`0x8004` / `0x8005`). Only
    AES-256-CBC + Elephant Diffuser (`0x8001`) is recognized-but-refused (no
    oracle yet); startup-key / TPM protectors are out of scope. The metadata
    parser still reports their presence. See [Format Research](RESEARCH.md) and
    [Validation](validation.md).

## What it does

BitLocker encrypts a whole volume behind a Full Volume Encryption Key (FVEK),
itself wrapped by a Volume Master Key (VMK) that each *protector* (password,
recovery key, TPM, …) can unwrap. `bitlocker-core`:

- parses the `-FVE-FS-` / BitLocker To Go volume header and the FVE metadata
  block (key protectors, cipher, volume GUID),
- derives the VMK from a password (double-SHA-256) or a recovery password
  (48 digits → eight `÷11` words → SHA-256), each fed to the `0x100000`-iteration
  stretch → AES-CCM unwrap, then the FVEK from the VMK,
- decrypts sectors with AES-CBC (± Elephant Diffuser) or AES-XTS, 128- or
  256-bit, honouring BitLocker's volume-header relocation, and
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
