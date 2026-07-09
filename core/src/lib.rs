//! # bitlocker-core — a from-scratch BitLocker (BDE) reader and decryptor
//!
//! Parses the BitLocker Drive Encryption on-disk format (the `-FVE-FS-` /
//! BitLocker To Go volume header, the FVE metadata block, and its key-protector
//! entries) and decrypts a volume from a password or recovery password, exposing
//! a plaintext `Read + Seek` view.
//!
//! Scope of this build: the **password** (`0x2000`) and **recovery-password**
//! (`0x0800`) protectors over **five of the six** BitLocker ciphers, each
//! validated by a `pybde` oracle — AES-128-CBC ± Elephant Diffuser (`0x8000` /
//! `0x8002`), AES-256-CBC (`0x8003`), and XTS-AES-128/256 (`0x8004` / `0x8005`).
//! Only AES-256-CBC + Elephant Diffuser (`0x8001`) is recognized-but-refused (no
//! oracle yet); startup-key and TPM protectors are out of scope for *unlock*.
//! The metadata parser still *reports* every protector and cipher it finds.
//!
//! Every primitive comes from an audited crate — `aes`, `cbc`, `ccm`, `sha2`,
//! and `xts-mode` for the XTS methods — except the Elephant Diffuser, for which
//! no ecosystem crate exists; it lives in our own [`elephant_diffuser`] crate
//! (extracted from here) and is validated **in situ** by this repo's Tier-1
//! oracle (never a self-authored round-trip, which would prove nothing).
//!
//! ```no_run
//! use std::fs::File;
//! use bitlocker::BitLockerVolume;
//!
//! let image = File::open("bdetogo.raw")?;
//! let mut volume = BitLockerVolume::unlock_with_password(image, "bde-TEST")?;
//! let mut boot = [0u8; 512];
//! volume.read_at(0, &mut boot)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod bytes;
mod crypto;
mod error;
mod guid;
mod header;
mod metadata;
mod method;
mod volume;

pub use error::{BdeError, Result};
pub use guid::format_guid;
pub use header::{BdeVariant, VolumeHeader};
pub use metadata::{FveMetadata, MetadataEntry};
pub use volume::{BitLockerVolume, DecryptedVolume};
