//! # bitlocker-core — a from-scratch BitLocker (BDE) reader and decryptor
//!
//! Parses the BitLocker Drive Encryption on-disk format (the `-FVE-FS-` /
//! BitLocker To Go volume header, the FVE metadata block, and its key-protector
//! entries) and decrypts a volume from a password, exposing a plaintext
//! `Read + Seek` view.
//!
//! Scope of this build: the **password** protector (type `0x2000`) over
//! **AES-128-CBC** — with the Elephant Diffuser (method `0x8000`) or without it
//! (method `0x8002`), each validated by a Tier-1 `pybde` oracle (dfvfs
//! `bdetogo.raw` and picoCTF `bitlocker-1.dd` respectively). AES-256-CBC,
//! AES-XTS, recovery-password, startup-key and TPM protectors are deliberately
//! out of scope here (see the crate README); the metadata parser still *reports*
//! their presence.
//!
//! Every primitive comes from an audited RustCrypto crate — `aes`, `cbc`, `ccm`,
//! `sha2` — except the Elephant Diffuser, for which no ecosystem crate exists;
//! it lives in our own [`elephant_diffuser`] crate (extracted from here) and is
//! validated **in situ** by this repo's Tier-1 oracle (never a self-authored
//! round-trip, which would prove nothing).
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
