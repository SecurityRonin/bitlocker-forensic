//! # bitlocker-core — a from-scratch BitLocker (BDE) reader and decryptor
//!
//! Parses the BitLocker Drive Encryption on-disk format (the `-FVE-FS-` /
//! BitLocker To Go volume header, the FVE metadata block, and its key-protector
//! entries) and decrypts a volume from a password, exposing a plaintext
//! `Read + Seek` view.
//!
//! Scope of this build: the **password** protector (type `0x2000`) over the
//! **AES-128-CBC + Elephant Diffuser** cipher (method `0x8000`) — exactly what
//! the Tier-1 dfvfs `bdetogo.raw` oracle validates. AES-XTS, recovery-password,
//! startup-key and TPM protectors are deliberately out of scope here (see the
//! crate README); the metadata parser still *reports* their presence.
//!
//! Every primitive comes from an audited RustCrypto crate — `aes`, `cbc`, `ccm`,
//! `sha2` — except the Elephant Diffuser, for which no crate exists; it is
//! implemented to the `libbde` reference and validated **only** against the
//! Tier-1 oracle (never a self-authored round-trip, which would prove nothing).
//!
//! ```ignore
//! use std::fs::File;
//! use std::io::Read;
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

pub use error::{BdeError, Result};
pub use guid::format_guid;
pub use header::{BdeVariant, VolumeHeader};
pub use metadata::{FveMetadata, MetadataEntry};
