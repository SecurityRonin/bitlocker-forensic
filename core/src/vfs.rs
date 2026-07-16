//! `forensic-vfs` [`CryptoLayer`] adapter for BitLocker, behind the `vfs` feature.
//!
//! Wraps an encrypted BitLocker volume (a parent [`ImageSource`]) and, given a
//! credential, presents the **decrypted** volume as a [`DynSource`] a normal
//! filesystem mounts unchanged. The decryption is bitlocker-core's own (audited
//! RustCrypto ciphers + the `elephant-diffuser` crate); this module only wires
//! the contract: pull a credential from the [`CredentialSource`], call the
//! matching `unlock_*`, and expose the result as a positioned-read source.

use std::io::{Read, Seek};
use std::sync::{Arc, Mutex, PoisonError};

use forensic_vfs::adapters::SourceCursor;
use forensic_vfs::{
    Credential, CredentialSource, CryptoLayer, CryptoScheme, DynSource, ImageSource, VfsError,
    VfsResult,
};

use crate::{BitLockerVolume, DecryptedVolume};

/// A BitLocker-encrypted volume presented as a [`CryptoLayer`].
pub struct BitlockerLayer {
    encrypted: DynSource,
    len: u64,
}

impl BitlockerLayer {
    /// Wrap an encrypted BitLocker volume (the ciphertext byte source).
    pub fn new(encrypted: DynSource) -> Self {
        let len = encrypted.len();
        Self { encrypted, len }
    }
}

/// Translate a bitlocker-core error into the VFS error type: a bad key / bad
/// header is a loud [`VfsError::Decode`].
fn map_bde_err(e: &crate::BdeError) -> VfsError {
    VfsError::Decode {
        layer: "bitlocker",
        offset: 0,
        detail: e.to_string(),
        bytes: forensic_vfs::SmallHex::new(&[]),
    }
}

impl CryptoLayer for BitlockerLayer {
    fn scheme(&self) -> CryptoScheme {
        CryptoScheme::Bitlocker
    }

    fn open(&self, creds: &dyn CredentialSource) -> VfsResult<DynSource> {
        let cands = creds.credentials_for(CryptoScheme::Bitlocker, "");
        if cands.is_empty() {
            return Err(VfsError::NeedCredentials {
                scheme: "bitlocker",
                target: String::new(),
            });
        }
        // Try each offered credential; a fresh Read+Seek view of the ciphertext
        // per attempt (unlock consumes the reader).
        let mut last_err = None;
        for cred in &cands {
            let cursor = SourceCursor::new(Arc::clone(&self.encrypted), 0, self.len);
            let attempt = match cred {
                Credential::Password(p) => BitLockerVolume::unlock_with_password(cursor, p),
                Credential::RecoveryKey(rk) => {
                    BitLockerVolume::unlock_with_recovery_password(cursor, rk)
                }
                // KeyBytes / KeyFile are not a BitLocker protector this layer wires.
                _ => continue,
            };
            match attempt {
                Ok(vol) => return Ok(Arc::new(BitlockerSource::new(vol))),
                Err(e) => last_err = Some(e),
            }
        }
        // Credentials were offered but none unlocked → a loud bad-key Decode,
        // never a silent empty or a guess.
        Err(last_err.as_ref().map_or(
            VfsError::NeedCredentials {
                scheme: "bitlocker",
                target: String::new(),
            },
            map_bde_err,
        ))
    }
}

/// A decrypted BitLocker volume presented as a read-only [`ImageSource`]. Reads
/// serialize through a poison-recovering `Mutex` (bitlocker-core's `read_at`
/// advances an internal cursor).
struct BitlockerSource<R: Read + Seek> {
    inner: Mutex<DecryptedVolume<R>>,
    len: u64,
}

impl<R: Read + Seek> BitlockerSource<R> {
    fn new(vol: DecryptedVolume<R>) -> Self {
        let len = vol.volume_size();
        Self {
            inner: Mutex::new(vol),
            len,
        }
    }
}

impl<R: Read + Seek + Send> ImageSource for BitlockerSource<R> {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let avail = self.len.saturating_sub(offset);
        if avail == 0 {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(avail) as usize;
        let Some(dst) = buf.get_mut(..want) else {
            return Ok(0); // cov:unreachable: want <= buf.len() by the min above
        };
        let mut guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        guard.read_at(offset, dst).map_err(|e| map_bde_err(&e))?;
        Ok(want)
    }
}

#[cfg(test)]
mod tests {
    use super::BitlockerLayer;
    use forensic_vfs::adapters::FileSource;
    use forensic_vfs::{Credential, CredentialSource, CryptoLayer, CryptoScheme, DynSource};
    use std::sync::Arc;

    struct FixedCreds(Vec<Credential>);
    impl CredentialSource for FixedCreds {
        fn credentials_for(&self, _scheme: CryptoScheme, _target: &str) -> Vec<Credential> {
            self.0.clone()
        }
    }

    /// The real dfVFS `bdetogo.raw` BitLocker image (password `bde-TEST`), staged
    /// at /tmp (env `BDE_ORACLE_IMAGE`, default /tmp path). Ground truth from
    /// pybde: the decrypted volume is a FAT — "mkdosfs\0" at [3..11], 0x55AA at
    /// [510..512]. Skips cleanly if the image is absent.
    fn encrypted() -> Option<DynSource> {
        let path =
            std::env::var("BDE_ORACLE_IMAGE").unwrap_or_else(|_| "/tmp/bdetogo.raw".to_string());
        let src = FileSource::open(&path).ok()?;
        Some(Arc::new(src))
    }

    #[test]
    fn bitlocker_cryptolayer_decrypts_bdetogo() {
        let Some(enc) = encrypted() else {
            eprintln!("skip: no BitLocker image (set BDE_ORACLE_IMAGE / stage /tmp/bdetogo.raw)");
            return;
        };
        let layer = BitlockerLayer::new(enc);
        assert_eq!(layer.scheme(), CryptoScheme::Bitlocker);

        let creds = FixedCreds(vec![Credential::Password("bde-TEST".to_string())]);
        let dec: DynSource = layer.open(&creds).expect("unlock bdetogo.raw");
        let mut boot = [0u8; 512];
        assert_eq!(dec.read_at(0, &mut boot).expect("read decrypted boot"), 512);
        assert_eq!(&boot[3..11], b"mkdosfs\0", "decrypted volume is a FAT");
        assert_eq!(&boot[510..512], &[0x55, 0xAA]);

        // No credentials offered → NeedCredentials, never a guess or panic.
        let empty = FixedCreds(vec![]);
        assert!(layer.open(&empty).is_err());
    }
}
