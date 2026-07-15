//! `forensic-vfs` [`CryptoLayer`] adapter for BitLocker, behind the `vfs` feature.
//!
//! Wraps an encrypted BitLocker volume (a parent [`ImageSource`]) and, given a
//! credential, presents the **decrypted** volume as a [`DynSource`] a normal
//! filesystem mounts unchanged. The decryption is bitlocker-core's own (audited
//! RustCrypto ciphers + the `elephant-diffuser` crate); this module only wires
//! the contract: pull a credential from the [`CredentialSource`], call the
//! matching `unlock_*`, and expose the result as a positioned-read source.

use forensic_vfs::{CredentialSource, CryptoLayer, CryptoScheme, DynSource, VfsError, VfsResult};

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

impl CryptoLayer for BitlockerLayer {
    fn scheme(&self) -> CryptoScheme {
        CryptoScheme::Bitlocker
    }

    fn open(&self, _creds: &dyn CredentialSource) -> VfsResult<DynSource> {
        // RED: decryption not wired yet.
        Err(VfsError::NeedCredentials {
            scheme: "bitlocker",
            target: String::new(),
        })
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
