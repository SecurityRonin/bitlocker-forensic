//! Error type for the BitLocker reader/decryptor.
//!
//! The reader never panics on malformed input: out-of-range reads yield safe
//! defaults through the bounds-checked helpers. Genuine failures — a non-BitLocker
//! image, an unsupported cipher, a wrong password (CCM tag mismatch), or missing
//! key material — surface as loud, specific errors that carry the offending value,
//! never a silent empty result.

/// An error decoding or unlocking a BitLocker (BDE) volume.
#[derive(Debug, thiserror::Error)]
pub enum BdeError {
    /// An I/O error reading the underlying volume.
    #[error("i/o error reading BitLocker volume: {0}")]
    Io(#[from] std::io::Error),

    /// The volume header carries neither a BitLocker `-FVE-FS-` signature nor a
    /// BitLocker To Go `MSWIN4.1` signature. The offending bytes at offset 3 are
    /// included so the caller can identify what was actually there.
    #[error("not a BitLocker volume: signature at offset 3 is {signature:02x?} (expected \"-FVE-FS-\" or \"MSWIN4.1\")")]
    NotBitLocker {
        /// The 8 bytes found at offset 3 of the volume header.
        signature: [u8; 8],
    },

    /// No FVE metadata block carried a valid `-FVE-FS-` block-header signature at
    /// any of the three candidate offsets read from the volume header.
    #[error("no valid FVE metadata block found at candidate offsets {offsets:?}")]
    NoValidMetadata {
        /// The three candidate byte offsets tried.
        offsets: [u64; 3],
    },

    /// The volume's encryption method is not one this build decrypts. The raw
    /// method value is included.
    #[error("unsupported encryption method 0x{method:04x} (this build decrypts 0x8000 AES-128-CBC + Elephant Diffuser)")]
    UnsupportedEncryptionMethod {
        /// The raw 16-bit encryption-method value from the metadata header.
        method: u16,
    },

    /// The metadata carries no password-protected VMK (protection type 0x2000),
    /// so `unlock_with_password` cannot proceed. The protector types that *were*
    /// present are listed to guide the examiner toward the right unlock path.
    #[error("no password protector (type 0x2000) present; protectors found: {found:?}")]
    NoPasswordProtector {
        /// The key-protection types that were present.
        found: Vec<u16>,
    },

    /// The password-protected VMK is missing its stretch key or AES-CCM key
    /// entry, so the VMK cannot be derived. Names which part is absent.
    #[error("password protector is malformed: missing {what}")]
    MissingKeyMaterial {
        /// Which required sub-entry was absent (e.g. "stretch key", "AES-CCM key").
        what: &'static str,
    },

    /// The AES-CCM authentication tag did not verify — for a password unlock this
    /// means the supplied password is wrong; for FVEK it means the VMK is wrong.
    #[error(
        "AES-CCM authentication failed unwrapping the {what} (wrong password or corrupt metadata)"
    )]
    AuthenticationFailed {
        /// Which key was being unwrapped ("volume master key" or "FVEK").
        what: &'static str,
    },

    /// A decrypted key container was shorter than the fixed layout requires, or a
    /// key field ran past the end of the plaintext.
    #[error("decrypted {what} key container is malformed (got {got} bytes, need at least {need})")]
    MalformedKeyContainer {
        /// Which container ("volume master key" or "FVEK").
        what: &'static str,
        /// Bytes actually present.
        got: usize,
        /// Minimum bytes the layout requires.
        need: usize,
    },
}

/// Convenience alias for reader results.
pub type Result<T> = std::result::Result<T, BdeError>;
