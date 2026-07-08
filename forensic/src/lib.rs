//! # bitlocker-forensic — BitLocker metadata anomaly auditor
//!
//! Emits severity-graded [`forensicnomicon::report::Finding`]s over the
//! key-protector and cipher metadata decoded by [`bitlocker`](bitlocker).
//! Findings are OBSERVATIONS, never verdicts — the examiner draws conclusions.
//!
//! The analyzer never decrypts; it audits the *protector inventory* and *cipher*
//! that are visible without any credential:
//!
//! - `BDE-CLEAR-KEY-PRESENT` — a clear-key protector ⇒ the VMK is unprotected,
//!   so the volume is effectively unencrypted (High).
//! - `BDE-PROTECTOR-INVENTORY` — one per key protector (password / recovery /
//!   TPM / startup key / …) (Info).
//! - `BDE-WEAK-CIPHER` — AES-CBC ± Elephant Diffuser is weaker than AES-XTS,
//!   consistent with an older Windows version (Low).
//! - `BDE-TO-GO` — a BitLocker To Go removable-media volume (Info).
//!
//! ```no_run
//! use std::fs::File;
//! let mut image = File::open("bdetogo.raw")?;
//! for anomaly in bitlocker_forensic::audit_reader(&mut image)? {
//!     println!("{}: {}", anomaly.code, anomaly.note);
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::io::{Read, Seek, SeekFrom};

use bitlocker::{BdeError, BdeVariant, BitLockerVolume, FveMetadata, VolumeHeader};
use forensicnomicon::report::{Category, Evidence, Finding, Observation, Severity, Source};

/// The producing analyzer name embedded in emitted findings' `Source`.
pub const ANALYZER: &str = "bitlocker-forensic";

// BitLocker key-protection types (VMK protector-type field).
const PROT_CLEAR_KEY: u16 = 0x0000;
const PROT_TPM: u16 = 0x0100;
const PROT_STARTUP_KEY: u16 = 0x0200;
const PROT_TPM_PIN: u16 = 0x0500;
const PROT_RECOVERY: u16 = 0x0800;
const PROT_PASSWORD: u16 = 0x2000;

/// A classified BitLocker metadata observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnomalyKind {
    /// A clear-key protector is present: the VMK is stored unprotected, so the
    /// volume can be decrypted with no credential — effectively unencrypted.
    ClearKeyPresent,
    /// A key protector is present (one per protector).
    Protector {
        /// The raw protection-type value.
        protector_type: u16,
    },
    /// The volume cipher is AES-CBC (with or without the Elephant Diffuser),
    /// which is weaker than AES-XTS.
    WeakCipher {
        /// The raw encryption-method value.
        method: u16,
    },
    /// The volume is a BitLocker To Go removable-media volume.
    ToGo,
}

impl AnomalyKind {
    /// Severity — the single source of truth for this kind.
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self {
            AnomalyKind::ClearKeyPresent => Severity::High,
            AnomalyKind::WeakCipher { .. } => Severity::Low,
            AnomalyKind::Protector { .. } | AnomalyKind::ToGo => Severity::Info,
        }
    }

    /// Stable, scheme-prefixed machine code (published contract).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            AnomalyKind::ClearKeyPresent => "BDE-CLEAR-KEY-PRESENT",
            AnomalyKind::Protector { .. } => "BDE-PROTECTOR-INVENTORY",
            AnomalyKind::WeakCipher { .. } => "BDE-WEAK-CIPHER",
            AnomalyKind::ToGo => "BDE-TO-GO",
        }
    }

    /// Analytical lens.
    #[must_use]
    pub fn category(&self) -> Category {
        match self {
            AnomalyKind::ClearKeyPresent | AnomalyKind::WeakCipher { .. } => Category::Integrity,
            AnomalyKind::Protector { .. } => Category::Provenance,
            AnomalyKind::ToGo => Category::Structure,
        }
    }

    /// Human-readable note including the offending value.
    #[must_use]
    pub fn note(&self) -> String {
        match self {
            AnomalyKind::ClearKeyPresent => "a clear-key protector (type 0x0000) is present; the \
                 volume master key is stored unprotected, so the volume can be decrypted with no \
                 credential — it is effectively unencrypted"
                .to_string(),
            AnomalyKind::Protector { protector_type } => format!(
                "key protector present: {} (type 0x{protector_type:04x})",
                protector_name(*protector_type)
            ),
            AnomalyKind::WeakCipher { method } => format!(
                "volume cipher is {} (method 0x{method:04x}); AES-CBC, with or without the Elephant \
                 Diffuser, is weaker than AES-XTS and is consistent with an older Windows version",
                cipher_name(*method)
            ),
            AnomalyKind::ToGo => "the volume is a BitLocker To Go volume (removable-media BitLocker \
                 on a FAT-formatted volume)"
                .to_string(),
        }
    }

    fn evidence(&self) -> Vec<Evidence> {
        match self {
            AnomalyKind::Protector { protector_type } => {
                vec![evidence("protector_type", format!("0x{protector_type:04x}"))]
            }
            AnomalyKind::WeakCipher { method } => {
                vec![evidence("encryption_method", format!("0x{method:04x}"))]
            }
            AnomalyKind::ClearKeyPresent | AnomalyKind::ToGo => Vec::new(),
        }
    }
}

fn evidence(field: &str, value: String) -> Evidence {
    Evidence {
        field: field.to_string(),
        value,
        location: None,
    }
}

/// Human name for a BitLocker key-protection type.
#[must_use]
pub fn protector_name(protector_type: u16) -> &'static str {
    match protector_type {
        PROT_CLEAR_KEY => "clear key",
        PROT_TPM => "TPM",
        PROT_STARTUP_KEY => "startup key",
        PROT_TPM_PIN => "TPM and PIN",
        PROT_RECOVERY => "recovery password",
        PROT_PASSWORD => "password",
        _ => "other/unknown",
    }
}

/// Human name for a BitLocker encryption method.
#[must_use]
pub fn cipher_name(method: u16) -> &'static str {
    match method {
        0x8000 => "AES-128-CBC + Elephant Diffuser",
        0x8001 => "AES-256-CBC + Elephant Diffuser",
        0x8002 => "AES-128-CBC",
        0x8003 => "AES-256-CBC",
        0x8004 => "AES-128-XTS",
        0x8005 => "AES-256-XTS",
        _ => "unknown",
    }
}

/// Whether a cipher method is AES-XTS (the strong, current mode).
#[must_use]
fn is_aes_xts(method: u16) -> bool {
    matches!(method, 0x8004 | 0x8005)
}

/// A BitLocker forensic anomaly: an observation graded by severity, with a stable
/// code and note derived from its [`AnomalyKind`] so they cannot drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anomaly {
    /// Severity, derived from `kind`.
    pub severity: Severity,
    /// Stable machine-readable code, derived from `kind`.
    pub code: &'static str,
    /// The classified anomaly.
    pub kind: AnomalyKind,
    /// Human-readable note, derived from `kind`.
    pub note: String,
}

impl Anomaly {
    /// Build an [`Anomaly`], deriving severity/code/note from `kind`.
    #[must_use]
    pub fn new(kind: AnomalyKind) -> Self {
        Anomaly {
            severity: kind.severity(),
            code: kind.code(),
            note: kind.note(),
            kind,
        }
    }
}

impl Observation for Anomaly {
    fn severity(&self) -> Option<Severity> {
        Some(self.severity)
    }
    fn code(&self) -> &'static str {
        self.code
    }
    fn note(&self) -> String {
        self.note.clone()
    }
    fn category(&self) -> Category {
        self.kind.category()
    }
    fn evidence(&self) -> Vec<Evidence> {
        self.kind.evidence()
    }
}

/// Audit already-parsed metadata (and whether the volume is BitLocker To Go),
/// returning classified anomalies. Pure and side-effect-free.
#[must_use]
pub fn audit(metadata: &FveMetadata, to_go: bool) -> Vec<Anomaly> {
    let mut out = Vec::new();

    if to_go {
        out.push(Anomaly::new(AnomalyKind::ToGo));
    }

    if !is_aes_xts(metadata.encryption_method) {
        out.push(Anomaly::new(AnomalyKind::WeakCipher {
            method: metadata.encryption_method,
        }));
    }

    for protector_type in metadata.protector_types() {
        if protector_type == PROT_CLEAR_KEY {
            out.push(Anomaly::new(AnomalyKind::ClearKeyPresent));
        }
        out.push(Anomaly::new(AnomalyKind::Protector { protector_type }));
    }

    out
}

/// Parse a BitLocker volume from `reader` and audit its metadata.
///
/// # Errors
/// Propagates [`BdeError`] from header/metadata parsing (e.g. a non-BitLocker
/// image or no valid FVE metadata block).
pub fn audit_reader<R: Read + Seek>(reader: &mut R) -> Result<Vec<Anomaly>, BdeError> {
    let mut header = [0u8; 512];
    reader.seek(SeekFrom::Start(0))?;
    reader.read_exact(&mut header)?;
    let variant = VolumeHeader::parse(&header)?.variant;
    let metadata = BitLockerVolume::read_metadata(reader)?;
    Ok(audit(&metadata, variant == BdeVariant::BitLockerToGo))
}

/// Audit a BitLocker volume and map each anomaly to a canonical [`Finding`],
/// tagged with the producing [`Source`] (`scope` names the evidence).
///
/// # Errors
/// Propagates [`BdeError`] from parsing.
pub fn audit_findings<R: Read + Seek>(
    reader: &mut R,
    scope: impl Into<String>,
) -> Result<Vec<Finding>, BdeError> {
    let source = Source {
        analyzer: ANALYZER.to_string(),
        scope: scope.into(),
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
    };
    Ok(audit_reader(reader)?
        .into_iter()
        .map(|anomaly| anomaly.to_finding(source.clone()))
        .collect())
}

#[cfg(test)]
mod tests;
