//! # bitlocker-forensic — BitLocker metadata anomaly auditor
//!
//! Emits severity-graded [`forensicnomicon::report::Finding`]s over the
//! key-protector metadata decoded by [`bitlocker`](bitlocker). Findings are
//! OBSERVATIONS, never verdicts.
//!
//! The analyzer is filled in by its own test-driven cycle; this scaffold only
//! fixes the crate identity.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

/// The producing analyzer name embedded in emitted findings' `Source`.
pub const ANALYZER: &str = "bitlocker-forensic";
