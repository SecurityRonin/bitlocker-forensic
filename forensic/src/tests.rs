use std::io::Cursor;

use bitlocker::{FveMetadata, MetadataEntry};
use forensicnomicon::report::Severity;

use super::*;

fn vmk_entry(protector: u16) -> MetadataEntry {
    let mut data = vec![0u8; 28];
    data[26..28].copy_from_slice(&protector.to_le_bytes());
    MetadataEntry {
        entry_type: 0x0002,
        value_type: 0x0008,
        version: 1,
        data,
    }
}

fn metadata(method: u16, protectors: &[u16]) -> FveMetadata {
    FveMetadata {
        encryption_method: method,
        volume_guid: [0u8; 16],
        creation_time: 0,
        entries: protectors.iter().map(|p| vmk_entry(*p)).collect(),
        encrypted_volume_size: 0,
        volume_header_offset: 0,
        volume_header_size: 0,
        metadata_offsets: [0u64; 3],
        metadata_size: 0,
    }
}

fn has(anomalies: &[Anomaly], code: &str) -> bool {
    anomalies.iter().any(|a| a.code == code)
}

#[test]
fn clear_key_yields_high_finding() {
    let m = metadata(0x8000, &[PROT_CLEAR_KEY, PROT_PASSWORD]);
    let a = audit(&m, true);
    let clear = a
        .iter()
        .find(|x| x.code == "BDE-CLEAR-KEY-PRESENT")
        .expect("clear-key finding");
    assert_eq!(clear.severity, Severity::High);
    assert!(has(&a, "BDE-TO-GO"));
    assert!(a
        .iter()
        .any(|x| x.code == "BDE-WEAK-CIPHER" && x.severity == Severity::Low));
    // One protector-inventory entry per protector.
    assert_eq!(
        a.iter()
            .filter(|x| x.code == "BDE-PROTECTOR-INVENTORY")
            .count(),
        2
    );
}

#[test]
fn xts_and_non_to_go_are_quiet() {
    let a = audit(&metadata(0x8004, &[PROT_PASSWORD]), false);
    assert!(!has(&a, "BDE-WEAK-CIPHER"));
    assert!(!has(&a, "BDE-TO-GO"));
    assert!(!has(&a, "BDE-CLEAR-KEY-PRESENT"));
    // Still inventories the protector.
    assert!(has(&a, "BDE-PROTECTOR-INVENTORY"));
}

#[test]
fn protector_note_includes_type_and_name() {
    let a = audit(&metadata(0x8000, &[PROT_RECOVERY]), false);
    let p = a
        .iter()
        .find(|x| x.code == "BDE-PROTECTOR-INVENTORY")
        .unwrap();
    assert!(p.note.contains("recovery password"), "{}", p.note);
    assert!(p.note.contains("0x0800"), "{}", p.note);
}

#[test]
fn cipher_and_protector_names() {
    assert_eq!(cipher_name(0x8000), "AES-128-CBC + Elephant Diffuser");
    assert_eq!(cipher_name(0x8004), "AES-128-XTS");
    assert_eq!(cipher_name(0x9999), "unknown");
    assert_eq!(protector_name(0x2000), "password");
    assert_eq!(protector_name(0x0100), "TPM");
    assert_eq!(protector_name(0x1234), "other/unknown");
}

/// Build a minimal BitLocker image (metadata only — no key material, since the
/// auditor never unlocks).
fn build_image(method: u16, to_go: bool, protectors: &[u16]) -> Vec<u8> {
    fn entry(entry_type: u16, value_type: u16, data: &[u8]) -> Vec<u8> {
        let size = (8 + data.len()) as u16;
        let mut v = Vec::new();
        v.extend_from_slice(&size.to_le_bytes());
        v.extend_from_slice(&entry_type.to_le_bytes());
        v.extend_from_slice(&value_type.to_le_bytes());
        v.extend_from_slice(&1u16.to_le_bytes());
        v.extend_from_slice(data);
        v
    }

    let mut entries = Vec::new();
    for p in protectors {
        let mut vmk_data = vec![0u8; 28];
        vmk_data[26..28].copy_from_slice(&p.to_le_bytes());
        entries.extend(entry(0x0002, 0x0008, &vmk_data));
    }
    let metadata_size = 48 + entries.len();

    let mb = 0x1000usize;
    let mut image = vec![0u8; 0x2000];
    image[0..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
    image[12] = 0x02; // bytes per sector = 512
    if to_go {
        image[3..11].copy_from_slice(b"MSWIN4.1");
        image[440..448].copy_from_slice(&(mb as u64).to_le_bytes());
    } else {
        image[3..11].copy_from_slice(b"-FVE-FS-");
        image[176..184].copy_from_slice(&(mb as u64).to_le_bytes());
    }

    image[mb..mb + 8].copy_from_slice(b"-FVE-FS-");
    image[mb + 10..mb + 12].copy_from_slice(&2u16.to_le_bytes());
    image[mb + 32..mb + 40].copy_from_slice(&(mb as u64).to_le_bytes());
    image[mb + 64..mb + 68].copy_from_slice(&(metadata_size as u32).to_le_bytes());
    image[mb + 64 + 36..mb + 64 + 38].copy_from_slice(&method.to_le_bytes());
    image[mb + 64 + 48..mb + 64 + 48 + entries.len()].copy_from_slice(&entries);
    image
}

#[test]
fn audit_reader_on_to_go_password_volume() {
    let img = build_image(0x8000, true, &[PROT_PASSWORD]);
    let a = audit_reader(&mut Cursor::new(img)).unwrap();
    assert!(has(&a, "BDE-TO-GO"));
    assert!(has(&a, "BDE-WEAK-CIPHER"));
    assert!(has(&a, "BDE-PROTECTOR-INVENTORY"));
}

#[test]
fn audit_findings_map_source_and_severity() {
    let img = build_image(0x8000, true, &[PROT_CLEAR_KEY]);
    let findings = audit_findings(&mut Cursor::new(img), "evidence.raw").unwrap();
    assert!(findings.iter().all(|f| f.source.analyzer == ANALYZER));
    assert!(findings
        .iter()
        .any(|f| f.code == "BDE-CLEAR-KEY-PRESENT" && f.severity == Some(Severity::High)));
}

#[test]
fn audit_reader_rejects_non_bitlocker() {
    let r = audit_reader(&mut Cursor::new(vec![0u8; 1024]));
    assert!(matches!(r, Err(bitlocker::BdeError::NotBitLocker { .. })));
}
