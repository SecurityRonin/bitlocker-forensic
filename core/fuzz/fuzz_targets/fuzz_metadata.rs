#![no_main]
//! Fuzz the BitLocker parsers over arbitrary bytes: the volume header, the FVE
//! metadata block, the entry sequence, and the header+metadata read path.
//! Invariant: must never panic. (Unlock is excluded — its 0x100000-round stretch
//! would dominate the fuzzer without exercising more parse surface.)

use bitlocker::{BitLockerVolume, FveMetadata, MetadataEntry, VolumeHeader};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let _ = VolumeHeader::parse(data);
    let _ = FveMetadata::parse(data, 512);
    for entry in MetadataEntry::parse_sequence(data) {
        let _ = entry.protection_type();
        let _ = entry.nested(28);
    }
    let _ = BitLockerVolume::read_metadata(&mut Cursor::new(data));
});
