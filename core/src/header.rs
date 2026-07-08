//! BitLocker volume-header parsing.
//!
//! The first 512-byte sector identifies the BitLocker variant and locates the
//! three FVE metadata blocks. Three on-disk layouts exist (Windows Vista,
//! Windows 7/10, and BitLocker To Go on FAT); they are distinguished by the
//! signature at offset 3 and the boot entry at offset 0. This is not a
//! special-case per image — it is the documented rule for each variant of the
//! format (see `docs/RESEARCH.md`).

use crate::bytes::{le_u16, le_u64, read_guid};
use crate::error::{BdeError, Result};

/// Which BitLocker on-disk volume-header layout was recognised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BdeVariant {
    /// Windows Vista (`-FVE-FS-`, boot `EB 52 90`): metadata block 1 is a cluster
    /// number; the other two offsets come from the metadata block header.
    WindowsVista,
    /// Windows 7 and later (`-FVE-FS-`, boot `EB 58 90`).
    Windows7OrLater,
    /// BitLocker To Go on a FAT volume (`MSWIN4.1`).
    BitLockerToGo,
}

/// The parsed BitLocker volume header.
#[derive(Debug, Clone)]
pub struct VolumeHeader {
    /// Which layout was recognised.
    pub variant: BdeVariant,
    /// Bytes per sector (from the BPB); defaults to 512 when the field is zero.
    pub bytes_per_sector: u16,
    /// The BitLocker identifier GUID (all-zero for the Vista layout, which stores
    /// none at a fixed offset).
    pub bitlocker_guid: [u8; 16],
    /// Byte offsets of the three FVE metadata blocks relative to the volume start.
    /// For the Vista layout only the first is derived here (the block header
    /// carries all three authoritatively).
    pub fve_metadata_offsets: [u64; 3],
}

const SIG_FVE: &[u8; 8] = b"-FVE-FS-";
const SIG_TO_GO: &[u8; 8] = b"MSWIN4.1";
const BOOT_WIN7: [u8; 3] = [0xeb, 0x58, 0x90];

impl VolumeHeader {
    /// Parse the 512-byte volume header sector.
    ///
    /// # Errors
    /// Returns [`BdeError::NotBitLocker`] (carrying the offending signature bytes)
    /// when neither the `-FVE-FS-` nor the `MSWIN4.1` signature is present.
    pub fn parse(_sector: &[u8]) -> Result<VolumeHeader> {
        // RED stub — replaced by the real parser in the GREEN commit.
        unimplemented!("VolumeHeader::parse")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_sector() -> Vec<u8> {
        let mut s = vec![0u8; 512];
        s[11] = 0x00;
        s[12] = 0x02; // bytes per sector = 512 (LE)
        s
    }

    #[test]
    fn parses_bitlocker_to_go() {
        let mut s = base_sector();
        s[0..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
        s[3..11].copy_from_slice(b"MSWIN4.1");
        s[424..440].copy_from_slice(&[
            0x3b, 0xd6, 0x67, 0x49, 0x29, 0x2e, 0xd8, 0x4a, 0x83, 0x99, 0xf6, 0xa3, 0x39, 0xe3,
            0xd0, 0x01,
        ]);
        s[440..448].copy_from_slice(&0x0210_0000u64.to_le_bytes());
        s[448..456].copy_from_slice(&0x02b5_5800u64.to_le_bytes());
        s[456..464].copy_from_slice(&0x035a_b000u64.to_le_bytes());

        let h = VolumeHeader::parse(&s).unwrap();
        assert_eq!(h.variant, BdeVariant::BitLockerToGo);
        assert_eq!(h.bytes_per_sector, 512);
        assert_eq!(
            h.fve_metadata_offsets,
            [0x0210_0000, 0x02b5_5800, 0x035a_b000]
        );
        assert_eq!(
            crate::format_guid(&h.bitlocker_guid),
            "4967d63b-2e29-4ad8-8399-f6a339e3d001"
        );
    }

    #[test]
    fn parses_windows7() {
        let mut s = base_sector();
        s[0..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
        s[3..11].copy_from_slice(b"-FVE-FS-");
        s[176..184].copy_from_slice(&0x1000u64.to_le_bytes());
        s[184..192].copy_from_slice(&0x2000u64.to_le_bytes());
        s[192..200].copy_from_slice(&0x3000u64.to_le_bytes());

        let h = VolumeHeader::parse(&s).unwrap();
        assert_eq!(h.variant, BdeVariant::Windows7OrLater);
        assert_eq!(h.fve_metadata_offsets, [0x1000, 0x2000, 0x3000]);
    }

    #[test]
    fn parses_vista_cluster_offset() {
        let mut s = base_sector();
        s[0..3].copy_from_slice(&[0xeb, 0x52, 0x90]);
        s[3..11].copy_from_slice(b"-FVE-FS-");
        s[13] = 8; // sectors per cluster
        s[56..64].copy_from_slice(&100u64.to_le_bytes()); // cluster number
        let h = VolumeHeader::parse(&s).unwrap();
        assert_eq!(h.variant, BdeVariant::WindowsVista);
        // 100 clusters * (512 * 8) = 409600
        assert_eq!(h.fve_metadata_offsets[0], 100 * 512 * 8);
    }

    #[test]
    fn rejects_non_bitlocker_with_signature() {
        let mut s = base_sector();
        s[0..3].copy_from_slice(&[0xeb, 0x52, 0x90]);
        s[3..11].copy_from_slice(b"NTFS    ");
        match VolumeHeader::parse(&s) {
            Err(BdeError::NotBitLocker { signature }) => assert_eq!(&signature, b"NTFS    "),
            other => panic!("expected NotBitLocker, got {other:?}"),
        }
    }

    #[test]
    fn short_sector_does_not_panic() {
        assert!(matches!(
            VolumeHeader::parse(&[0u8; 4]),
            Err(BdeError::NotBitLocker { .. })
        ));
    }
}
