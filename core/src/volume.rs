//! Public API: parse a BitLocker volume's metadata and unlock it from a password.
//!
//! [`BitLockerVolume::unlock_with_password`] runs the full chain — parse the
//! volume header, locate and parse the FVE metadata, derive the VMK from the
//! password (stretch → AES-CCM), unwrap the FVEK/TWEAK, and return a
//! [`DecryptedVolume`] exposing a plaintext `Read + Seek` view that honours
//! BitLocker's volume-header relocation and metadata-region blanking.

use std::io::{Read, Seek, SeekFrom};

use crate::crypto::{aes_ccm_unwrap, password_hash, stretch_key, SectorCipher};
use crate::error::{BdeError, Result};
use crate::header::VolumeHeader;
use crate::metadata::{FveMetadata, PROTECTION_PASSWORD, VALUE_TYPE_AES_CCM, VALUE_TYPE_STRETCH};

/// Encryption method decrypted by this build: AES-128-CBC + Elephant Diffuser.
const METHOD_AES128_CBC_DIFFUSER: u16 = 0x8000;
/// Encryption method sentinel: the volume is not encrypted.
const METHOD_NONE: u16 = 0x0000;
/// The fixed BitLocker sector size.
const SECTOR_SIZE: usize = 512;
/// How many bytes to read at a candidate metadata offset (reserved FVE metadata
/// blocks are well under this).
const METADATA_READ_LEN: usize = 64 * 1024;

/// Namespace for opening a BitLocker volume. All state lives in the returned
/// [`DecryptedVolume`]; this type carries no data itself.
pub struct BitLockerVolume;

impl BitLockerVolume {
    /// Parse the volume header and the first valid FVE metadata block from
    /// `reader`, without unlocking. Used by the forensic analyzer to audit the
    /// key protectors even when no password is known.
    ///
    /// # Errors
    /// [`BdeError::NotBitLocker`] if the header signature is absent, or
    /// [`BdeError::NoValidMetadata`] if no `-FVE-FS-` block is found.
    pub fn read_metadata<R: Read + Seek>(reader: &mut R) -> Result<FveMetadata> {
        let _ = ();
        unimplemented!("RED stub");
    }

    /// Unlock the volume with `password`, returning a plaintext view.
    ///
    /// # Errors
    /// Fails loud on a non-BitLocker image, an unsupported cipher, a missing
    /// password protector, absent key material, or a wrong password (the AES-CCM
    /// tag fails to verify).
    pub fn unlock_with_password<R: Read + Seek>(
        mut reader: R,
        password: &str,
    ) -> Result<DecryptedVolume<R>> {
        let _ = ();
        unimplemented!("RED stub");
    }
}

/// Derive the sector cipher (FVEK + TWEAK) from the password-protected VMK.
fn derive_cipher(metadata: &FveMetadata, password: &str) -> Result<SectorCipher> {
    // 1. Locate the password-protected VMK.
    let vmk = metadata
        .vmk_entries()
        .find(|e| e.protection_type() == Some(PROTECTION_PASSWORD))
        .ok_or_else(|| BdeError::NoPasswordProtector {
            found: metadata.protector_types(),
        })?;

    // VMK properties are nested entries starting at value-data offset 28.
    let props = vmk.nested(28);
    let stretch = props
        .iter()
        .find(|e| e.value_type == VALUE_TYPE_STRETCH)
        .ok_or(BdeError::MissingKeyMaterial {
            what: "stretch key",
        })?;
    let vmk_ccm = props
        .iter()
        .find(|e| e.value_type == VALUE_TYPE_AES_CCM)
        .ok_or(BdeError::MissingKeyMaterial {
            what: "VMK AES-CCM key",
        })?;

    // Salt is at stretch value-data offset 4 (after the 4-byte method).
    let mut salt = [0u8; 16];
    let salt_src = stretch
        .data
        .get(4..20)
        .ok_or(BdeError::MissingKeyMaterial {
            what: "stretch salt",
        })?;
    salt.copy_from_slice(salt_src);

    // 2. Password -> stretched key -> unwrap the VMK.
    let stretched = stretch_key(&password_hash(password), &salt);
    let vmk_container =
        aes_ccm_unwrap(&stretched, &vmk_ccm.data).ok_or(BdeError::AuthenticationFailed {
            what: "volume master key",
        })?;
    let vmk_key = take_key32(&vmk_container, 12, "volume master key")?;

    // 3. FVEK entry -> unwrap with the VMK -> FVEK + TWEAK (first 16 bytes each).
    let fvek_entry = metadata
        .fvek_entry()
        .ok_or(BdeError::MissingKeyMaterial { what: "FVEK entry" })?;
    let fvek_container = aes_ccm_unwrap(&vmk_key, &fvek_entry.data)
        .ok_or(BdeError::AuthenticationFailed { what: "FVEK" })?;
    let fvek = take_key16(&fvek_container, 12, "FVEK")?;
    let tweak = take_key16(&fvek_container, 44, "FVEK")?;

    Ok(SectorCipher::new(fvek, tweak))
}

fn take_key32(container: &[u8], off: usize, what: &'static str) -> Result<[u8; 32]> {
    let s = container
        .get(off..off + 32)
        .ok_or(BdeError::MalformedKeyContainer {
            what,
            got: container.len(),
            need: off + 32,
        })?;
    let mut k = [0u8; 32];
    k.copy_from_slice(s);
    Ok(k)
}

fn take_key16(container: &[u8], off: usize, what: &'static str) -> Result<[u8; 16]> {
    let s = container
        .get(off..off + 16)
        .ok_or(BdeError::MalformedKeyContainer {
            what,
            got: container.len(),
            need: off + 16,
        })?;
    let mut k = [0u8; 16];
    k.copy_from_slice(s);
    Ok(k)
}

/// A plaintext view of an unlocked BitLocker volume.
pub struct DecryptedVolume<R> {
    reader: R,
    cipher: SectorCipher,
    metadata: FveMetadata,
    total_size: u64,
    position: u64,
}

impl<R: Read + Seek> DecryptedVolume<R> {
    /// The parsed FVE metadata (cipher, protectors, volume GUID, …).
    #[must_use]
    pub fn metadata(&self) -> &FveMetadata {
        &self.metadata
    }

    /// The total size of the volume in bytes.
    #[must_use]
    pub fn volume_size(&self) -> u64 {
        self.total_size
    }

    /// Read decrypted bytes at logical `offset` into `buf`, filling it completely
    /// (bytes past the end of the volume read back as zero).
    ///
    /// # Errors
    /// Propagates I/O errors from the underlying reader.
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            let sector_start = pos - (pos % SECTOR_SIZE as u64);
            let within = (pos - sector_start) as usize;
            let plain = self.decrypt_logical_sector(sector_start)?;
            let take = (SECTOR_SIZE - within).min(buf.len() - done);
            buf[done..done + take].copy_from_slice(&plain[within..within + take]);
            done += take;
        }
        Ok(())
    }

    /// Decrypt the logical 512-byte sector starting at `sector_start` (a multiple
    /// of 512), applying metadata-region blanking, volume-header relocation, and
    /// the encrypted-volume-size boundary exactly as BitLocker's read path does.
    fn decrypt_logical_sector(&mut self, sector_start: u64) -> Result<[u8; SECTOR_SIZE]> {
        // Metadata block regions read back as zero in the decrypted view.
        let meta_size = u64::from(self.metadata.metadata_size);
        for &m in &self.metadata.metadata_offsets {
            if m != 0 && sector_start >= m && sector_start < m + meta_size {
                return Ok([0u8; SECTOR_SIZE]);
            }
        }

        // The first `volume_header_size` bytes are stored, encrypted, elsewhere;
        // the physical location doubles as the IV sector address.
        let physical = if sector_start < self.metadata.volume_header_size {
            self.metadata.volume_header_offset + sector_start
        } else {
            sector_start
        };

        let mut ct = [0u8; SECTOR_SIZE];
        self.reader.seek(SeekFrom::Start(physical))?;
        read_available(&mut self.reader, &mut ct)?;

        // Not encrypted: NONE method, or past the still-encrypted region.
        let evs = self.metadata.encrypted_volume_size;
        if self.metadata.encryption_method == METHOD_NONE || (evs != 0 && physical >= evs) {
            return Ok(ct);
        }

        let plain = self.cipher.decrypt_sector(&ct, physical);
        let mut out = [0u8; SECTOR_SIZE];
        let n = plain.len().min(SECTOR_SIZE);
        out[..n].copy_from_slice(&plain[..n]);
        Ok(out)
    }
}

impl<R: Read + Seek> Read for DecryptedVolume<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.position >= self.total_size {
            return Ok(0);
        }
        let remaining = self.total_size - self.position;
        let n = (buf.len() as u64).min(remaining) as usize;
        self.read_at(self.position, &mut buf[..n])
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        self.position += n as u64;
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for DecryptedVolume<R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(o) => o as i128,
            SeekFrom::End(o) => self.total_size as i128 + o as i128,
            SeekFrom::Current(o) => self.position as i128 + o as i128,
        };
        if new < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.position = new as u64;
        Ok(self.position)
    }
}

/// Read exactly `buf.len()` bytes, erroring on premature EOF.
fn read_fill<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<()> {
    reader.read_exact(buf)?;
    Ok(())
}

/// Read up to `buf.len()` bytes, zero-filling the remainder on EOF. Returns the
/// number of real bytes read.
fn read_available<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    for b in &mut buf[filled..] {
        *b = 0;
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{aes_ccm_wrap, password_hash, stretch_key, SectorCipher};
    use crate::metadata::{
        ENTRY_TYPE_FVEK, ENTRY_TYPE_VMK, ENTRY_TYPE_VOLUME_HEADER, PROTECTION_PASSWORD,
    };
    use std::io::Cursor;

    const RELOCATED_OFFSET: u64 = 0x4000;
    const META_BLOCK_OFFSET: u64 = 0x1000;
    const IMAGE_SIZE: usize = 0x5000;

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

    /// Build a minimal synthetic BitLocker To Go volume plus the plaintext of its
    /// relocated first sector.
    fn build_volume(password: &str) -> (Vec<u8>, [u8; 512]) {
        let salt = [0x33u8; 16];
        let fvek = [0x11u8; 16];
        let tweak = [0x22u8; 16];
        let vmk = [0x44u8; 32];

        let mut vmk_container = vec![0u8; 44];
        vmk_container[12..44].copy_from_slice(&vmk);
        let stretched = stretch_key(&password_hash(password), &salt);
        let vmk_ccm = aes_ccm_wrap(&stretched, &[0x55; 12], &vmk_container);

        let mut fvek_container = vec![0u8; 76];
        fvek_container[12..28].copy_from_slice(&fvek);
        fvek_container[44..60].copy_from_slice(&tweak);
        let fvek_ccm = aes_ccm_wrap(&vmk, &[0x66; 12], &fvek_container);

        let mut stretch_data = vec![0u8; 4]; // 4-byte method
        stretch_data.extend_from_slice(&salt);
        let stretch_entry = entry(0, VALUE_TYPE_STRETCH, &stretch_data);
        let vmk_ccm_entry = entry(0, VALUE_TYPE_AES_CCM, &vmk_ccm);

        let mut vmk_data = vec![0u8; 28];
        vmk_data[26..28].copy_from_slice(&PROTECTION_PASSWORD.to_le_bytes());
        vmk_data.extend_from_slice(&stretch_entry);
        vmk_data.extend_from_slice(&vmk_ccm_entry);
        let vmk_entry = entry(ENTRY_TYPE_VMK, VALUE_TYPE_VMK, &vmk_data);

        let fvek_entry = entry(ENTRY_TYPE_FVEK, VALUE_TYPE_AES_CCM, &fvek_ccm);

        let mut vh_data = Vec::new();
        vh_data.extend_from_slice(&RELOCATED_OFFSET.to_le_bytes());
        vh_data.extend_from_slice(&512u64.to_le_bytes());
        let vh_entry = entry(ENTRY_TYPE_VOLUME_HEADER, ENTRY_TYPE_VOLUME_HEADER, &vh_data);

        let mut entries = Vec::new();
        entries.extend_from_slice(&vh_entry);
        entries.extend_from_slice(&vmk_entry);
        entries.extend_from_slice(&fvek_entry);
        let metadata_size = 48 + entries.len();

        let mut image = vec![0u8; IMAGE_SIZE];
        image[0..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
        image[3..11].copy_from_slice(b"MSWIN4.1");
        image[12] = 0x02; // bytes per sector = 512
        image[440..448].copy_from_slice(&META_BLOCK_OFFSET.to_le_bytes());

        let mb = META_BLOCK_OFFSET as usize;
        image[mb..mb + 8].copy_from_slice(b"-FVE-FS-");
        image[mb + 10..mb + 12].copy_from_slice(&2u16.to_le_bytes());
        image[mb + 16..mb + 24].copy_from_slice(&(IMAGE_SIZE as u64).to_le_bytes());
        image[mb + 28..mb + 32].copy_from_slice(&1u32.to_le_bytes());
        image[mb + 32..mb + 40].copy_from_slice(&META_BLOCK_OFFSET.to_le_bytes());
        image[mb + 56..mb + 64].copy_from_slice(&RELOCATED_OFFSET.to_le_bytes());
        image[mb + 64..mb + 68].copy_from_slice(&(metadata_size as u32).to_le_bytes());
        image[mb + 64 + 36..mb + 64 + 38].copy_from_slice(&0x8000u16.to_le_bytes());
        image[mb + 64 + 48..mb + 64 + 48 + entries.len()].copy_from_slice(&entries);

        let mut plain = [0u8; 512];
        for (i, b) in plain.iter_mut().enumerate() {
            *b = (i as u8) ^ 0x5a;
        }
        let cipher = SectorCipher::new(fvek, tweak);
        let ct = cipher.encrypt_sector(&plain, RELOCATED_OFFSET);
        let ro = RELOCATED_OFFSET as usize;
        image[ro..ro + 512].copy_from_slice(&ct);

        (image, plain)
    }

    use crate::metadata::{VALUE_TYPE_AES_CCM, VALUE_TYPE_STRETCH, VALUE_TYPE_VMK};

    #[test]
    fn unlock_and_read_synthetic_volume() {
        // Self-consistency (Tier-3): we author both encoder and decoder here, so
        // this proves the pipeline is internally consistent, NOT that it matches
        // BitLocker. The Tier-1 pybde oracle (oracle_bdetogo.rs) is the real proof.
        let (image, plain) = build_volume("test-pw");
        let mut vol = BitLockerVolume::unlock_with_password(Cursor::new(image), "test-pw").unwrap();
        let mut buf = [0u8; 512];
        vol.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, plain);
        assert_eq!(vol.metadata().encryption_method, 0x8000);
    }

    #[test]
    fn wrong_password_fails_authentication() {
        let (image, _) = build_volume("test-pw");
        match BitLockerVolume::unlock_with_password(Cursor::new(image), "wrong") {
            Err(BdeError::AuthenticationFailed { what }) => assert_eq!(what, "volume master key"),
            Err(e) => panic!("expected AuthenticationFailed, got {e:?}"),
            Ok(_) => panic!("expected AuthenticationFailed, got a decrypted volume"),
        }
    }

    #[test]
    fn read_and_seek_traits() {
        use std::io::{Read as _, Seek as _};
        let (image, plain) = build_volume("test-pw");
        let mut vol = BitLockerVolume::unlock_with_password(Cursor::new(image), "test-pw").unwrap();
        vol.seek(SeekFrom::Start(0)).unwrap();
        let mut buf = [0u8; 256];
        vol.read_exact(&mut buf).unwrap();
        assert_eq!(&buf[..], &plain[..256]);
        assert_eq!(vol.volume_size(), IMAGE_SIZE as u64);
    }

    #[test]
    fn non_bitlocker_reader_errors() {
        let r = BitLockerVolume::unlock_with_password(Cursor::new(vec![0u8; 1024]), "x");
        assert!(matches!(r, Err(BdeError::NotBitLocker { .. })));
    }

    #[test]
    fn read_metadata_reports_protectors() {
        let (image, _) = build_volume("test-pw");
        let meta = BitLockerVolume::read_metadata(&mut Cursor::new(image)).unwrap();
        assert_eq!(meta.protector_types(), vec![PROTECTION_PASSWORD]);
    }
}
