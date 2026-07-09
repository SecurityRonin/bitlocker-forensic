//! Public API: parse a BitLocker volume's metadata and unlock it from a password.
//!
//! [`BitLockerVolume::unlock_with_password`] runs the full chain — parse the
//! volume header, locate and parse the FVE metadata, derive the VMK from the
//! password (stretch → AES-CCM), unwrap the FVEK/TWEAK, and return a
//! [`DecryptedVolume`] exposing a plaintext `Read + Seek` view that honours
//! BitLocker's volume-header relocation and metadata-region blanking.

use std::io::{Read, Seek, SeekFrom};

use crate::crypto::{aes_ccm_unwrap, password_hash, recovery_key_hash, stretch_key, SectorCipher};
use crate::error::{BdeError, Result};
use crate::header::VolumeHeader;
use crate::metadata::{
    FveMetadata, PROTECTION_PASSWORD, PROTECTION_RECOVERY, VALUE_TYPE_AES_CCM, VALUE_TYPE_STRETCH,
};
use crate::method::{EncryptionMethod, SectorCipherKind};

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
        let mut header = [0u8; SECTOR_SIZE];
        reader.seek(SeekFrom::Start(0))?;
        read_fill(reader, &mut header)?;
        let volume_header = VolumeHeader::parse(&header)?;

        let offsets = volume_header.fve_metadata_offsets;
        for &offset in &offsets {
            if offset == 0 {
                continue;
            }
            let mut block = vec![0u8; METADATA_READ_LEN];
            reader.seek(SeekFrom::Start(offset))?;
            let n = read_available(reader, &mut block)?;
            block.truncate(n);
            if let Some(meta) = FveMetadata::parse(&block, volume_header.bytes_per_sector) {
                return Ok(meta);
            }
        }
        Err(BdeError::NoValidMetadata { offsets })
    }

    /// Unlock the volume with `password`, returning a plaintext view.
    ///
    /// # Errors
    /// Fails loud on a non-BitLocker image, an unsupported cipher, a missing
    /// password protector, absent key material, or a wrong password (the AES-CCM
    /// tag fails to verify).
    pub fn unlock_with_password<R: Read + Seek>(
        reader: R,
        password: &str,
    ) -> Result<DecryptedVolume<R>> {
        Self::unlock_with_protector(
            reader,
            PROTECTION_PASSWORD,
            "password",
            password_hash(password),
        )
    }

    /// Unlock the volume with a 48-digit `recovery` password, returning a
    /// plaintext view. Uses the recovery protector (`0x0800`) and the recovery
    /// key-derivation ([`crate::crypto::recovery_key_hash`]).
    ///
    /// # Errors
    /// [`BdeError::InvalidRecoveryPassword`] if the recovery password is
    /// malformed; otherwise the same failures as [`Self::unlock_with_password`]
    /// (non-BitLocker image, unsupported/unvalidated cipher, no recovery
    /// protector, absent key material, or a wrong key).
    pub fn unlock_with_recovery_password<R: Read + Seek>(
        reader: R,
        recovery: &str,
    ) -> Result<DecryptedVolume<R>> {
        let key_hash = recovery_key_hash(recovery)
            .map_err(|reason| BdeError::InvalidRecoveryPassword { reason })?;
        Self::unlock_with_protector(reader, PROTECTION_RECOVERY, "recovery password", key_hash)
    }

    /// Shared unlock path: parse metadata, gate the cipher method, derive the
    /// sector cipher from the given protector, and return the plaintext view.
    fn unlock_with_protector<R: Read + Seek>(
        mut reader: R,
        protector_type: u16,
        protector_name: &'static str,
        key_hash: [u8; 32],
    ) -> Result<DecryptedVolume<R>> {
        let metadata = Self::read_metadata(&mut reader)?;

        // Decode the method into its three axes, then gate on whether we have an
        // oracle-validated decrypt for it: unrecognized ⇒ Unsupported; recognized
        // but no oracle (0x8001/0x8003/0x8004/0x8005) ⇒ Unvalidated (refuse, never
        // decrypt by construction); validated ⇒ build the sector cipher.
        let raw = metadata.encryption_method;
        let kind = EncryptionMethod::decode(raw)
            .ok_or(BdeError::UnsupportedEncryptionMethod { method: raw })?
            .validated_kind()
            .ok_or(BdeError::UnvalidatedEncryptionMethod { method: raw })?;

        let cipher = derive_cipher(&metadata, kind, protector_type, protector_name, &key_hash)?;
        let total_size = reader.seek(SeekFrom::End(0))?;

        Ok(DecryptedVolume {
            reader,
            cipher,
            metadata,
            total_size,
            position: 0,
        })
    }
}

/// Derive the sector cipher from the VMK protected by `protector_type`, using
/// `key_hash` as the stretch input, and build the transform for the
/// already-validated `kind`. `protector_name` names the protector in the
/// not-found error.
fn derive_cipher(
    metadata: &FveMetadata,
    kind: SectorCipherKind,
    protector_type: u16,
    protector_name: &'static str,
    key_hash: &[u8; 32],
) -> Result<SectorCipher> {
    // 1. Locate the VMK for the requested protector.
    let vmk = metadata
        .vmk_entries()
        .find(|e| e.protection_type() == Some(protector_type))
        .ok_or_else(|| BdeError::NoUnlockProtector {
            protector: protector_name,
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

    // 2. Key hash -> stretched key -> unwrap the VMK.
    let stretched = stretch_key(key_hash, &salt);
    let vmk_container =
        aes_ccm_unwrap(&stretched, &vmk_ccm.data).ok_or(BdeError::AuthenticationFailed {
            what: "volume master key",
        })?;
    let vmk_key = take_key32(&vmk_container, 12, "volume master key")?;

    // 3. FVEK entry -> unwrap with the VMK -> FVEK (first 16 bytes). The
    //    diffuser kind additionally carries a 16-byte TWEAK key at offset 44.
    let fvek_entry = metadata
        .fvek_entry()
        .ok_or(BdeError::MissingKeyMaterial { what: "FVEK entry" })?;
    let fvek_container = aes_ccm_unwrap(&vmk_key, &fvek_entry.data)
        .ok_or(BdeError::AuthenticationFailed { what: "FVEK" })?;

    match kind {
        SectorCipherKind::Cbc128Diffuser => {
            let fvek = take_key16(&fvek_container, 12, "FVEK")?;
            let tweak = take_key16(&fvek_container, 44, "FVEK")?;
            Ok(SectorCipher::new(fvek, tweak))
        }
        SectorCipherKind::Cbc128 => {
            let fvek = take_key16(&fvek_container, 12, "FVEK")?;
            Ok(SectorCipher::new_cbc(fvek))
        }
        SectorCipherKind::Cbc256 => {
            let fvek = take_key32(&fvek_container, 12, "FVEK")?;
            Ok(SectorCipher::new_cbc256(fvek))
        }
    }
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
            SeekFrom::Start(o) => i128::from(o),
            SeekFrom::End(o) => i128::from(self.total_size) + i128::from(o),
            SeekFrom::Current(o) => i128::from(self.position) + i128::from(o),
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
    // Smaller than the image so a physical offset past it exercises the
    // still-encrypted-region boundary (bytes beyond are returned raw).
    const ENCRYPTED_SIZE: u64 = 0x4800;

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
        image[mb + 16..mb + 24].copy_from_slice(&ENCRYPTED_SIZE.to_le_bytes());
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

        // A metadata-block region reads back as zero in the decrypted view.
        let mut z = [1u8; 512];
        vol.read_at(META_BLOCK_OFFSET, &mut z).unwrap();
        assert_eq!(z, [0u8; 512]);

        // A sector past the relocated volume-header region but still encrypted:
        // physical == logical, decrypted in place (no panic).
        let mut e = [0u8; 512];
        vol.read_at(0x600, &mut e).unwrap();

        // A sector at/after the encrypted-volume-size boundary is returned raw
        // (the image is zero there).
        let mut r = [0u8; 512];
        vol.read_at(ENCRYPTED_SIZE, &mut r).unwrap();
        assert_eq!(r, [0u8; 512]);
    }

    /// CBC-encrypt one sector for method 0x8002: IV = ECB(FVEK, LE128(off)),
    /// then AES-128-CBC encrypt with the FVEK — no diffuser, no tweak. This is a
    /// test-authored encoder (Tier-3 self-consistency); the Tier-1 proof that the
    /// *decrypt* matches BitLocker is `core/tests/oracle_bitlocker1.rs`.
    fn cbc_encrypt_sector(fvek: &[u8; 16], byte_offset: u64, plain: &[u8; 512]) -> [u8; 512] {
        use aes::cipher::block_padding::NoPadding;
        use aes::cipher::generic_array::GenericArray;
        use aes::cipher::{BlockEncrypt, BlockEncryptMut, KeyInit, KeyIvInit};
        use aes::Aes128;

        let mut iv = [0u8; 16];
        iv[0..8].copy_from_slice(&byte_offset.to_le_bytes());
        let mut iv_block = GenericArray::clone_from_slice(&iv);
        Aes128::new(GenericArray::from_slice(fvek)).encrypt_block(&mut iv_block);

        let mut buf = *plain;
        cbc::Encryptor::<Aes128>::new(GenericArray::from_slice(fvek), &iv_block)
            .encrypt_padded_mut::<NoPadding>(&mut buf, 512)
            .unwrap();
        buf
    }

    /// Build a minimal synthetic method-0x8002 (AES-128-CBC, no diffuser) volume
    /// plus the plaintext of its relocated first sector, wrapping the VMK under
    /// `protector_type` with `key_hash` as the stretch input. The FVEK container
    /// holds only a 128-bit FVEK (no TWEAK) — the key layout for a no-diffuser
    /// volume.
    fn build_cbc_volume(protector_type: u16, key_hash: [u8; 32]) -> (Vec<u8>, [u8; 512]) {
        let salt = [0x37u8; 16];
        let fvek = [0x13u8; 16];
        let vmk = [0x46u8; 32];

        let mut vmk_container = vec![0u8; 44];
        vmk_container[12..44].copy_from_slice(&vmk);
        let stretched = stretch_key(&key_hash, &salt);
        let vmk_ccm = aes_ccm_wrap(&stretched, &[0x57; 12], &vmk_container);

        // No TWEAK for 0x8002: the container carries only the FVEK at offset 12.
        let mut fvek_container = vec![0u8; 44];
        fvek_container[12..28].copy_from_slice(&fvek);
        let fvek_ccm = aes_ccm_wrap(&vmk, &[0x68; 12], &fvek_container);

        let mut stretch_data = vec![0u8; 4];
        stretch_data.extend_from_slice(&salt);
        let stretch_entry = entry(0, VALUE_TYPE_STRETCH, &stretch_data);
        let vmk_ccm_entry = entry(0, VALUE_TYPE_AES_CCM, &vmk_ccm);

        let mut vmk_data = vec![0u8; 28];
        vmk_data[26..28].copy_from_slice(&protector_type.to_le_bytes());
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
        image[12] = 0x02;
        image[440..448].copy_from_slice(&META_BLOCK_OFFSET.to_le_bytes());

        let mb = META_BLOCK_OFFSET as usize;
        image[mb..mb + 8].copy_from_slice(b"-FVE-FS-");
        image[mb + 10..mb + 12].copy_from_slice(&2u16.to_le_bytes());
        image[mb + 16..mb + 24].copy_from_slice(&ENCRYPTED_SIZE.to_le_bytes());
        image[mb + 28..mb + 32].copy_from_slice(&1u32.to_le_bytes());
        image[mb + 32..mb + 40].copy_from_slice(&META_BLOCK_OFFSET.to_le_bytes());
        image[mb + 56..mb + 64].copy_from_slice(&RELOCATED_OFFSET.to_le_bytes());
        image[mb + 64..mb + 68].copy_from_slice(&(metadata_size as u32).to_le_bytes());
        image[mb + 64 + 36..mb + 64 + 38].copy_from_slice(&0x8002u16.to_le_bytes());
        image[mb + 64 + 48..mb + 64 + 48 + entries.len()].copy_from_slice(&entries);

        let mut plain = [0u8; 512];
        for (i, b) in plain.iter_mut().enumerate() {
            *b = (i as u8) ^ 0x3c;
        }
        let ct = cbc_encrypt_sector(&fvek, RELOCATED_OFFSET, &plain);
        let ro = RELOCATED_OFFSET as usize;
        image[ro..ro + 512].copy_from_slice(&ct);

        (image, plain)
    }

    #[test]
    fn unlock_and_read_synthetic_cbc_volume() {
        // Self-consistency (Tier-3): we author both the CBC encoder and the
        // decoder here, so this proves the 0x8002 pipeline is internally
        // consistent, NOT that it matches BitLocker. The Tier-1 pybde oracle
        // (oracle_bitlocker1.rs) is the real proof.
        let (image, plain) = build_cbc_volume(PROTECTION_PASSWORD, password_hash("cbc-pw"));
        let mut vol = BitLockerVolume::unlock_with_password(Cursor::new(image), "cbc-pw").unwrap();
        let mut buf = [0u8; 512];
        vol.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, plain);
        assert_eq!(vol.metadata().encryption_method, 0x8002);
    }

    #[test]
    fn unlock_and_read_synthetic_recovery_volume() {
        // Recovery-password unlock over a synthetic 0x8002 volume: the VMK is
        // wrapped with the recovery-key hash under a recovery protector (0x0800).
        // Tier-3 self-consistency for the recovery-pw wiring; the real end-to-end
        // proof is the m8003/vault Tier-1/2 oracles.
        let rk = "111111-111111-111111-111111-111111-111111-111111-111111";
        let key_hash = crate::crypto::recovery_key_hash(rk).unwrap();
        let (image, plain) = build_cbc_volume(crate::metadata::PROTECTION_RECOVERY, key_hash);
        let mut vol =
            BitLockerVolume::unlock_with_recovery_password(Cursor::new(image), rk).unwrap();
        let mut buf = [0u8; 512];
        vol.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, plain);
        assert_eq!(vol.metadata().encryption_method, 0x8002);
    }

    #[test]
    fn recovery_unlock_rejects_malformed_password() {
        let rk = "111111-111111-111111-111111-111111-111111-111111-111111";
        let key_hash = crate::crypto::recovery_key_hash(rk).unwrap();
        let (image, _) = build_cbc_volume(crate::metadata::PROTECTION_RECOVERY, key_hash);
        let res = BitLockerVolume::unlock_with_recovery_password(Cursor::new(image), "nope");
        assert!(matches!(res, Err(BdeError::InvalidRecoveryPassword { .. })));
    }

    #[test]
    fn no_recovery_protector_errors() {
        // A password-only volume has no recovery protector to unlock with.
        let rk = "111111-111111-111111-111111-111111-111111-111111-111111";
        let (image, _) = build_cbc_volume(PROTECTION_PASSWORD, password_hash("cbc-pw"));
        let res = BitLockerVolume::unlock_with_recovery_password(Cursor::new(image), rk);
        assert!(matches!(res, Err(BdeError::NoUnlockProtector { .. })));
    }

    /// Build a synthetic method-0x8003 (AES-256-CBC, no diffuser) volume plus the
    /// plaintext of its relocated first sector. The FVEK container carries a
    /// 256-bit FVEK at offset 12 and no TWEAK.
    fn build_cbc256_volume(key_hash: [u8; 32]) -> (Vec<u8>, [u8; 512]) {
        let salt = [0x39u8; 16];
        let fvek = [0x24u8; 32];
        let vmk = [0x48u8; 32];

        let mut vmk_container = vec![0u8; 44];
        vmk_container[12..44].copy_from_slice(&vmk);
        let stretched = stretch_key(&key_hash, &salt);
        let vmk_ccm = aes_ccm_wrap(&stretched, &[0x59; 12], &vmk_container);

        // 0x8003: 32-byte FVEK at offset 12, no TWEAK.
        let mut fvek_container = vec![0u8; 76];
        fvek_container[12..44].copy_from_slice(&fvek);
        let fvek_ccm = aes_ccm_wrap(&vmk, &[0x6a; 12], &fvek_container);

        let mut stretch_data = vec![0u8; 4];
        stretch_data.extend_from_slice(&salt);
        let stretch_entry = entry(0, VALUE_TYPE_STRETCH, &stretch_data);
        let vmk_ccm_entry = entry(0, VALUE_TYPE_AES_CCM, &vmk_ccm);

        let mut vmk_data = vec![0u8; 28];
        vmk_data[26..28].copy_from_slice(&PROTECTION_RECOVERY.to_le_bytes());
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
        image[12] = 0x02;
        image[440..448].copy_from_slice(&META_BLOCK_OFFSET.to_le_bytes());

        let mb = META_BLOCK_OFFSET as usize;
        image[mb..mb + 8].copy_from_slice(b"-FVE-FS-");
        image[mb + 10..mb + 12].copy_from_slice(&2u16.to_le_bytes());
        image[mb + 16..mb + 24].copy_from_slice(&ENCRYPTED_SIZE.to_le_bytes());
        image[mb + 28..mb + 32].copy_from_slice(&1u32.to_le_bytes());
        image[mb + 32..mb + 40].copy_from_slice(&META_BLOCK_OFFSET.to_le_bytes());
        image[mb + 56..mb + 64].copy_from_slice(&RELOCATED_OFFSET.to_le_bytes());
        image[mb + 64..mb + 68].copy_from_slice(&(metadata_size as u32).to_le_bytes());
        image[mb + 64 + 36..mb + 64 + 38].copy_from_slice(&0x8003u16.to_le_bytes());
        image[mb + 64 + 48..mb + 64 + 48 + entries.len()].copy_from_slice(&entries);

        let mut plain = [0u8; 512];
        for (i, b) in plain.iter_mut().enumerate() {
            *b = (i as u8) ^ 0x71;
        }
        let ct = SectorCipher::new_cbc256(fvek).encrypt_sector(&plain, RELOCATED_OFFSET);
        let ro = RELOCATED_OFFSET as usize;
        image[ro..ro + 512].copy_from_slice(&ct);

        (image, plain)
    }

    #[test]
    fn unlock_and_read_synthetic_cbc256_volume() {
        // Tier-3 self-consistency for the 0x8003 pipeline; the Tier-2 proof is
        // oracle_m8003.rs.
        let rk = "222222-222222-222222-222222-222222-222222-222222-222222";
        let key_hash = crate::crypto::recovery_key_hash(rk).unwrap();
        let (image, plain) = build_cbc256_volume(key_hash);
        let mut vol =
            BitLockerVolume::unlock_with_recovery_password(Cursor::new(image), rk).unwrap();
        let mut buf = [0u8; 512];
        vol.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, plain);
        assert_eq!(vol.metadata().encryption_method, 0x8003);
    }

    #[test]
    fn seek_variants_and_eof() {
        use std::io::{Read as _, Seek as _};
        let (image, _) = build_volume("test-pw");
        let mut vol = BitLockerVolume::unlock_with_password(Cursor::new(image), "test-pw").unwrap();

        assert_eq!(vol.seek(SeekFrom::End(0)).unwrap(), IMAGE_SIZE as u64);
        let mut b = [0u8; 16];
        assert_eq!(vol.read(&mut b).unwrap(), 0); // read at EOF

        assert_eq!(vol.seek(SeekFrom::Start(10)).unwrap(), 10);
        assert_eq!(vol.seek(SeekFrom::Current(5)).unwrap(), 15);
        assert!(vol.seek(SeekFrom::Current(-100)).is_err()); // before start
    }

    /// A metadata-only image (no key material) with configurable cipher,
    /// protectors, header offsets, and whether the block is actually present.
    fn meta_only_image(
        method: u16,
        protectors: &[u16],
        header_offsets: [u64; 3],
        block_at: Option<usize>,
    ) -> Vec<u8> {
        let mut entries = Vec::new();
        for p in protectors {
            let mut d = vec![0u8; 28];
            d[26..28].copy_from_slice(&p.to_le_bytes());
            entries.extend(entry(0x0002, 0x0008, &d));
        }
        let metadata_size = 48 + entries.len();
        let mut image = vec![0u8; 0x2000];
        image[0..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
        image[3..11].copy_from_slice(b"MSWIN4.1");
        image[12] = 0x02;
        image[440..448].copy_from_slice(&header_offsets[0].to_le_bytes());
        image[448..456].copy_from_slice(&header_offsets[1].to_le_bytes());
        image[456..464].copy_from_slice(&header_offsets[2].to_le_bytes());
        if let Some(mb) = block_at {
            image[mb..mb + 8].copy_from_slice(b"-FVE-FS-");
            image[mb + 10..mb + 12].copy_from_slice(&2u16.to_le_bytes());
            image[mb + 32..mb + 40].copy_from_slice(&(mb as u64).to_le_bytes());
            image[mb + 64..mb + 68].copy_from_slice(&(metadata_size as u32).to_le_bytes());
            image[mb + 64 + 36..mb + 64 + 38].copy_from_slice(&method.to_le_bytes());
            image[mb + 64 + 48..mb + 64 + 48 + entries.len()].copy_from_slice(&entries);
        }
        image
    }

    #[test]
    fn recognized_but_unvalidated_methods_refuse() {
        // 0x8001 CBC-256+diffuser, 0x8004 XTS-128, 0x8005 XTS-256 are recognized
        // by the dispatch but have no Tier-1/2 oracle yet — they must refuse
        // (naming the method), never by-construction decrypt. The refusal is
        // gated before key derivation. (0x8003 is now oracle-validated.)
        for m in [0x8001u16, 0x8004, 0x8005] {
            let img = meta_only_image(m, &[0x2000], [0x1000, 0, 0], Some(0x1000));
            let res = BitLockerVolume::unlock_with_password(Cursor::new(img), "x");
            assert!(
                matches!(res, Err(BdeError::UnvalidatedEncryptionMethod { method }) if method == m),
                "method {m:#06x} must be recognized-but-unvalidated"
            );
        }
    }

    #[test]
    fn unrecognized_method_errors() {
        // Not a 0x800x BDE cipher at all — a distinct "unsupported" error.
        let img = meta_only_image(0x1234, &[0x2000], [0x1000, 0, 0], Some(0x1000));
        let res = BitLockerVolume::unlock_with_password(Cursor::new(img), "x");
        assert!(matches!(
            res,
            Err(BdeError::UnsupportedEncryptionMethod { method: 0x1234 })
        ));
    }

    #[test]
    fn no_password_protector_errors() {
        // Recovery-only volume — no password protector to unlock with.
        let img = meta_only_image(0x8000, &[0x0800], [0x1000, 0, 0], Some(0x1000));
        let res = BitLockerVolume::unlock_with_password(Cursor::new(img), "x");
        assert!(matches!(
            res,
            Err(BdeError::NoUnlockProtector { protector, .. }) if protector == "password"
        ));
    }

    #[test]
    fn no_valid_metadata_errors() {
        // Valid BitLocker header, but the block offsets point to non-FVE bytes.
        let img = meta_only_image(0x8000, &[0x2000], [0x1000, 0x1200, 0x1400], None);
        let err = BitLockerVolume::read_metadata(&mut Cursor::new(img)).unwrap_err();
        assert!(matches!(err, BdeError::NoValidMetadata { .. }));
    }

    #[test]
    fn read_metadata_skips_zero_first_offset() {
        // First offset zero (skipped), second valid — covers the `continue`.
        let img = meta_only_image(0x8000, &[0x2000], [0, 0x1000, 0], Some(0x1000));
        let meta = BitLockerVolume::read_metadata(&mut Cursor::new(img)).unwrap();
        assert_eq!(meta.encryption_method, 0x8000);
    }

    /// A reader that returns a valid header once, then a transient `Interrupted`,
    /// then a hard error — to exercise the I/O-error arms of `read_available`.
    struct FlakyReader {
        header: Vec<u8>,
        phase: usize,
    }

    impl Read for FlakyReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.phase += 1;
            match self.phase {
                1 => {
                    let n = buf.len().min(self.header.len());
                    buf[..n].copy_from_slice(&self.header[..n]);
                    Ok(n)
                }
                2 => Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "eintr",
                )),
                _ => Err(std::io::Error::other("boom")),
            }
        }
    }

    impl Seek for FlakyReader {
        fn seek(&mut self, _pos: SeekFrom) -> std::io::Result<u64> {
            Ok(0)
        }
    }

    #[test]
    fn io_error_during_block_read_propagates() {
        let mut header = vec![0u8; 512];
        header[0..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
        header[3..11].copy_from_slice(b"MSWIN4.1");
        header[12] = 0x02;
        header[440..448].copy_from_slice(&0x1000u64.to_le_bytes());
        let mut reader = FlakyReader { header, phase: 0 };
        let res = BitLockerVolume::read_metadata(&mut reader);
        assert!(matches!(res, Err(BdeError::Io(_))));
    }

    #[test]
    fn wrong_password_fails_authentication() {
        let (image, _) = build_volume("test-pw");
        let res = BitLockerVolume::unlock_with_password(Cursor::new(image), "wrong");
        assert!(matches!(
            res,
            Err(BdeError::AuthenticationFailed { what }) if what == "volume master key"
        ));
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
