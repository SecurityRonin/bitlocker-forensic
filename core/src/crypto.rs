//! BitLocker cryptography: password-key derivation, AES-CCM key unwrap, the
//! Elephant Diffuser, and AES-CBC sector decryption.
//!
//! Every primitive comes from an audited RustCrypto crate — `aes`, `cbc`, `ccm`,
//! `sha2`. The one exception is the **Elephant Diffuser**, for which no crate
//! exists: it is implemented to the `dislocker`/`libbde` reference and validated
//! **only** against the Tier-1 `pybde` oracle (a self-authored round-trip proves
//! nothing — see `docs/validation.md`).

use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockDecryptMut, BlockEncrypt, KeyInit, KeyIvInit};
use aes::Aes128;
use ccm::aead::generic_array::GenericArray;
use ccm::aead::AeadInPlace;
use ccm::consts::{U12, U16};
use ccm::{Ccm, KeyInit as CcmKeyInit};
use sha2::{Digest, Sha256};

/// Number of key-stretch iterations (`0x100000`), per the BDE format.
const STRETCH_ITERATIONS: u64 = 0x0010_0000;

/// AES-256 CCM with a 16-byte tag and a 12-byte nonce — the mode BitLocker uses
/// to wrap the VMK and FVEK (both are 256-bit keys). Type params are the tag
/// size (`U16`) then the nonce size (`U12`).
type BdeCcm = Ccm<aes::Aes256, U16, U12>;

/// Compute the BitLocker password hash: `SHA-256(SHA-256(UTF-16LE(password)))`,
/// with no byte-order mark and no NUL terminator.
#[must_use]
pub fn password_hash(password: &str) -> [u8; 32] {
    let utf16: Vec<u8> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let first = Sha256::digest(&utf16);
    let second = Sha256::digest(first);
    second.into()
}

/// Run the BDE key-stretch loop `iterations` times and return the final 32-byte
/// key. The hashed structure is `last[32] | initial[32] | salt[16] | count(u64
/// LE)`; each round hashes it into `last` and increments `count`.
#[must_use]
pub fn stretch_key_n(password_hash: &[u8; 32], salt: &[u8; 16], iterations: u64) -> [u8; 32] {
    let mut buf = [0u8; 88];
    // buf[0..32] = last (starts zero); buf[32..64] = initial; buf[64..80] = salt.
    buf[32..64].copy_from_slice(password_hash);
    buf[64..80].copy_from_slice(salt);
    for count in 0..iterations {
        buf[80..88].copy_from_slice(&count.to_le_bytes());
        let digest = Sha256::digest(buf);
        buf[0..32].copy_from_slice(&digest);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&buf[0..32]);
    out
}

/// The full BitLocker password stretch (`0x100000` iterations).
#[must_use]
pub fn stretch_key(password_hash: &[u8; 32], salt: &[u8; 16]) -> [u8; 32] {
    stretch_key_n(password_hash, salt, STRETCH_ITERATIONS)
}

/// AES-CCM-unwrap a key. `value_data` is an AES-CCM-encrypted-key entry value:
/// `nonce(12) | MAC(16) | ciphertext`. `key` is the 256-bit unwrapping key
/// (stretched key for the VMK, VMK for the FVEK). Returns the plaintext container
/// on success, or `None` when the authentication tag does not verify (wrong key).
#[must_use]
pub fn aes_ccm_unwrap(key: &[u8; 32], value_data: &[u8]) -> Option<Vec<u8>> {
    let nonce = value_data.get(0..12)?;
    let tag = value_data.get(12..28)?;
    let mut buffer = value_data.get(28..)?.to_vec();
    let cipher = <BdeCcm as CcmKeyInit>::new(GenericArray::from_slice(key));
    cipher
        .decrypt_in_place_detached(
            GenericArray::from_slice(nonce),
            &[],
            &mut buffer,
            GenericArray::from_slice(tag),
        )
        .ok()?;
    Some(buffer)
}

/// Wrap `plaintext` into the BitLocker on-disk AES-CCM key layout
/// (`nonce(12) | MAC(16) | ciphertext`) — the inverse of [`aes_ccm_unwrap`], used
/// only to build synthetic volumes in tests.
#[cfg(test)]
#[must_use]
pub fn aes_ccm_wrap(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    let cipher = <BdeCcm as CcmKeyInit>::new(GenericArray::from_slice(key));
    let mut buffer = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(GenericArray::from_slice(nonce), &[], &mut buffer)
        .unwrap();
    let mut out = Vec::with_capacity(12 + 16 + buffer.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&buffer);
    out
}

/// A word-count helper for the diffuser (bytes → 32-bit words).
fn to_words(sector: &[u8]) -> Vec<u32> {
    sector
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

fn from_words(words: &[u32], out: &mut [u8]) {
    for (i, w) in words.iter().enumerate() {
        if let Some(slot) = out.get_mut(i * 4..i * 4 + 4) {
            slot.copy_from_slice(&w.to_le_bytes());
        }
    }
}

const RA: [u32; 4] = [9, 0, 13, 0];
const RB: [u32; 4] = [0, 10, 0, 25];

/// Elephant Diffuser A (decryption direction): `d[i] += d[i-2] ^ ROL(d[i-5],
/// Ra[i%4])`, 5 cycles, indices ascending, mod word count.
pub fn diffuser_a_decrypt(sector: &mut [u8]) {
    let mut d = to_words(sector);
    let n = d.len();
    if n == 0 {
        return;
    }
    for _ in 0..5 {
        for i in 0..n {
            let a = d[(i + n - 2) % n];
            let b = d[(i + n - 5) % n].rotate_left(RA[i % 4]);
            d[i] = d[i].wrapping_add(a ^ b);
        }
    }
    from_words(&d, sector);
}

/// Elephant Diffuser B (decryption direction): `d[i] += d[i+2] ^ ROL(d[i+5],
/// Rb[i%4])`, 3 cycles, indices ascending, mod word count.
pub fn diffuser_b_decrypt(sector: &mut [u8]) {
    let mut d = to_words(sector);
    let n = d.len();
    if n == 0 {
        return;
    }
    for _ in 0..3 {
        for i in 0..n {
            let a = d[(i + 2) % n];
            let b = d[(i + 5) % n].rotate_left(RB[i % 4]);
            d[i] = d[i].wrapping_add(a ^ b);
        }
    }
    from_words(&d, sector);
}

/// Elephant Diffuser A (encryption direction) — inverse of [`diffuser_a_decrypt`],
/// used only by the round-trip self-consistency test.
#[cfg(test)]
pub fn diffuser_a_encrypt(sector: &mut [u8]) {
    let mut d = to_words(sector);
    let n = d.len();
    if n == 0 {
        return;
    }
    for _ in 0..5 {
        for i in (0..n).rev() {
            let a = d[(i + n - 2) % n];
            let b = d[(i + n - 5) % n].rotate_left(RA[i % 4]);
            d[i] = d[i].wrapping_sub(a ^ b);
        }
    }
    from_words(&d, sector);
}

/// Elephant Diffuser B (encryption direction) — inverse of [`diffuser_b_decrypt`].
#[cfg(test)]
pub fn diffuser_b_encrypt(sector: &mut [u8]) {
    let mut d = to_words(sector);
    let n = d.len();
    if n == 0 {
        return;
    }
    for _ in 0..3 {
        for i in (0..n).rev() {
            let a = d[(i + 2) % n];
            let b = d[(i + 5) % n].rotate_left(RB[i % 4]);
            d[i] = d[i].wrapping_sub(a ^ b);
        }
    }
    from_words(&d, sector);
}

/// The volume sector cipher for method 0x8000 (AES-128-CBC + Elephant Diffuser).
/// Holds the 16-byte FVEK and TWEAK keys derived from the FVEK entry.
pub struct SectorCipher {
    fvek: [u8; 16],
    tweak: Aes128,
    fvek_ecb: Aes128,
}

impl SectorCipher {
    /// Build the sector cipher from the 16-byte FVEK and TWEAK keys.
    #[must_use]
    pub fn new(fvek: [u8; 16], tweak: [u8; 16]) -> SectorCipher {
        SectorCipher {
            fvek,
            tweak: Aes128::new(GenericArray::from_slice(&tweak)),
            fvek_ecb: Aes128::new(GenericArray::from_slice(&fvek)),
        }
    }

    fn ecb(cipher: &Aes128, input: &[u8; 16]) -> [u8; 16] {
        let mut block = GenericArray::clone_from_slice(input);
        cipher.encrypt_block(&mut block);
        block.into()
    }

    /// The 32-byte per-sector key: `ECB(TWEAK, LE128(off))` ‖
    /// `ECB(TWEAK, LE128(off) with byte[15]=0x80)`.
    fn sector_key(&self, byte_offset: u64) -> [u8; 32] {
        let mut iv = [0u8; 16];
        iv[0..8].copy_from_slice(&byte_offset.to_le_bytes());
        let lower = Self::ecb(&self.tweak, &iv);
        iv[15] = 0x80;
        let upper = Self::ecb(&self.tweak, &iv);
        let mut key = [0u8; 32];
        key[0..16].copy_from_slice(&lower);
        key[16..32].copy_from_slice(&upper);
        key
    }

    fn cbc_iv(&self, byte_offset: u64) -> [u8; 16] {
        let mut iv = [0u8; 16];
        iv[0..8].copy_from_slice(&byte_offset.to_le_bytes());
        Self::ecb(&self.fvek_ecb, &iv)
    }

    /// Decrypt one sector of `cipher` at volume byte offset `byte_offset`.
    /// The sector length must be a non-zero multiple of 16.
    #[must_use]
    pub fn decrypt_sector(&self, cipher: &[u8], byte_offset: u64) -> Vec<u8> {
        let sector_key = self.sector_key(byte_offset);
        let iv = self.cbc_iv(byte_offset);
        let mut buf = cipher.to_vec();

        // AES-CBC decrypt with the FVEK (no padding: sector is a 16-byte multiple).
        let dec = cbc::Decryptor::<Aes128>::new(
            GenericArray::from_slice(&self.fvek),
            GenericArray::from_slice(&iv),
        );
        let len = buf.len() - (buf.len() % 16);
        if let Ok(plain) = dec.decrypt_padded_mut::<NoPadding>(&mut buf[..len]) {
            let plain_len = plain.len();
            // Diffuser B then A, then XOR the sector key.
            diffuser_b_decrypt(&mut buf[..plain_len]);
            diffuser_a_decrypt(&mut buf[..plain_len]);
            for (i, b) in buf[..plain_len].iter_mut().enumerate() {
                *b ^= sector_key[i % 32];
            }
        }
        buf
    }

    /// Encrypt one sector — the inverse of [`Self::decrypt_sector`], used only by
    /// the round-trip self-consistency test.
    #[cfg(test)]
    #[must_use]
    pub fn encrypt_sector(&self, plain: &[u8], byte_offset: u64) -> Vec<u8> {
        use aes::cipher::BlockEncryptMut;
        let sector_key = self.sector_key(byte_offset);
        let iv = self.cbc_iv(byte_offset);
        let mut buf = plain.to_vec();
        for (i, b) in buf.iter_mut().enumerate() {
            *b ^= sector_key[i % 32];
        }
        diffuser_a_encrypt(&mut buf);
        diffuser_b_encrypt(&mut buf);
        let enc = cbc::Encryptor::<Aes128>::new(
            GenericArray::from_slice(&self.fvek),
            GenericArray::from_slice(&iv),
        );
        let len = buf.len() - (buf.len() % 16);
        let out = enc
            .encrypt_padded_mut::<NoPadding>(&mut buf[..len], len)
            .unwrap()
            .to_vec();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn password_hash_matches_independent_python() {
        // hashlib.sha256(hashlib.sha256("bde-TEST".encode("utf-16-le")).digest())
        assert_eq!(
            hex(&password_hash("bde-TEST")),
            "f5acb5bd3c4e31c5c988128fcfc50717da18ca4f7dbaa8bf21e7525bd431ee3f"
        );
    }

    #[test]
    fn stretch_two_iterations_matches_independent_python() {
        let salt: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let ph = password_hash("bde-TEST");
        assert_eq!(
            hex(&stretch_key_n(&ph, &salt, 2)),
            "0660651b876f7d3777e292fb96671e57d48a4b34d7e17c3e01f20d6ba6af42e4"
        );
    }

    fn sample_sector() -> Vec<u8> {
        (0..512u32)
            .map(|i| (i.wrapping_mul(31) ^ 0xA5) as u8)
            .collect()
    }

    #[test]
    fn diffuser_a_roundtrip() {
        let orig = sample_sector();
        let mut buf = orig.clone();
        diffuser_a_encrypt(&mut buf);
        assert_ne!(buf, orig);
        diffuser_a_decrypt(&mut buf);
        assert_eq!(buf, orig);
    }

    #[test]
    fn diffuser_b_roundtrip() {
        let orig = sample_sector();
        let mut buf = orig.clone();
        diffuser_b_encrypt(&mut buf);
        assert_ne!(buf, orig);
        diffuser_b_decrypt(&mut buf);
        assert_eq!(buf, orig);
    }

    #[test]
    fn diffuser_empty_and_short_no_panic() {
        let mut empty: [u8; 0] = [];
        diffuser_a_decrypt(&mut empty);
        diffuser_b_decrypt(&mut empty);
        let mut three = [1u8, 2, 3];
        diffuser_a_decrypt(&mut three); // < 1 word after chunks_exact -> no-op
    }

    #[test]
    fn ccm_unwrap_roundtrip_ms_layout() {
        // Encrypt with the ccm crate, assemble BitLocker's nonce|MAC|ciphertext,
        // and confirm aes_ccm_unwrap recovers it (wiring self-consistency; the
        // MS-compat proof is the Tier-1 oracle).
        let key = [7u8; 32];
        let nonce = [3u8; 12];
        let plaintext = b"volume master key container payload!!".to_vec();
        let cipher = <BdeCcm as CcmKeyInit>::new(GenericArray::from_slice(&key));
        let mut buf = plaintext.clone();
        let tag = cipher
            .encrypt_in_place_detached(GenericArray::from_slice(&nonce), &[], &mut buf)
            .unwrap();
        let mut value_data = Vec::new();
        value_data.extend_from_slice(&nonce);
        value_data.extend_from_slice(&tag); // MAC first, then ciphertext
        value_data.extend_from_slice(&buf);

        assert_eq!(aes_ccm_unwrap(&key, &value_data).unwrap(), plaintext);
        // Wrong key -> authentication fails -> None.
        assert!(aes_ccm_unwrap(&[8u8; 32], &value_data).is_none());
        // Truncated value -> None, no panic.
        assert!(aes_ccm_unwrap(&key, &value_data[..20]).is_none());
    }

    #[test]
    fn sector_cipher_roundtrip() {
        let cipher = SectorCipher::new([0x11; 16], [0x22; 16]);
        let plain = sample_sector();
        let off = 0x2110_800u64;
        let ct = cipher.encrypt_sector(&plain, off);
        assert_ne!(ct, plain);
        assert_eq!(cipher.decrypt_sector(&ct, off), plain);
    }
}
