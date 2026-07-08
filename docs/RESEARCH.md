# BitLocker (BDE) format research

This is the working reference the implementation is built to. It records the
authoritative sources, the on-disk layout, and the exact decryption pipeline —
so the code can be checked against the spec line by line, and so the next reader
does not have to re-derive BitLocker's layout from memory.

## Authoritative sources

| Source | Used for |
|---|---|
| **libbde** — *BitLocker Drive Encryption (BDE) format specification*, J. Metz ([libyal/libbde](https://github.com/libyal/libbde/blob/main/documentation/BitLocker%20Drive%20Encryption%20(BDE)%20format.asciidoc)) | Volume header, FVE metadata block/header/entries, key protectors, key derivation |
| **libbde source** (`libbde_password.c`, `libbde_metadata.c`, `libbde_encryption_context.c`, `libbde_sector_data.c`) | Exact password-key iteration count, FVEK/TWEAK split by method, volume-header relocation, sector-address for the IV |
| **dislocker** — `src/encryption/diffuser.c`, `decrypt.c` ([Aorimn/dislocker](https://github.com/Aorimn/dislocker)) | Elephant Diffuser A/B, sector-key derivation, AES-CCM (CTR + CBC-MAC) reference |
| **[FERGUSON06]** — N. Ferguson, *AES-CBC + Elephant diffuser: A Disk Encryption Algorithm for Windows Vista* | Diffuser design rationale |

## Volume header (first 512 bytes)

Three variants, distinguished by the signature at offset 3 and the boot entry at
offset 0. The FVE metadata is located by three 64-bit byte offsets:

| Variant | Sig @3 | FVE block offsets | BitLocker GUID |
|---|---|---|---|
| Windows Vista | `-FVE-FS-` (boot `EB 52 90`) | block 1 = cluster@56 × cluster-size; blocks 2/3 from block header | — |
| Windows 7 / 10 | `-FVE-FS-` (boot `EB 58 90`) | u64 @ 176 / 184 / 192 | @160 |
| BitLocker To Go (FAT) | `MSWIN4.1` | u64 @ 440 / 448 / 456 | @424 |

The three offsets are re-read (authoritatively) from the FVE metadata **block
header** once located, and the first block's `-FVE-FS-` signature confirms it.

## FVE metadata block (at each of the 3 offsets)

```
block header (64 bytes)   "-FVE-FS-" sig; version (v2 for Win7/To Go);
                          encrypted_volume_size @16; number_of_volume_header_sectors @28;
                          block offsets @32/40/48; volume_header_offset @56
metadata header (48 bytes) metadata_size @0; volume GUID @16; encryption method @36;
                          creation FILETIME @40
metadata entries          array, until metadata_size consumed
```

### Metadata entry (recursive)

```
0  u16 entry size (incl. this field)     2  u16 entry type     4  u16 value type
6  u16 version                            8  … value data
```

Entry types: `0x0000` property · `0x0002` VMK · `0x0003` FVEK · `0x000f` volume
header block. Value types: `0x0001` key · `0x0002` UTF-16 string · `0x0003`
stretch key · `0x0005` AES-CCM encrypted key · `0x0008` VMK · `0x000f`
offset+size.

### Key-protection types (VMK header @26, u16)

`0x0000` clear key · `0x0100` TPM · `0x0200` startup key · `0x0500` TPM+PIN ·
`0x0800` recovery password · `0x2000` password.

### Encryption methods (metadata header @36, u16)

`0x8000` AES-128-CBC + Elephant Diffuser **(this build)** · `0x8001` AES-256-CBC +
diffuser · `0x8002/0x8003` AES-CBC 128/256 (no diffuser) · `0x8004/0x8005`
AES-XTS 128/256 · `0x2000…` AES-CCM (key data).

## Password → VMK → FVEK

1. **Password hash** — `SHA-256(SHA-256(UTF-16LE(password)))` (no BOM, no NUL).
2. **Stretch** — build `struct { last[32], initial[32], salt[16], count u64 }`
   (88 bytes), `last`/`count` = 0, `initial` = the password hash, `salt` from the
   VMK's **stretch key** entry (0x0003). Loop **0x100000** times: `last =
   SHA-256(struct); count += 1`. The final `last` is the 32-byte stretched key.
   (`libbde` runs the loop `0xFFFFF` times then one final hash — 0x100000 total.)
3. **VMK** — AES-CCM-decrypt the VMK's **AES-CCM key** entry (0x0005, a sibling of
   the stretch key in the VMK properties) with the stretched key. Nonce = the
   entry's first 12 bytes (FILETIME + counter); the 16-byte MAC precedes the
   ciphertext (= the CCM tag). Plaintext container: `size@0, version@4, method@8,
   key@12` → **VMK = container[12..44]** (32 bytes).
4. **FVEK/TWEAK** — AES-CCM-decrypt the top-level FVEK entry (type 0x0003, value
   0x0005) with the VMK. For method 0x8000 the container `data_size` is `0x4c` and
   **FVEK = container[12..44]**, **TWEAK = container[44..76]**; only the first 16
   bytes of each are used (AES-128).

AES-CCM here is standard NIST SP 800-38C (nonce 12, tag 16, no AAD, L=3), so the
on-disk `MAC‖ciphertext` maps directly to a detached-tag CCM decrypt.

## Sector decryption — AES-CBC + Elephant Diffuser (method 0x8000)

Each 512-byte sector at byte offset `O` (relative to the volume start):

```
sector_key[0..16] = AES-ECB-ENC(TWEAK, LE128(O))
sector_key[16..32]= AES-ECB-ENC(TWEAK, LE128(O) with byte[15]=0x80)
iv                = AES-ECB-ENC(FVEK, LE128(O))
plain             = AES-CBC-DEC(FVEK, iv, cipher)
plain             = DiffuserB_decrypt(plain)     # forward, 3 cycles, Rb={0,10,0,25}
plain             = DiffuserA_decrypt(plain)     # forward, 5 cycles, Ra={9,0,13,0}
plain[i]         ^= sector_key[i % 32]
```

`LE128(O)` is the 8-byte little-endian byte offset in the low 8 bytes, zero-padded
to 16. Diffuser words are 32-bit; `A: d[i] += d[i-2] ^ ROL(d[i-5], Ra[i%4])`,
`B: d[i] += d[i+2] ^ ROL(d[i+5], Rb[i%4])` (indices mod word-count, decrypt runs
`i` ascending).

## Volume-header relocation (the read-path subtlety)

The original volume's first `volume_header_size` bytes are stored **encrypted at
`volume_header_offset`** (the FVE volume-header block, value 0x000f: `block_offset`
@0, `block_size` @8; equivalently `number_of_volume_header_sectors × 512`). To
read decrypted logical offset `o` when `o < volume_header_size`, read ciphertext
from `volume_header_offset + o` **and decrypt with the sector byte-address =
`volume_header_offset + o`** (the physical location, per `libbde_sector_data.c`).
Metadata-block regions read back as zeros. In `bdetogo.raw`, `volume_header_size`
is `0x515a00` (5 331 456 B), so every oracle test offset falls inside this
relocated region.

## Out of scope in this build (structured for easy addition)

AES-XTS methods (no Tier-1 oracle yet), recovery-password unlock (same stretch,
but the 48-digit value isn't published so it can't be Tier-1 validated here),
AES-256 CBC/diffuser, and TPM / startup-key / clear-key *unlock*. The metadata
parser still **reports** every protector and cipher it sees.
