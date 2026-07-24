# 6. On-disk format: three volume-header variants, FVE offsets, little-endian

Date: 2026-07-24
Status: Accepted

## Context

BitLocker has three distinct on-disk volume-header layouts, produced by different
Windows generations: Windows Vista, Windows 7 and later, and BitLocker To Go on a
FAT-formatted removable volume. They differ in where the signature, the
BitLocker identifier GUID, and the three FVE metadata block offsets live. A
reader must recognise which layout it is looking at from the first 512-byte
sector alone, and must decode multi-byte fields with the format's byte order.

The risk is treating each real image as a special case. The authoritative
references are libbde and dfvfs (documented in `docs/RESEARCH.md`); the three
layouts are a genuine, documented discontinuity of the *format*, not a per-image
hack.

## Decision

Parse the 512-byte header into a `BdeVariant` (`core/src/header.rs`) by the
documented rule for each layout, not per image:

- signature `MSWIN4.1` at offset 3 ⇒ `BitLockerToGo`; GUID at offset 424, the
  three FVE offsets at 440/448/456;
- signature `-FVE-FS-` with boot bytes `EB 58 90` at offset 0 ⇒
  `Windows7OrLater` (GUID at offset 160);
- `-FVE-FS-` otherwise ⇒ `WindowsVista`.

All multi-byte fields are little-endian, read through the bounds-checked helpers
in `core/src/bytes.rs` (`le_u16`, `le_u64`, `read_guid`). The encryption method
lives at FVE metadata header offset 36 (`core/src/method.rs` module doc). When
neither signature is present, `VolumeHeader::parse` returns
`BdeError::NotBitLocker` carrying the offending signature bytes. The header
comment states the principle explicitly: "This is not a special-case per image —
it is the documented rule for each variant of the format."

The three-layout parser and the FVE block/header/entry parser were built as
separate, tested units (`06ab042`/`aaa3135` volume-header for all three layouts;
`3e160eb`/`4f2e7cc` FVE metadata parser).

## Consequences

- A new image of any of the three generations parses by construction; an
  unrecognised image fails loud with its signature bytes rather than
  mis-detecting.
- Offsets and endianness are grounded in libbde/dfvfs and captured in
  `docs/RESEARCH.md`, so the constants are traceable to the spec, not to a sample.
- `bytes_per_sector` defaults to 512 when the BPB field is zero — a documented
  format quirk, handled once in the parser.
