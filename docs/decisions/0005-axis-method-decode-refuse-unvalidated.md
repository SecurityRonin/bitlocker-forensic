# 5. Decode ciphers by axis; refuse any cipher without an oracle

Date: 2026-07-24
Status: Accepted

## Context

BitLocker defines six ciphers as a discrete numeric domain, `0x8000`–`0x8005`
(libbde `libbde_definitions.h` / dfvfs). Two failure modes threaten a decryptor
here. First, a `match raw { 0x8000 => …, 0x8002 => … }` table per method is the
"special case" smell the global discipline forbids — it hides the algorithm
behind literals and breaks the moment an untested sibling appears. Second, and
worse for a forensic tool: emitting bytes for a cipher the code has never
validated against an independent oracle is placeholder-crypto by another name —
it *fabricates evidence*, the textbook fail-loud violation.

At this build, only some of the six ciphers have a validated oracle
(`0x8000`/`0x8002`/`0x8004` Tier-1; `0x8003`/`0x8005` cross-checked Tier-2). The
remaining method — AES-256-CBC + Elephant Diffuser (`0x8001`) — has none.

## Decision

Decode the raw 16-bit method into its three orthogonal axes — key size, cipher
mode, diffuser — and branch the unlock dispatch on the *axes*, never on
per-method literals. `EncryptionMethod::decode` (`core/src/method.rs`) derives
`key_bits` from bit 0 and `(mode, diffuser)` from the pair index, returning `None`
for anything outside `0x8000..=0x8005`. This is the documented structure of the
domain, so a new cipher drops in as one arm plus a builder and an oracle test.

Separately, `EncryptionMethod::validated_kind` returns a `SectorCipherKind`
*only* for a cipher this build has actually validated against an oracle, and
`None` otherwise. The volume dispatch (`core/src/volume.rs`) gates on it:
unrecognized ⇒ `BdeError::UnsupportedEncryptionMethod { method }`; recognized but
no oracle ⇒ `BdeError::UnvalidatedEncryptionMethod { method }` — a named refusal,
never a by-construction decrypt (test `recognized_but_unvalidated_method_refuses`
asserts `0x8001` refuses). Both errors carry the offending method value.

The axis/refusal design was introduced together in `11e88b9`/`6e13c8b`
("generic six-method dispatch, gate unvalidated ciphers"); subsequent commits
(`d253973` AES-256-CBC, `af7642f` XTS-128, `e36db19` XTS-256) each moved a cipher
from refused to validated by adding an oracle, exactly as the design intended.

## Consequences

- Adding cipher support is a one-arm, one-oracle-test change; the refusal path
  guarantees the tool never emits unverified plaintext.
- `0x8001` lights up as a one-line change plus a test the moment it gets an
  oracle — visible in the code as the single `validated_kind` gap.
- The analyzer (`bitlocker-forensic`) still *reports* every cipher and protector
  it finds even when the reader refuses to decrypt — observation is not gated on
  decryptability.
