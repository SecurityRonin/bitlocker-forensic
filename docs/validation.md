# Validation

Correctness is proven against an **independent third-party oracle on real-world
data** — never against fixtures we authored (which would only prove
self-consistency, the LZNT1 trap). The Elephant Diffuser in particular produces a
value that an independent oracle can check, so a Tier-1 oracle is mandatory for
it, and we have one.

## Tier-1 — dfvfs `bdetogo.raw` vs `pybde`

- **Artifact**: `bdetogo.raw`, from the [log2timeline/dfvfs](https://github.com/log2timeline/dfvfs/blob/main/test_data/bdetogo.raw)
  test corpus (Apache-2.0). 64 MiB, md5 `fcba22f9363388101ae66c741588bc45`.
  BitLocker To Go on FAT, whole-file volume, method `0x8000`.
- **Published key**: password `bde-TEST` (protector type `0x2000`).
- **Answer key**: `pybde` (libbde 20240502) decrypting the same image with the
  same password. `bitlocker-core` must reproduce each decrypted 512-byte sector
  **byte-for-byte** (SHA-256 match).

The env-gated test `core/tests/oracle_bdetogo.rs` (`BDE_ORACLE_IMAGE`) unlocks the
image and asserts these SHA-256 digests:

| Logical offset | Region | SHA-256 |
|---|---|---|
| 0 | FAT boot sector | `139b857c…28f3` |
| 512 | zero-plaintext (non-zero ciphertext ⇒ proves correct inversion) | `076a27c7…6560` |
| 2048 | FAT table | `bf762af7…bd71` |
| 35840 | root directory | `48ddda42…5a7b` |
| 0x8000 (4096-byte read) | data | `1d138f11…fe4d` |

Run:

```bash
BDE_ORACLE_IMAGE=/path/to/bdetogo.raw \
  cargo test -p bitlocker-core --test oracle_bdetogo -- --nocapture
```

The image is **not** committed (64 MiB); the test skips cleanly when the env var
is unset. Provenance is recorded in `tests/data/README.md`.

## Tier-1 — picoCTF `bitlocker-1.dd` vs `pybde` (method `0x8002`)

- **Artifact**: `bitlocker-1.dd`, from picoCTF 2025 (challenge *Bitlocker-1*).
  100 MiB, md5 `22c3492cbc26ff648df066e1ed5329a7`. Bare BitLocker volume at
  offset 0, method `0x8002` (AES-128-CBC, no Elephant Diffuser).
- **Published key**: password `jacqueline` (protector type `0x2000`).
- **Answer key**: `pybde` decrypting the same image with the same password.
  `bitlocker-core` reproduces each decrypted 512-byte sector **byte-for-byte**.

The env-gated test `core/tests/oracle_bitlocker1.rs` (`BDE_CBC2_ORACLE`) unlocks
the image and asserts these SHA-256 digests:

| Logical offset | SHA-256 |
|---|---|
| 0 (NTFS boot sector) | `f2468bab…a65e` |
| 512 | `ef6d6118…b546` |
| 1024 | `e8459413…edad` |
| 1536 | `f49bb7df…a14fe` |
| 2048 | `7289d589…7ee3` |

```bash
BDE_CBC2_ORACLE=/path/to/bitlocker-1.dd \
  cargo test -p bitlocker-core --test oracle_bitlocker1 -- --nocapture
```

The image is **not** committed (100 MiB); the test skips cleanly when the env var
is unset. Provenance is recorded in `tests/data/README.md`.

## Tier-1 — BelkaCTF6 `vault.raw` vs `pybde` (method `0x8004`, XTS-AES-128)

- **Artifact**: `vault.raw`, the BitLocker volume from BelkaCTF #6 "Bogus Bill"
  (2024, Belkasoft). BitLocker volume at byte offset 16777216; method `0x8004`
  (XTS-AES-128). Belkasoft CTF material — **not redistributable**, not committed.
- **Published key**: recovery password
  `590238-514580-359986-088242-029766-319495-410509-636911` (protector `0x0800`),
  published in the official write-up.
- **Answer key**: `pybde`. The env-gated test `core/tests/oracle_vault.rs`
  (`BDE_XTS_ORACLE`) reproduces each decrypted sector byte-for-byte. Sectors 0–5
  (the relocated boot region) confirm the header-region XTS tweak uses the
  **physical** offset (`byte_offset / 512`), exactly as CBC's IV does; deep
  sectors 32768 / 262144 (16 / 128 MiB) confirm the tweak is the sector number.

## Tier-2 — self-minted `m8003` / `m8004` / `m8005` vs `pybde`

Three BitLocker volumes minted on a Windows 11 guest (`manage-bde`,
recovery-password protector only), one per remaining cipher, decrypted
independently by `pybde` on the host. We authored the images, so this is Tier-2
(the answer key is an independent oracle; the scenario is ours). Env-gated on
`BDE_MINT_ORACLE_DIR`; partition at byte 65536.

| Image | Method | Test | LBA 0 SHA-256 |
|---|---|---|---|
| `m8003` | `0x8003` AES-256-CBC | `oracle_m8003.rs` | `7ba645fe…f09a98` |
| `m8004` | `0x8004` XTS-AES-128 | `oracle_m8004.rs` | `bb5795df…13b2` |
| `m8005` | `0x8005` XTS-AES-256 | `oracle_m8005.rs` | `4d42f174…a413` |

Each asserts LBA 0/1/2/16/100/200 against `pybde`. Because every oracle here
unlocks via the **recovery password**, a passing `m8003` (etc.) is also the
end-to-end proof of the recovery-key derivation: a wrong `recovery_key_hash`
fails the AES-CCM VMK unwrap and never reaches a matching plaintext.

## Tier-2 — independent hash vectors

The password-hash step is checked against values computed independently by
Python `hashlib` (`SHA-256(SHA-256(UTF-16LE("bde-TEST")))` =
`f5acb5bd…ee3f`) and a two-iteration stretch vector. The **recovery-key** hash is
likewise checked against independent Python vectors (e.g. the all-`1`s recovery
password → `17f2c896…648e`) — real hash output whose ground truth is derivable,
not authored alongside the code.

## Tier-3 — structural unit tests

FVE metadata-entry parsing, volume-header variant detection, and every sector
transform's encrypt/decrypt round-trip (CBC-128 ± diffuser, CBC-256, XTS-128,
XTS-256) plus a synthetic recovery-password volume are exercised over hand-built
byte buffers. These are regression scaffolding under the Tier-1/2 oracles — a
round-trip proves self-consistency only; the real correctness proof for each
cipher and the full pipeline is the oracle.

## Fuzzing

`core/fuzz/fuzz_targets/fuzz_metadata.rs` drives the FVE-metadata parser over
arbitrary bytes; invariant: never panic.
