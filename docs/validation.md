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

## Tier-2 — independent hash vectors

The password-hash step is checked against values computed independently by
Python `hashlib` (`SHA-256(SHA-256(UTF-16LE("bde-TEST")))` =
`f5acb5bd…ee3f`) and a two-iteration stretch vector — real hash output whose
ground truth is derivable, not authored alongside the code.

## Tier-3 — structural unit tests

FVE metadata-entry parsing, volume-header variant detection, and both sector
transforms' encrypt/decrypt round-trips (CBC + diffuser for `0x8000`, CBC-only
for `0x8002`) are exercised over hand-built byte buffers. These are regression
scaffolding under the Tier-1 oracles — a round-trip proves self-consistency
only; the real correctness proof for each cipher and the full pipeline is
Tier-1.

## Fuzzing

`core/fuzz/fuzz_targets/fuzz_metadata.rs` drives the FVE-metadata parser over
arbitrary bytes; invariant: never panic.
