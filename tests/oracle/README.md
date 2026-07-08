# Tier-1 oracle

The correctness backstop for `bitlocker-core` is the `dfvfs` **`bdetogo.raw`**
image decrypted by **`pybde`** (libbde 20240502) with the published password
`bde-TEST`. `bitlocker-core` must reproduce each decrypted 512-byte sector
byte-for-byte (SHA-256 match).

- Image provenance + download: [`../data/README.md`](../data/README.md).
- Ground-truth digests + methodology: [`../../docs/validation.md`](../../docs/validation.md).
- Consuming test: [`../../core/tests/oracle_bdetogo.rs`](../../core/tests/oracle_bdetogo.rs),
  env-gated on `BDE_ORACLE_IMAGE`.

Regenerate / extend ground truth with `pybde`:

```python
import pybde
v = pybde.volume()
v.set_password("bde-TEST")
with open("bdetogo.raw", "rb") as f:
    v.open_file_object(f)
    print(v.read_buffer_at_offset(512, 0).hex())
```
