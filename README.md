# abdm-ecdh

ABDM (Ayushman Bharat Digital Mission) ECDH encryption/decryption for secure health data exchange.

Implements ECDH key agreement using Curve25519 (Weierstrass form) with AES-256-GCM encryption, as required by the ABDM HIE-CM specification. Available for Go and Python.

## Packages

| Language | Source | Import |
|---|---|---|
| Go | [`go/`](./go/) | `github.com/eka-care/abdm-ecdh/go` |
| Python | [`python/`](./python/) | `abdm-ecdh` via GitHub |

## Go

```bash
go get github.com/eka-care/abdm-ecdh/go
```

> **Note:** Module path changed from `github.com/eka-care/abdm-ecdh` (v1.x) to `github.com/eka-care/abdm-ecdh/go` (v2.0.0).

See [`go/`](./go/) for full API documentation.

## Python

```bash
pip install "git+https://github.com/eka-care/abdm-ecdh.git#subdirectory=python"
```

To pin to a specific version:

```bash
pip install "git+https://github.com/eka-care/abdm-ecdh.git@v2.0.0#subdirectory=python"
```

In `pyproject.toml`:

```toml
dependencies = [
    "abdm-ecdh @ git+https://github.com/eka-care/abdm-ecdh.git@v2.0.0#subdirectory=python"
]
```

```python
from abdm_ecdh import generate_key_material, encrypt, decrypt

sender    = generate_key_material()
requester = generate_key_material()

enc = encrypt(
    string_to_encrypt="sensitive health data",
    sender_nonce=sender.nonce,
    requester_nonce=requester.nonce,
    sender_private_key=sender.private_key,
    requester_public_key=requester.x509_public_key,
)
dec = decrypt(
    encrypted_data=enc.encrypted_data,
    sender_nonce=sender.nonce,
    requester_nonce=requester.nonce,
    requester_private_key=requester.private_key,
    sender_public_key=sender.x509_public_key,
)
```

See [`python/`](./python/) for full API documentation.

## License

MIT
