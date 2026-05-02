# abdm-ecdh

Python library implementing the ABDM (Ayushman Bharat Digital Mission) ECDH encryption protocol for secure health data exchange.

## Installation

```bash
pip install abdm-ecdh
```

## Usage

```python
from abdm_ecdh import generate_key_material, encrypt, decrypt

# Each party generates their own key material
sender    = generate_key_material()
requester = generate_key_material()

# Sender encrypts
enc = encrypt(
    string_to_encrypt="sensitive health data",
    sender_nonce=sender.nonce,
    requester_nonce=requester.nonce,
    sender_private_key=sender.private_key,
    requester_public_key=requester.x509_public_key,
)

# Requester decrypts
dec = decrypt(
    encrypted_data=enc.encrypted_data,
    sender_nonce=sender.nonce,
    requester_nonce=requester.nonce,
    requester_private_key=requester.private_key,
    sender_public_key=sender.x509_public_key,
)

print(dec.decrypted_data)  # "sensitive health data"
```

## API

### `generate_key_material() -> KeyMaterial`

Generates an ECDH key pair on Curve25519 (Weierstrass form) and a random 32-byte nonce.

Returns a `KeyMaterial` dataclass with fields:
- `private_key` — base64-encoded private scalar
- `public_key` — base64-encoded uncompressed EC point (65 bytes)
- `x509_public_key` — base64-encoded X.509 SubjectPublicKeyInfo DER
- `nonce` — base64-encoded 32-byte random nonce

### `encrypt(...) -> EncryptionResponse`

Encrypts a plaintext string using ECDH shared secret derivation + HKDF-SHA256 + AES-256-GCM.

Parameters: `string_to_encrypt`, `sender_nonce`, `requester_nonce`, `sender_private_key`, `requester_public_key`

Returns `EncryptionResponse` with `encrypted_data` (base64 string).

### `decrypt(...) -> DecryptionResponse`

Decrypts ciphertext using ECDH shared secret derivation + HKDF-SHA256 + AES-256-GCM.

Parameters: `encrypted_data`, `sender_nonce`, `requester_nonce`, `requester_private_key`, `sender_public_key`

Returns `DecryptionResponse` with `decrypted_data` (string).

## Cryptographic Details

- **Key Agreement:** ECDH on Curve25519 (Weierstrass form), compatible with Java/BouncyCastle
- **Key Derivation:** HKDF-SHA256
- **Encryption:** AES-256-GCM
- **Nonce Handling:** IV and salt derived from XOR of sender and requester nonces

## License

MIT
