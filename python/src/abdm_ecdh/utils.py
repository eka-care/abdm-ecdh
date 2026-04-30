from __future__ import annotations
import base64
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .curve import FIELD_SIZE, scalar_mult, unmarshal_uncompressed, is_on_curve
from .x509 import parse_x509_public_key


def sanitize_base64(s: str) -> str:
    s = s.replace(r"\u002B", "+")
    s = s.replace(r"\u002F", "/")
    s = s.replace(r"\u003D", "=")
    return s


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if not a or not b:
        raise ValueError("xor_bytes: input must not be empty")
    if len(a) != len(b):
        raise ValueError(f"xor_bytes: length mismatch ({len(a)} vs {len(b)})")
    return bytes(x ^ y for x, y in zip(a, b))


def derive_iv_and_salt(sender_nonce: str, requester_nonce: str) -> Tuple[bytes, bytes]:
    if not sender_nonce:
        raise ValueError("sender nonce is empty")
    if not requester_nonce:
        raise ValueError("requester nonce is empty")
    xored = xor_bytes(base64.b64decode(sender_nonce), base64.b64decode(requester_nonce))
    if len(xored) < 20:
        raise ValueError(f"XORed nonce too short ({len(xored)} bytes), need at least 20")
    return xored[-12:], xored[:20]


def compute_shared_secret(b64_private_key: str, b64_public_key: str) -> str:
    b64_private_key = sanitize_base64(b64_private_key)
    b64_public_key  = sanitize_base64(b64_public_key)

    d = int.from_bytes(base64.b64decode(b64_private_key), 'big')

    # 88 base64 chars = 65 raw bytes = uncompressed EC point; otherwise X.509 DER
    if len(b64_public_key) == 88:
        px, py = unmarshal_uncompressed(base64.b64decode(b64_public_key))
    else:
        px, py = parse_x509_public_key(b64_public_key)

    if not is_on_curve(px, py):
        raise ValueError("peer public key is not on the curve")

    result = scalar_mult(d, (px, py))
    if result is None:
        raise ValueError("ECDH resulted in point at infinity")

    sx, _ = result
    return base64.b64encode(sx.to_bytes(FIELD_SIZE, 'big')).decode()


def derive_aes_key(shared_secret: str, salt: bytes) -> bytes:
    ikm = base64.b64decode(shared_secret)
    return HKDF(algorithm=SHA256(), length=32, salt=salt, info=b"").derive(ikm)


def aes_gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    return AESGCM(key).encrypt(iv, plaintext, None)


def aes_gcm_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    return AESGCM(key).decrypt(iv, ciphertext, None)
