from __future__ import annotations
import base64
import secrets
from dataclasses import dataclass

from .curve import CURVE_N, FIELD_SIZE, scalar_base_mult, marshal_uncompressed
from .x509 import marshal_x509_public_key


@dataclass
class KeyMaterial:
    private_key: str
    public_key: str
    x509_public_key: str
    nonce: str


def generate_key_material() -> KeyMaterial:
    d = secrets.randbelow(CURVE_N - 1) + 1  # random scalar in [1, N-1]

    point = scalar_base_mult(d)
    if point is None:
        raise RuntimeError("scalar_base_mult returned point at infinity")
    qx, qy = point

    # Java BigInteger.toByteArray() compatibility: prepend 0x00 if high bit set
    priv_bytes = d.to_bytes((d.bit_length() + 7) // 8, 'big')
    if priv_bytes[0] & 0x80:
        priv_bytes = b'\x00' + priv_bytes

    return KeyMaterial(
        private_key=base64.b64encode(priv_bytes).decode(),
        public_key=base64.b64encode(marshal_uncompressed(qx, qy)).decode(),
        x509_public_key=base64.b64encode(marshal_x509_public_key(qx, qy)).decode(),
        nonce=base64.b64encode(secrets.token_bytes(32)).decode(),
    )
