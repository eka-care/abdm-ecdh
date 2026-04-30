from __future__ import annotations
import base64
from typing import Tuple

from .curve import (
    CURVE_P, CURVE_A, CURVE_B, CURVE_N, CURVE_GX, CURVE_GY,
    FIELD_SIZE, marshal_uncompressed, unmarshal_uncompressed,
)

OID_EC_PUBLIC_KEY = (1, 2, 840, 10045, 2, 1)
OID_PRIME_FIELD   = (1, 2, 840, 10045, 1, 1)


def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    lb = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(lb)]) + lb


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _enc_len(len(value)) + value


def _enc_int(n: int) -> bytes:
    if n == 0:
        return _tlv(0x02, b'\x00')
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    if b[0] & 0x80:
        b = b'\x00' + b
    return _tlv(0x02, b)


def _enc_oid(oid: tuple) -> bytes:
    body = bytes([40 * oid[0] + oid[1]])
    for c in oid[2:]:
        if c == 0:
            body += b'\x00'
        else:
            parts: list[int] = []
            while c:
                parts.append(c & 0x7F)
                c >>= 7
            parts.reverse()
            body += bytes([p | 0x80 for p in parts[:-1]] + [parts[-1]])
    return _tlv(0x06, body)


def _enc_seq(*items: bytes) -> bytes:
    return _tlv(0x30, b''.join(items))


def _pad32(b: bytes) -> bytes:
    if len(b) >= FIELD_SIZE:
        return b[len(b) - FIELD_SIZE:]
    return b'\x00' * (FIELD_SIZE - len(b)) + b


def _read_tlv(data: bytes, pos: int) -> Tuple[int, bytes, int]:
    """Returns (tag, value_bytes, next_pos)."""
    tag = data[pos]
    pos += 1
    if data[pos] < 0x80:
        length, pos = data[pos], pos + 1
    else:
        n      = data[pos] & 0x7F
        length = int.from_bytes(data[pos + 1:pos + 1 + n], 'big')
        pos   += 1 + n
    return tag, data[pos:pos + length], pos + length


def marshal_x509_public_key(x: int, y: int) -> bytes:
    point     = marshal_uncompressed(x, y)
    generator = marshal_uncompressed(CURVE_GX, CURVE_GY)
    a_bytes   = _pad32(CURVE_A.to_bytes((CURVE_A.bit_length() + 7) // 8, 'big'))
    b_bytes   = _pad32(CURVE_B.to_bytes((CURVE_B.bit_length() + 7) // 8, 'big'))

    ec_params = _enc_seq(
        _enc_int(1),
        _enc_seq(_enc_oid(OID_PRIME_FIELD), _enc_int(CURVE_P)),
        _enc_seq(_tlv(0x04, a_bytes), _tlv(0x04, b_bytes)),
        _tlv(0x04, generator),
        _enc_int(CURVE_N),
        _enc_int(8),
    )
    algorithm = _enc_seq(_enc_oid(OID_EC_PUBLIC_KEY), ec_params)
    return _enc_seq(algorithm, _tlv(0x03, b'\x00' + point))


def parse_x509_public_key(base64_key: str) -> Tuple[int, int]:
    der = base64.b64decode(base64_key)
    _, spki_content, _ = _read_tlv(der, 0)          # outer SEQUENCE
    _, _, next_pos     = _read_tlv(spki_content, 0)  # skip AlgorithmIdentifier
    _, bs_value, _     = _read_tlv(spki_content, next_pos)  # BIT STRING
    return unmarshal_uncompressed(bs_value[1:])       # skip unused-bits byte (0x00)
