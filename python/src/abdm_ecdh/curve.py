from __future__ import annotations
from typing import Optional, Tuple

CURVE_P  = int("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)
CURVE_A  = int("2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA984914A144", 16)
CURVE_B  = int("7B425ED097B425ED097B425ED097B425ED097B425ED097B4260B5E9C7710C864", 16)
CURVE_N  = int("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED", 16)
CURVE_GX = int("2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD245A", 16)
CURVE_GY = int("20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9", 16)

FIELD_SIZE = 32
POINT_SIZE = 65

Point = Optional[Tuple[int, int]]


def point_add(p1: Point, p2: Point) -> Point:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        return point_double(p1) if y1 == y2 else None
    p = CURVE_P
    lam = ((y2 - y1) * pow(x2 - x1, p - 2, p)) % p
    x3  = (lam * lam - x1 - x2) % p
    y3  = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def point_double(p: Point) -> Point:
    if p is None:
        return None
    x, y = p
    if y == 0:
        return None
    mod = CURVE_P
    lam = ((3 * x * x + CURVE_A) * pow(2 * y, mod - 2, mod)) % mod
    x3  = (lam * lam - 2 * x) % mod
    y3  = (lam * (x - x3) - y) % mod
    return (x3, y3)


def scalar_mult(k: int, point: Point) -> Point:
    k      = k % CURVE_N
    result: Point = None
    addend = point
    for i in range(k.bit_length()):
        if (k >> i) & 1:
            result = point_add(result, addend)
        addend = point_double(addend)
    return result


def scalar_base_mult(k: int) -> Point:
    return scalar_mult(k, (CURVE_GX, CURVE_GY))


def marshal_uncompressed(x: int, y: int) -> bytes:
    buf = bytearray(POINT_SIZE)
    buf[0] = 0x04
    buf[1:1 + FIELD_SIZE]            = x.to_bytes(FIELD_SIZE, 'big')
    buf[1 + FIELD_SIZE:POINT_SIZE]   = y.to_bytes(FIELD_SIZE, 'big')
    return bytes(buf)


def unmarshal_uncompressed(data: bytes) -> Tuple[int, int]:
    if len(data) != POINT_SIZE:
        raise ValueError(f"invalid point length: expected 65, got {len(data)}")
    if data[0] != 0x04:
        raise ValueError("invalid point prefix: expected 0x04")
    return (
        int.from_bytes(data[1:1 + FIELD_SIZE], 'big'),
        int.from_bytes(data[1 + FIELD_SIZE:], 'big'),
    )


def is_on_curve(x: int, y: int) -> bool:
    p   = CURVE_P
    lhs = pow(y, 2, p)
    rhs = (pow(x, 3, p) + CURVE_A * x + CURVE_B) % p
    return lhs == rhs
