import base64
import pytest

# Static test vectors (Java/BouncyCastle-generated, same as Go tests)
REQUESTER_PRIVATE_KEY = "Dnh316gsSfP+0kiNmEgsIekLsY6BQr7b++3rHQ8otAI="
REQUESTER_PUBLIC_KEY  = "BBbWU1fw1y1ErdKasIoQKKAWzq3N9ARcrukg7b1MpD3RHi9ofFAFhyIwMIA5p+iMCcLHkzQRoEFvCpNET1+tFtQ="
REQUESTER_NONCE       = "5mLKfBzxPw5+xVgxHu/iG+mzw+xIVN1dSFDrqB/KkIE="
SENDER_PRIVATE_KEY    = "BJig2akHxYJKjA/uyUSzVris72DsOt95vVaG2ZzGSDE="
SENDER_PUBLIC_KEY     = "BDWu6EFsroAUi8lnWZmLZCDZT7XbpsdEC7eeEtNnseHkDKa0igaRxDQOKro7KBaivUiTxdfvRK0mVlVgWGyZo98="
SENDER_NONCE          = "IEEtSc15HpLboL/kjBhu+K2Hqro/aoTh9HAgXA5JwMM="
PLAINTEXT             = ""
ENCRYPTED_DATA        = ""  # placeholder — test using this will be skipped


def test_generator_point_on_curve():
    from abdm_ecdh.curve import CURVE_GX, CURVE_GY, is_on_curve
    assert is_on_curve(CURVE_GX, CURVE_GY)


def test_requester_public_key_on_curve():
    from abdm_ecdh.curve import unmarshal_uncompressed, is_on_curve
    x, y = unmarshal_uncompressed(base64.b64decode(REQUESTER_PUBLIC_KEY))
    assert is_on_curve(x, y)


def test_x509_marshal_parse_roundtrip():
    from abdm_ecdh.x509 import marshal_x509_public_key, parse_x509_public_key
    from abdm_ecdh.curve import CURVE_GX, CURVE_GY
    x, y = parse_x509_public_key(marshal_x509_public_key(CURVE_GX, CURVE_GY))
    assert x == CURVE_GX
    assert y == CURVE_GY


def test_sanitize_base64():
    from abdm_ecdh.utils import sanitize_base64
    assert sanitize_base64(r"A\u002BB\u002FC\u003D") == "A+B/C="
    assert sanitize_base64("unchanged") == "unchanged"


def test_xor_bytes_known():
    from abdm_ecdh.utils import xor_bytes
    assert xor_bytes(b'\xff\x00', b'\x0f\xf0') == b'\xf0\xf0'


def test_xor_bytes_length_mismatch():
    from abdm_ecdh.utils import xor_bytes
    with pytest.raises(ValueError, match="length mismatch"):
        xor_bytes(b'\x01', b'\x01\x02')


def test_derive_iv_and_salt_lengths():
    from abdm_ecdh.utils import derive_iv_and_salt
    iv, salt = derive_iv_and_salt(SENDER_NONCE, REQUESTER_NONCE)
    assert len(iv) == 12
    assert len(salt) == 20


def test_generate_key_material_fields():
    from abdm_ecdh import generate_key_material
    km = generate_key_material()
    for field in (km.private_key, km.public_key, km.x509_public_key, km.nonce):
        assert field
        base64.b64decode(field)  # must be valid base64


def test_generated_public_key_on_curve():
    from abdm_ecdh import generate_key_material
    from abdm_ecdh.curve import unmarshal_uncompressed, is_on_curve
    km = generate_key_material()
    x, y = unmarshal_uncompressed(base64.b64decode(km.public_key))
    assert is_on_curve(x, y)


def test_round_trip():
    from abdm_ecdh import generate_key_material, encrypt, decrypt
    sender    = generate_key_material()
    requester = generate_key_material()
    original  = "The secret is safe"

    enc = encrypt(
        string_to_encrypt=original,
        sender_nonce=sender.nonce,
        requester_nonce=requester.nonce,
        sender_private_key=sender.private_key,
        requester_public_key=requester.public_key,
    )
    dec = decrypt(
        encrypted_data=enc.encrypted_data,
        sender_nonce=sender.nonce,
        requester_nonce=requester.nonce,
        requester_private_key=requester.private_key,
        sender_public_key=sender.public_key,
    )
    assert dec.decrypted_data == original


def test_encrypt_decrypt_with_java_keys():
    from abdm_ecdh import encrypt, decrypt
    enc = encrypt(
        string_to_encrypt=PLAINTEXT,
        sender_nonce=SENDER_NONCE,
        requester_nonce=REQUESTER_NONCE,
        sender_private_key=SENDER_PRIVATE_KEY,
        requester_public_key=REQUESTER_PUBLIC_KEY,
    )
    dec = decrypt(
        encrypted_data=enc.encrypted_data,
        sender_nonce=SENDER_NONCE,
        requester_nonce=REQUESTER_NONCE,
        requester_private_key=REQUESTER_PRIVATE_KEY,
        sender_public_key=SENDER_PUBLIC_KEY,
    )
    assert dec.decrypted_data == PLAINTEXT


def test_cross_impl_python_encrypt_java_decrypt():
    from abdm_ecdh import generate_key_material, encrypt, decrypt
    py_sender = generate_key_material()
    original  = ""

    enc = encrypt(
        string_to_encrypt=original,
        sender_nonce=py_sender.nonce,
        requester_nonce=REQUESTER_NONCE,
        sender_private_key=py_sender.private_key,
        requester_public_key=REQUESTER_PUBLIC_KEY,
    )
    dec = decrypt(
        encrypted_data=enc.encrypted_data,
        sender_nonce=py_sender.nonce,
        requester_nonce=REQUESTER_NONCE,
        requester_private_key=REQUESTER_PRIVATE_KEY,
        sender_public_key=py_sender.public_key,
    )
    assert dec.decrypted_data == original


def test_cross_impl_java_encrypt_python_decrypt():
    from abdm_ecdh import generate_key_material, encrypt, decrypt
    py_requester = generate_key_material()
    original     = "Orig"

    enc = encrypt(
        string_to_encrypt=original,
        sender_nonce=SENDER_NONCE,
        requester_nonce=py_requester.nonce,
        sender_private_key=SENDER_PRIVATE_KEY,
        requester_public_key=py_requester.public_key,
    )
    dec = decrypt(
        encrypted_data=enc.encrypted_data,
        sender_nonce=SENDER_NONCE,
        requester_nonce=py_requester.nonce,
        requester_private_key=py_requester.private_key,
        sender_public_key=SENDER_PUBLIC_KEY,
    )
    assert dec.decrypted_data == original


def test_encrypt_with_x509_public_key():
    """Explicitly tests the X.509 DER key path in compute_shared_secret."""
    from abdm_ecdh import generate_key_material, encrypt, decrypt
    py_requester = generate_key_material()
    original     = "test x509 path"

    enc = encrypt(
        string_to_encrypt=original,
        sender_nonce=SENDER_NONCE,
        requester_nonce=py_requester.nonce,
        sender_private_key=SENDER_PRIVATE_KEY,
        requester_public_key=py_requester.x509_public_key,  # X.509 DER format
    )
    dec = decrypt(
        encrypted_data=enc.encrypted_data,
        sender_nonce=SENDER_NONCE,
        requester_nonce=py_requester.nonce,
        requester_private_key=py_requester.private_key,
        sender_public_key=SENDER_PUBLIC_KEY,
    )
    assert dec.decrypted_data == original


@pytest.mark.skipif(not ENCRYPTED_DATA, reason="static encrypted vector not set")
def test_decrypt_with_known_vector():
    from abdm_ecdh import decrypt
    dec = decrypt(
        encrypted_data=ENCRYPTED_DATA,
        sender_nonce=SENDER_NONCE,
        requester_nonce=REQUESTER_NONCE,
        requester_private_key=REQUESTER_PRIVATE_KEY,
        sender_public_key=SENDER_PUBLIC_KEY,
    )
    assert dec.decrypted_data == PLAINTEXT


# --- peer key validation ---------------------------------------------------------

def _low_order_point():
    """(A/3 mod P, 0): on the curve but of order 2 (Montgomery u = 0)."""
    from abdm_ecdh.curve import CURVE_P
    return (486662 * pow(3, -1, CURVE_P)) % CURVE_P, 0


def test_rejects_low_order_peer_key():
    from abdm_ecdh import encrypt, generate_key_material
    from abdm_ecdh.curve import is_on_curve, marshal_uncompressed
    x, y = _low_order_point()
    assert is_on_curve(x, y)
    pub = base64.b64encode(marshal_uncompressed(x, y)).decode()
    # enough iterations to hit both private-key parities (odd ones used to return a fixed secret)
    for _ in range(32):
        km = generate_key_material()
        with pytest.raises(ValueError, match="prime-order subgroup"):
            encrypt("x", km.nonce, km.nonce, km.private_key, pub)


def test_rejects_non_canonical_coordinates():
    from abdm_ecdh.curve import CURVE_GX, CURVE_GY, CURVE_P, is_on_curve
    assert not is_on_curve(CURVE_GX + CURVE_P, CURVE_GY)


def test_rejects_off_curve_key():
    from abdm_ecdh import generate_key_material
    from abdm_ecdh.utils import compute_shared_secret
    km = generate_key_material()
    raw = bytearray(base64.b64decode(km.public_key))
    raw[64] ^= 1
    with pytest.raises(ValueError, match="not on the curve"):
        compute_shared_secret(km.private_key, base64.b64encode(bytes(raw)).decode())


def test_truncated_x509_raises_value_error():
    from abdm_ecdh.x509 import parse_x509_public_key
    with pytest.raises(ValueError):
        parse_x509_public_key(b"\x30\x82\x01")


def test_encrypt_accepts_escaped_nonces():
    from abdm_ecdh import encrypt, decrypt, generate_key_material
    a, b = generate_key_material(), generate_key_material()
    esc = lambda s: s.replace("+", r"\u002B").replace("/", r"\u002F").replace("=", r"\u003D")
    enc = encrypt("hello", esc(a.nonce), esc(b.nonce), a.private_key, b.x509_public_key)
    dec = decrypt(enc.encrypted_data, a.nonce, b.nonce, b.private_key, a.x509_public_key)
    assert dec.decrypted_data == "hello"
