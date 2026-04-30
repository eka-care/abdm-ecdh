from __future__ import annotations
import base64
from dataclasses import dataclass

from .utils import (
    sanitize_base64, derive_iv_and_salt, compute_shared_secret,
    derive_aes_key, aes_gcm_decrypt,
)


@dataclass
class DecryptionResponse:
    decrypted_data: str


def decrypt(
    encrypted_data: str,
    sender_nonce: str,
    requester_nonce: str,
    requester_private_key: str,
    sender_public_key: str,
) -> DecryptionResponse:
    encrypted_data  = sanitize_base64(encrypted_data)
    sender_nonce    = sanitize_base64(sender_nonce)
    requester_nonce = sanitize_base64(requester_nonce)

    iv, salt      = derive_iv_and_salt(sender_nonce, requester_nonce)
    shared_secret = compute_shared_secret(requester_private_key, sender_public_key)
    aes_key       = derive_aes_key(shared_secret, salt)
    plaintext     = aes_gcm_decrypt(aes_key, iv, base64.b64decode(encrypted_data))
    return DecryptionResponse(decrypted_data=plaintext.decode())
