from __future__ import annotations
import base64
from dataclasses import dataclass

from .utils import sanitize_base64, derive_iv_and_salt, compute_shared_secret, derive_aes_key, aes_gcm_encrypt


@dataclass
class EncryptionResponse:
    encrypted_data: str


def encrypt(
    string_to_encrypt: str,
    sender_nonce: str,
    requester_nonce: str,
    sender_private_key: str,
    requester_public_key: str,
) -> EncryptionResponse:
    sender_nonce    = sanitize_base64(sender_nonce)
    requester_nonce = sanitize_base64(requester_nonce)

    iv, salt      = derive_iv_and_salt(sender_nonce, requester_nonce)
    shared_secret = compute_shared_secret(sender_private_key, requester_public_key)
    aes_key       = derive_aes_key(shared_secret, salt)
    ciphertext    = aes_gcm_encrypt(aes_key, iv, string_to_encrypt.encode())
    return EncryptionResponse(encrypted_data=base64.b64encode(ciphertext).decode())
