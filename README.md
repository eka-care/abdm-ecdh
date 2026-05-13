# abdm-ecdh

ABDM (Ayushman Bharat Digital Mission) ECDH encryption/decryption for secure health data exchange.

## What this does

ABDM's HIE-CM specification requires a specific encryption scheme for exchanging health records between parties. This library implements that scheme.

The overall pattern — ECDH key agreement → HKDF key derivation → AES-GCM encryption — is standard. Two things make it ABDM-specific:

**1. Weierstrass Curve25519**
ABDM's reference implementation is in Java using BouncyCastle, which represents Curve25519 in short Weierstrass form (`y² = x³ + Ax + B`) rather than the standard Montgomery form used by X25519. Standard crypto libraries don't expose this form, so the elliptic curve math is implemented directly.

**2. Dual-nonce IV derivation**
Both parties generate and exchange a random nonce. The sender and requester nonces are XOR'd together to produce the AES-GCM IV (last 12 bytes) and HKDF salt (first 20 bytes). This ensures both parties contribute entropy to the session.

## Cryptographic details

| Step | Algorithm |
|---|---|
| Key agreement | ECDH on Curve25519 (Weierstrass form) |
| Key derivation | HKDF-SHA256 (salt = first 20 bytes of XOR'd nonces) |
| Encryption | AES-256-GCM (IV = last 12 bytes of XOR'd nonces) |
| Key encoding | X.509 SubjectPublicKeyInfo DER (BouncyCastle explicit params) |

## CI Status

[![CI — Go](https://github.com/eka-care/abdm-ecdh/actions/workflows/ci-go.yml/badge.svg)](https://github.com/eka-care/abdm-ecdh/actions/workflows/ci-go.yml)
[![CI — Python](https://github.com/eka-care/abdm-ecdh/actions/workflows/ci-python.yml/badge.svg)](https://github.com/eka-care/abdm-ecdh/actions/workflows/ci-python.yml)
[![CI — Java](https://github.com/eka-care/abdm-ecdh/actions/workflows/ci-java.yml/badge.svg)](https://github.com/eka-care/abdm-ecdh/actions/workflows/ci-java.yml)

## Packages

| Language | Docs | Install |
|---|---|---|
| Go | [`go/`](./go/) | `go get github.com/eka-care/abdm-ecdh/go@v2.0.0` |
| Python | [`python/`](./python/) | `pip install abdm-ecdh` |
| Java | [`java/`](./java/) | `com.github.eka-care:abdm-ecdh:java/v1.0.0` (JitPack) |

## License

MIT
