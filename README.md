# abdm-ecdh

A Go library implementing the ABDM (Ayushman Bharat Digital Mission) ECDH encryption protocol for secure health data exchange.

## Overview

This library provides ECDH key agreement using Curve25519 (Weierstrass form) with AES-256-GCM encryption, as required by the ABDM Health Information Exchange & Consent Manager (HIE-CM) specification.

## Installation

```bash
go get github.com/eka-care/abdm-ecdh
```

## Usage

```go
package main

import (
    abdmecdh "github.com/eka-care/abdm-ecdh"
)

func main() {
    e := abdmecdh.New()

    // Generate key material (key pair + nonce)
    keyMaterial, err := e.GenerateKeyMaterial()
    if err != nil {
        panic(err)
    }

    // Encrypt
    encResp, err := e.Encrypt(abdmecdh.EncryptionRequest{
        StringToEncrypt:    "sensitive health data",
        SenderNonce:        senderKeyMaterial.Nonce,
        RequesterNonce:     requesterKeyMaterial.Nonce,
        SenderPrivateKey:   senderKeyMaterial.PrivateKey,
        RequesterPublicKey: requesterKeyMaterial.X509PublicKey,
    })
    if err != nil {
        panic(err)
    }

    // Decrypt
    decResp, err := e.Decrypt(abdmecdh.DecryptionRequest{
        EncryptedData:       encResp.EncryptedData,
        RequesterNonce:      requesterKeyMaterial.Nonce,
        SenderNonce:         senderKeyMaterial.Nonce,
        RequesterPrivateKey: requesterKeyMaterial.PrivateKey,
        SenderPublicKey:     senderKeyMaterial.X509PublicKey,
    })
    if err != nil {
        panic(err)
    }
}
```

## API

### `New() ECDH`

Returns a new ECDH instance implementing the `ECDH` interface.

### `GenerateKeyMaterial() (*KeyMaterial, error)`

Generates an ECDH key pair on Curve25519 (Weierstrass form) and a random 32-byte nonce. Returns:

- `PrivateKey` — base64-encoded private scalar
- `PublicKey` — base64-encoded uncompressed EC point
- `X509PublicKey` — base64-encoded X.509 SubjectPublicKeyInfo DER
- `Nonce` — base64-encoded 32-byte random nonce

### `Encrypt(req EncryptionRequest) (*EncryptionResponse, error)`

Encrypts a plaintext string using ECDH shared secret derivation + HKDF-SHA256 + AES-256-GCM.

### `Decrypt(req DecryptionRequest) (*DecryptionResponse, error)`

Decrypts ciphertext using ECDH shared secret derivation + HKDF-SHA256 + AES-256-GCM.

## Cryptographic Details

- **Key Agreement**: ECDH on Curve25519 (Weierstrass form)
- **Key Derivation**: HKDF-SHA256
- **Encryption**: AES-256-GCM
- **Nonce Handling**: IV and salt derived from XOR of sender and requester nonces

## License

MIT