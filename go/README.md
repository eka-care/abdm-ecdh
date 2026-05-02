# abdm-ecdh/go

Go library implementing the ABDM (Ayushman Bharat Digital Mission) ECDH encryption protocol for secure health data exchange.

## Installation

```bash
go get github.com/eka-care/abdm-ecdh/go
```

> **Note:** Module path changed from `github.com/eka-care/abdm-ecdh` (v1.x) to `github.com/eka-care/abdm-ecdh/go` (v2.x).

## Usage

```go
package main

import (
    abdmecdh "github.com/eka-care/abdm-ecdh/go"
)

func main() {
    e := abdmecdh.New()

    sender, err := e.GenerateKeyMaterial()
    if err != nil {
        panic(err)
    }
    requester, err := e.GenerateKeyMaterial()
    if err != nil {
        panic(err)
    }

    enc, err := e.Encrypt(abdmecdh.EncryptionRequest{
        StringToEncrypt:    "sensitive health data",
        SenderNonce:        sender.Nonce,
        RequesterNonce:     requester.Nonce,
        SenderPrivateKey:   sender.PrivateKey,
        RequesterPublicKey: requester.X509PublicKey,
    })
    if err != nil {
        panic(err)
    }

    dec, err := e.Decrypt(abdmecdh.DecryptionRequest{
        EncryptedData:       enc.EncryptedData,
        SenderNonce:         sender.Nonce,
        RequesterNonce:      requester.Nonce,
        RequesterPrivateKey: requester.PrivateKey,
        SenderPublicKey:     sender.X509PublicKey,
    })
    if err != nil {
        panic(err)
    }

    fmt.Println(dec.DecryptedData) // "sensitive health data"
}
```

## API

### `New() ECDH`

Returns a new ECDH instance.

### `GenerateKeyMaterial() (*KeyMaterial, error)`

Generates an ECDH key pair on Curve25519 (Weierstrass form) and a random 32-byte nonce.

Returns `*KeyMaterial` with fields:
- `PrivateKey` — base64-encoded private scalar
- `PublicKey` — base64-encoded uncompressed EC point (65 bytes)
- `X509PublicKey` — base64-encoded X.509 SubjectPublicKeyInfo DER
- `Nonce` — base64-encoded 32-byte random nonce

### `Encrypt(req EncryptionRequest) (*EncryptionResponse, error)`

Encrypts a plaintext string using ECDH shared secret derivation + HKDF-SHA256 + AES-256-GCM.

### `Decrypt(req DecryptionRequest) (*DecryptionResponse, error)`

Decrypts ciphertext using ECDH shared secret derivation + HKDF-SHA256 + AES-256-GCM.

## Cryptographic Details

- **Key Agreement:** ECDH on Curve25519 (Weierstrass form), compatible with Java/BouncyCastle
- **Key Derivation:** HKDF-SHA256
- **Encryption:** AES-256-GCM
- **Nonce Handling:** IV and salt derived from XOR of sender and requester nonces

## License

MIT
