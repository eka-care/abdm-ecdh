package abdmecdh

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
)

// KeyMaterial holds the generated ECDH key pair and nonce.
type KeyMaterial struct {
	PrivateKey   string `json:"privateKey"`
	PublicKey    string `json:"publicKey"`
	X509PublicKey string `json:"x509PublicKey"`
	Nonce        string `json:"nonce"`
}

// GenerateKeyMaterial generates an ECDH key pair on Weierstrass Curve25519
// and a random 32-byte nonce.
func GenerateKeyMaterial() (*KeyMaterial, error) {
	// Generate random scalar d in [1, N-1]
	d, err := rand.Int(rand.Reader, new(big.Int).Sub(curveN, big.NewInt(1)))
	if err != nil {
		return nil, fmt.Errorf("generate random scalar: %w", err)
	}
	d.Add(d, big.NewInt(1)) // shift from [0, N-2] to [1, N-1]

	// Compute public key Q = d * G
	qx, qy := scalarBaseMult(d)

	// Encode private key as base64 (matching Java BigInteger.toByteArray() sign byte behavior)
	privBytes := d.Bytes()
	// Java's BigInteger.toByteArray() prepends a 0x00 byte if the high bit is set
	if privBytes[0]&0x80 != 0 {
		privBytes = append([]byte{0x00}, privBytes...)
	}
	privateKeyB64 := base64.StdEncoding.EncodeToString(privBytes)

	// Encode public key as uncompressed point (65 bytes) -> base64
	pubBytes := marshalUncompressed(qx, qy)
	publicKeyB64 := base64.StdEncoding.EncodeToString(pubBytes)

	// Encode X.509 SubjectPublicKeyInfo DER -> base64
	x509Bytes, err := marshalX509PublicKey(qx, qy)
	if err != nil {
		return nil, fmt.Errorf("marshal x509 public key: %w", err)
	}
	x509PublicKeyB64 := base64.StdEncoding.EncodeToString(x509Bytes)

	// Generate random 32-byte nonce
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	nonceB64 := base64.StdEncoding.EncodeToString(nonce)

	return &KeyMaterial{
		PrivateKey:    privateKeyB64,
		PublicKey:     publicKeyB64,
		X509PublicKey: x509PublicKeyB64,
		Nonce:         nonceB64,
	}, nil
}
