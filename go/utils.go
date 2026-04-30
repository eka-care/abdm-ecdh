package abdmecdh

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"golang.org/x/crypto/hkdf"
)

// sanitizeBase64 replaces JSON unicode escapes (\u002B → +, \u002F → /, \u003D → =)
// that ABDM/Java systems embed in base64 strings.
func sanitizeBase64(s string) string {
	s = strings.ReplaceAll(s, `\u002B`, "+")
	s = strings.ReplaceAll(s, `\u002F`, "/")
	s = strings.ReplaceAll(s, `\u003D`, "=")
	return s
}

// computeSharedSecret performs ECDH: shared_secret = privateKey * peerPublicKey.
// Returns the base64-encoded X coordinate of the resulting point.
func computeSharedSecret(base64PrivateKey, base64PublicKey string) (string, error) {
	base64PrivateKey = sanitizeBase64(base64PrivateKey)
	base64PublicKey = sanitizeBase64(base64PublicKey)

	privBytes, err := base64.StdEncoding.DecodeString(base64PrivateKey)
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}
	d := new(big.Int).SetBytes(privBytes)

	var px, py *big.Int

	// Detect key format by base64 length:
	// 88 chars = raw EC uncompressed (65 bytes), otherwise = X.509/DER
	if len(base64PublicKey) == 88 {
		pubBytes, err := base64.StdEncoding.DecodeString(base64PublicKey)
		if err != nil {
			return "", fmt.Errorf("decode public key: %w", err)
		}
		px, py, err = unmarshalUncompressed(pubBytes)
		if err != nil {
			return "", fmt.Errorf("unmarshal public key: %w", err)
		}
	} else {
		px, py, err = parseX509PublicKey(base64PublicKey)
		if err != nil {
			return "", fmt.Errorf("parse x509 public key: %w", err)
		}
	}

	// Validate that the peer's public key is on the curve (prevents invalid curve attacks)
	if !isOnCurve(px, py) {
		return "", errors.New("peer public key is not on the curve")
	}

	// ECDH: S = d * Q
	sx, _ := scalarMult(d, px, py)
	if sx == nil {
		return "", errors.New("ECDH resulted in point at infinity")
	}

	// Return base64 of the X coordinate, padded to 32 bytes
	xBytes := make([]byte, fieldSize)
	sxBytes := sx.Bytes()
	copy(xBytes[fieldSize-len(sxBytes):], sxBytes)
	return base64.StdEncoding.EncodeToString(xBytes), nil
}

// xorBytes computes the XOR of two equal-length byte slices.
func xorBytes(a, b []byte) ([]byte, error) {
	if len(a) == 0 || len(b) == 0 {
		return nil, errors.New("xorBytes: input slices must not be empty")
	}
	if len(a) != len(b) {
		return nil, fmt.Errorf("xorBytes: length mismatch (%d vs %d)", len(a), len(b))
	}
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result, nil
}

// deriveIVAndSalt derives the 12-byte IV and 20-byte salt from XOR of nonces.
func deriveIVAndSalt(senderNonce, requesterNonce string) (iv, salt []byte, err error) {
	if senderNonce == "" {
		return nil, nil, errors.New("sender nonce is empty")
	}
	if requesterNonce == "" {
		return nil, nil, errors.New("requester nonce is empty")
	}

	senderNonceBytes, err := base64.StdEncoding.DecodeString(senderNonce)
	if err != nil {
		return nil, nil, fmt.Errorf("decode sender nonce: %w", err)
	}
	requesterNonceBytes, err := base64.StdEncoding.DecodeString(requesterNonce)
	if err != nil {
		return nil, nil, fmt.Errorf("decode requester nonce: %w", err)
	}

	xored, err := xorBytes(senderNonceBytes, requesterNonceBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("XOR nonces: %w", err)
	}
	if len(xored) < 20 {
		return nil, nil, fmt.Errorf("XORed nonce too short (%d bytes), need at least 20", len(xored))
	}
	iv = xored[len(xored)-12:]
	salt = xored[:20]
	return iv, salt, nil
}

// deriveAESKey derives a 32-byte AES key using HKDF-SHA256.
func deriveAESKey(sharedSecret string, salt []byte) ([]byte, error) {
	ikm, err := base64.StdEncoding.DecodeString(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("decode shared secret: %w", err)
	}

	hkdfReader := hkdf.New(sha256.New, ikm, salt, nil)
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("HKDF expand: %w", err)
	}
	return key, nil
}

// aesGCMEncrypt encrypts plaintext using AES-256-GCM.
func aesGCMEncrypt(key, iv, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, iv, plaintext, nil), nil
}

// aesGCMDecrypt decrypts ciphertext (with appended auth tag) using AES-256-GCM.
func aesGCMDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, iv, ciphertext, nil)
}

// parseX509PublicKey parses a base64-encoded X.509/DER SubjectPublicKeyInfo
// and extracts the uncompressed EC point.
func parseX509PublicKey(base64Key string) (*big.Int, *big.Int, error) {
	derBytes, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, nil, fmt.Errorf("decode base64: %w", err)
	}

	// SubjectPublicKeyInfo ::= SEQUENCE {
	//   algorithm AlgorithmIdentifier,
	//   subjectPublicKey BIT STRING
	// }
	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(derBytes, &spki); err != nil {
		return nil, nil, fmt.Errorf("unmarshal SPKI: %w", err)
	}

	return unmarshalUncompressed(spki.PublicKey.Bytes)
}
