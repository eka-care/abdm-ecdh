package abdmecdh

import (
	"encoding/base64"
	"fmt"
)

// DecryptionRequest holds the parameters for decryption.
type DecryptionRequest struct {
	EncryptedData      string `json:"encryptedData"`
	RequesterNonce     string `json:"requesterNonce"`
	SenderNonce        string `json:"senderNonce"`
	RequesterPrivateKey string `json:"requesterPrivateKey"`
	SenderPublicKey    string `json:"senderPublicKey"`
}

// DecryptionResponse holds the decrypted output.
type DecryptionResponse struct {
	DecryptedData string `json:"decryptedData"`
}

// Decrypt decrypts data using ECDH + HKDF + AES-256-GCM.
func Decrypt(req DecryptionRequest) (*DecryptionResponse, error) {
	// Derive IV and salt from XOR of nonces
	iv, salt, err := deriveIVAndSalt(req.SenderNonce, req.RequesterNonce)
	if err != nil {
		return nil, fmt.Errorf("derive IV and salt: %w", err)
	}

	// Compute ECDH shared secret
	sharedSecret, err := computeSharedSecret(req.RequesterPrivateKey, req.SenderPublicKey)
	if err != nil {
		return nil, fmt.Errorf("compute shared secret: %w", err)
	}

	// Derive AES key via HKDF-SHA256
	aesKey, err := deriveAESKey(sharedSecret, salt)
	if err != nil {
		return nil, fmt.Errorf("derive AES key: %w", err)
	}

	// Decode base64 ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(req.EncryptedData)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted data: %w", err)
	}

	// Decrypt with AES-256-GCM
	plaintext, err := aesGCMDecrypt(aesKey, iv, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decrypt: %w", err)
	}

	return &DecryptionResponse{
		DecryptedData: string(plaintext),
	}, nil
}
