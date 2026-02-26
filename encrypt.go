package abdmecdh

import (
	"encoding/base64"
	"fmt"
)

// EncryptionRequest holds the parameters for encryption.
type EncryptionRequest struct {
	StringToEncrypt    string `json:"stringToEncrypt"`
	SenderNonce        string `json:"senderNonce"`
	RequesterNonce     string `json:"requesterNonce"`
	SenderPrivateKey   string `json:"senderPrivateKey"`
	RequesterPublicKey string `json:"requesterPublicKey"`
}

// EncryptionResponse holds the encrypted output.
type EncryptionResponse struct {
	EncryptedData string `json:"encryptedData"`
}

// Encrypt encrypts a string using ECDH + HKDF + AES-256-GCM.
func Encrypt(req EncryptionRequest) (*EncryptionResponse, error) {
	// Derive IV and salt from XOR of nonces
	iv, salt, err := deriveIVAndSalt(req.SenderNonce, req.RequesterNonce)
	if err != nil {
		return nil, fmt.Errorf("derive IV and salt: %w", err)
	}

	// Compute ECDH shared secret
	sharedSecret, err := computeSharedSecret(req.SenderPrivateKey, req.RequesterPublicKey)
	if err != nil {
		return nil, fmt.Errorf("compute shared secret: %w", err)
	}

	// Derive AES key via HKDF-SHA256
	aesKey, err := deriveAESKey(sharedSecret, salt)
	if err != nil {
		return nil, fmt.Errorf("derive AES key: %w", err)
	}

	// Encrypt with AES-256-GCM
	ciphertext, err := aesGCMEncrypt(aesKey, iv, []byte(req.StringToEncrypt))
	if err != nil {
		return nil, fmt.Errorf("AES-GCM encrypt: %w", err)
	}

	return &EncryptionResponse{
		EncryptedData: base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}
