package abdmecdh

// ECDH defines the interface for ABDM ECDH key generation, encryption, and decryption.
type ECDH interface {
	GenerateKeyMaterial() (*KeyMaterial, error)
	Encrypt(req EncryptionRequest) (*EncryptionResponse, error)
	Decrypt(req DecryptionRequest) (*DecryptionResponse, error)
}

type ecdh struct{}

// New returns a new ECDH instance.
func New() ECDH {
	return &ecdh{}
}

func (e *ecdh) GenerateKeyMaterial() (*KeyMaterial, error) {
	return GenerateKeyMaterial()
}

func (e *ecdh) Encrypt(req EncryptionRequest) (*EncryptionResponse, error) {
	return Encrypt(req)
}

func (e *ecdh) Decrypt(req DecryptionRequest) (*DecryptionResponse, error) {
	return Decrypt(req)
}
