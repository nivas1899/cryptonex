package vault

import (
	"crypto/aes"
	"crypto/cipher"
)

// Card data at rest — AES-256-GCM (quantum-safe symmetric).
func Seal(key, plaintext, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key) // 256-bit key from KMS
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, nil), nil
}
