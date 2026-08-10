package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// CredentialCipher encrypts/decrypts secrets stored at rest
// (idp_oidc_configs.client_secret_encrypted) with AES-256-GCM. The key
// comes from the CREDENTIAL_ENCRYPTION_KEY env var: 32 raw bytes,
// base64-encoded, generated once per environment (e.g. `openssl rand
// -base64 32`) and never committed.
type CredentialCipher struct {
	gcm cipher.AEAD
}

func NewCredentialCipher(base64Key string) (*CredentialCipher, error) {
	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, fmt.Errorf("credential encryption key must be base64: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("credential encryption key must decode to 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &CredentialCipher{gcm: gcm}, nil
}

// Encrypt returns a base64-encoded nonce||ciphertext blob suitable for
// storing directly in a text column.
func (c *CredentialCipher) Encrypt(plaintext string) (string, error) {
	nonce := make([]byte, c.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := c.gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (c *CredentialCipher) Decrypt(encoded string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	nonceSize := c.gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("storage: ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := c.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
