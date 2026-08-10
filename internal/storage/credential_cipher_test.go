package storage

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func testEncryptionKey(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(key)
}

func TestCredentialCipher_EncryptDecryptRoundTrip(t *testing.T) {
	c, err := NewCredentialCipher(testEncryptionKey(t))
	if err != nil {
		t.Fatalf("NewCredentialCipher: %v", err)
	}

	ciphertext, err := c.Encrypt("super-secret-value")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if strings.Contains(ciphertext, "super-secret-value") {
		t.Fatalf("expected the plaintext not to appear verbatim in the ciphertext")
	}

	plaintext, err := c.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if plaintext != "super-secret-value" {
		t.Fatalf("expected round-trip to recover the original plaintext, got %q", plaintext)
	}
}

func TestCredentialCipher_EncryptIsNonDeterministic(t *testing.T) {
	c, err := NewCredentialCipher(testEncryptionKey(t))
	if err != nil {
		t.Fatalf("NewCredentialCipher: %v", err)
	}

	a, err := c.Encrypt("same-value")
	if err != nil {
		t.Fatalf("Encrypt (a): %v", err)
	}
	b, err := c.Encrypt("same-value")
	if err != nil {
		t.Fatalf("Encrypt (b): %v", err)
	}
	// 毎回ランダムなnonceを使うため、同じ平文でも暗号文は一致しない
	// (パターン分析対策)。
	if a == b {
		t.Fatalf("expected two encryptions of the same plaintext to differ, got identical ciphertexts")
	}
}

func TestCredentialCipher_DecryptRejectsTamperedCiphertext(t *testing.T) {
	c, err := NewCredentialCipher(testEncryptionKey(t))
	if err != nil {
		t.Fatalf("NewCredentialCipher: %v", err)
	}

	ciphertext, err := c.Encrypt("secret")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	raw[len(raw)-1] ^= 0xFF // 末尾1バイトを反転させ改ざんを模擬する
	tampered := base64.StdEncoding.EncodeToString(raw)

	if _, err := c.Decrypt(tampered); err == nil {
		t.Fatalf("expected decryption of a tampered ciphertext to fail (GCM auth tag)")
	}
}

func TestCredentialCipher_DecryptWithWrongKeyFails(t *testing.T) {
	c1, err := NewCredentialCipher(testEncryptionKey(t))
	if err != nil {
		t.Fatalf("NewCredentialCipher (1): %v", err)
	}
	c2, err := NewCredentialCipher(testEncryptionKey(t))
	if err != nil {
		t.Fatalf("NewCredentialCipher (2): %v", err)
	}

	ciphertext, err := c1.Encrypt("secret")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := c2.Decrypt(ciphertext); err == nil {
		t.Fatalf("expected decryption with a different key to fail")
	}
}

func TestNewCredentialCipher_RejectsWrongKeyLength(t *testing.T) {
	shortKey := base64.StdEncoding.EncodeToString([]byte("too-short"))
	if _, err := NewCredentialCipher(shortKey); err == nil {
		t.Fatalf("expected a non-32-byte key to be rejected")
	}
}

func TestNewCredentialCipher_RejectsNonBase64Key(t *testing.T) {
	if _, err := NewCredentialCipher("not base64!!"); err == nil {
		t.Fatalf("expected a non-base64 key to be rejected")
	}
}
