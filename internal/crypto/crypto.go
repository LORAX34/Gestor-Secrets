package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	keyLen   = 32
	nonceLen = 12
)

var (
	ErrInvalidKey = errors.New("crypto: invalid key")
)

// Argon2Params holds the KDF parameters. Serialized to JSON in the meta table.
type Argon2Params struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
	KeyLen  uint32 `json:"key_len"`
}

// DefaultParams returns sane defaults for an interactive CLI.
func DefaultParams() Argon2Params {
	return Argon2Params{Time: 3, Memory: 64 * 1024, Threads: 2, KeyLen: keyLen}
}

// RandomBytes returns n cryptographically random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// DeriveKey derives a Key Encryption Key (KEK) from the master password.
func DeriveKey(password string, salt []byte, p Argon2Params) []byte {
	return argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
}

// Seal encrypts plaintext with the given key (AES-256-GCM). Output: nonce||ciphertext.
func Seal(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, err := RandomBytes(gcm.NonceSize())
	if err != nil {
		return nil, err
	}
	out := gcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, out...), nil
}

// Open decrypts data formatted as nonce||ciphertext.
func Open(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, ErrInvalidKey
	}
	nonce, ct := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

// NewVaultKey generates a fresh random vault key.
func NewVaultKey() ([]byte, error) {
	return RandomBytes(keyLen)
}

// WrapKey seals the vault key with the KEK so it can be stored alongside data.
func WrapKey(vaultKey, kek []byte) ([]byte, error) {
	return Seal(vaultKey, kek)
}

// UnwrapKey restores the vault key using the KEK.
func UnwrapKey(wrapped, kek []byte) ([]byte, error) {
	return Open(wrapped, kek)
}

// NewToken generates a random API token, base64url encoded (no padding).
func NewToken() (string, error) {
	b, err := RandomBytes(32)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken hashes a token for storage using SHA-256.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", h)
}

// EncodeParams serializes KDF params to JSON.
func EncodeParams(p Argon2Params) (string, error) {
	b, err := json.Marshal(p)
	return string(b), err
}

// DecodeParams parses KDF params from JSON.
func DecodeParams(s string) (Argon2Params, error) {
	var p Argon2Params
	if err := json.Unmarshal([]byte(s), &p); err != nil {
		return p, err
	}
	if p.KeyLen == 0 {
		p.KeyLen = keyLen
	}
	return p, nil
}
