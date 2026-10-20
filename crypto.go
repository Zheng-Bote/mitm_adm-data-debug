package main

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"golang.org/x/crypto/argon2"
)

// Parameters of the password based file encryption. They must match
// mitm_maintenance_config/crypto, which produces the encrypted .enc files this
// tool reads: salt (16) || nonce (12) || AES-256-GCM ciphertext, key derived
// with Argon2id.
const (
	argonTime      = 3
	argonMemory    = 64 * 1024 // 64 MiB
	argonThreads   = 1
	argonKeyLength = 32
	configSaltLen  = 16
	configNonceLen = 12
)

// DecryptAESGCM decrypts a password protected blob in the format used by
// mitm_maintenance_config for encrypted configuration files.
func DecryptAESGCM(data, password []byte) ([]byte, error) {
	if len(data) < configSaltLen+configNonceLen {
		return nil, errors.New("encrypted data too short")
	}

	salt := data[:configSaltLen]
	nonce := data[configSaltLen : configSaltLen+configNonceLen]
	ciphertext := data[configSaltLen+configNonceLen:]

	key := argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, argonKeyLength)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, nonce, ciphertext, nil)
}

// EnvelopeDecrypt decrypts a payload using a wrapped DEK and a KEK
func EnvelopeDecrypt(kek []byte, wrappedKey []byte, payloadNonce []byte, payload []byte) ([]byte, error) {
	if len(kek) != 32 {
		adjusted := make([]byte, 32)
		copy(adjusted, kek)
		kek = adjusted
	}

	if len(wrappedKey) < 12 {
		return nil, errors.New("wrapped DEK too short")
	}
	dekNonce := wrappedKey[:12]
	wrappedCipher := wrappedKey[12:]

	kekBlock, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	kekGCM, err := cipher.NewGCM(kekBlock)
	if err != nil {
		return nil, err
	}
	dek, err := kekGCM.Open(nil, dekNonce, wrappedCipher, nil)
	if err != nil {
		return nil, errors.New("failed to decrypt DEK")
	}

	dekBlock, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	dekGCM, err := cipher.NewGCM(dekBlock)
	if err != nil {
		return nil, err
	}
	return dekGCM.Open(nil, payloadNonce, payload, nil)
}
