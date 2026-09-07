package main

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

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
