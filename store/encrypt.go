package store

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/nacl/secretbox"
)

var (
	errTokenTooLong = errors.New("token too long")
	errInvalidToken = errors.New("invalid token")
)

func EncodeToken(key [32]byte, message []byte) (string, error) {
	var nonce [24]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		return "", err
	}

	box := secretbox.Seal(nonce[:], message, &nonce, &key)

	token := base64.RawURLEncoding.EncodeToString(box)
	if len(token) > 4096 {
		return "", errTokenTooLong
	}

	return token, nil
}

func DecodeToken(key [32]byte, token string) ([]byte, error) {
	box, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, errInvalidToken
	}
	if len(box) < 24 {
		return nil, errInvalidToken
	}

	var nonce [24]byte
	copy(nonce[:], box[:24])
	message, ok := secretbox.Open(nil, box[24:], &nonce, &key)
	if !ok {
		return nil, errInvalidToken
	}

	return message[:], nil
}
