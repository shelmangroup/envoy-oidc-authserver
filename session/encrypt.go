package session

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"errors"

	"golang.org/x/crypto/nacl/secretbox"
)

var (
	errTokenTooLong = errors.New("token too long")
	errInvalidToken = errors.New("invalid token")
)

func EncodeToken(ctx context.Context, key [32]byte, sessionData *SessionData) (string, error) {

	// Is this safe???
	// message := (*[sessionDataSize]byte)(unsafe.Pointer(sessionData))[:]

	var message bytes.Buffer
	if err := gob.NewEncoder(&message).Encode(sessionData); err != nil {
		return "", err
	}

	var nonce [24]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		return "", err
	}

	box := secretbox.Seal(nonce[:], message.Bytes(), &nonce, &key)

	token := base64.RawURLEncoding.EncodeToString(box)
	if len(token) > 4096 {
		return "", errTokenTooLong
	}

	return token, nil
}

func DecodeToken(ctx context.Context, key [32]byte, token string) (*SessionData, error) {
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

	// sessionData = (*session.SessionData)(unsafe.Pointer(&dec[0]))
	var sessionData *SessionData
	r := bytes.NewReader(message)
	if err := gob.NewDecoder(r).Decode(&sessionData); err != nil {
		return nil, err
	}
	return sessionData, nil
}
