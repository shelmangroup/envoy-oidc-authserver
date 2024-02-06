package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/nacl/secretbox"
	"google.golang.org/protobuf/proto"

	pb "github.com/shelmangroup/envoy-oidc-authserver/internal/gen/session/v1"
)

var (
	errTokenTooLong = errors.New("token too long")
	errInvalidToken = errors.New("invalid token")
)

func EncodeToken(ctx context.Context, key [32]byte, sessionData *pb.SessionData) (string, error) {

	message, err := proto.Marshal(sessionData)
	if err != nil {
		return "", err
	}

	var nonce [24]byte
	_, err = rand.Read(nonce[:])
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

func DecodeToken(ctx context.Context, key [32]byte, token string) (*pb.SessionData, error) {
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

	sessionData := &pb.SessionData{}
	if err := proto.Unmarshal(message, sessionData); err != nil {
		return nil, err
	}
	return sessionData, nil
}
