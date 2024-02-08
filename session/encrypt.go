package session

import (
	"context"
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/nacl/secretbox"
	"google.golang.org/protobuf/proto"

	pb "github.com/shelmangroup/envoy-oidc-authserver/internal/gen/session/v1"
)

var (
	errInvalidToken = errors.New("invalid token")
)

func EncodeToken(ctx context.Context, key [32]byte, sessionData *pb.SessionData) ([]byte, error) {
	message, err := proto.Marshal(sessionData)
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	_, err = rand.Read(nonce[:])
	if err != nil {
		return nil, err
	}

	box := secretbox.Seal(nonce[:], message, &nonce, &key)

	return box, nil
}

func DecodeToken(ctx context.Context, key [32]byte, box []byte) (*pb.SessionData, error) {
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
