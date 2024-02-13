package session

import (
	"context"
	"crypto/rand"
	"errors"

	"go.opentelemetry.io/otel"
	"golang.org/x/crypto/nacl/secretbox"
	"google.golang.org/protobuf/proto"

	pb "github.com/shelmangroup/envoy-oidc-authserver/internal/gen/session/v1"
)

var (
	errInvalid = errors.New("invalid encrypted data")
	tracer     = otel.Tracer("session")
)

func EncryptSession(ctx context.Context, key [32]byte, sessionData *pb.SessionData) ([]byte, error) {
	_, span := tracer.Start(ctx, "EncryptSession")
	defer span.End()

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

func DecryptSession(ctx context.Context, key [32]byte, box []byte) (*pb.SessionData, error) {
	_, span := tracer.Start(ctx, "DecryptSession")
	defer span.End()
	if len(box) < 24 {
		return nil, errInvalid
	}

	var nonce [24]byte
	copy(nonce[:], box[:24])
	message, ok := secretbox.Open(nil, box[24:], &nonce, &key)
	if !ok {
		return nil, errInvalid
	}

	sessionData := &pb.SessionData{}
	if err := proto.Unmarshal(message, sessionData); err != nil {
		return nil, err
	}
	return sessionData, nil
}
