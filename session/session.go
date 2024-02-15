package session

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/fernet/fernet-go"
	"github.com/grokify/go-pkce"
	"go.opentelemetry.io/otel/codes"

	pb "github.com/shelmangroup/envoy-oidc-authserver/internal/gen/session/v1"
)

func NewSessionData() *pb.SessionData {
	return &pb.SessionData{}
}

func GenerateSessionToken(ctx context.Context, secret []byte) (string, error) {
	_, span := tracer.Start(ctx, "GenerateSessionToken")
	defer span.End()

	// Create a code_verifier with default 32 byte length.
	codeVerifier, err := pkce.NewCodeVerifier(-1)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", err
	}
	codeChallenge := pkce.CodeChallengeS256(codeVerifier)

	// concat codeVerifier and codeChallenge (both are 43 bytes long)
	msg := []byte(codeVerifier + codeChallenge)

	key := new(fernet.Key)
	copy(key[:], secret)
	token, err := fernet.EncryptAndSign(msg, key)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", err
	}

	span.SetStatus(codes.Ok, "success")
	return base64.RawURLEncoding.EncodeToString(token), nil
}

func VerifySessionToken(ctx context.Context, token string, secret []byte, ttl time.Duration) (string, error) {
	_, span := tracer.Start(ctx, "VerifySessionToken")
	defer span.End()

	t, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", err
	}

	key := new(fernet.Key)
	copy(key[:], secret)
	msg := fernet.VerifyAndDecrypt([]byte(t), ttl, []*fernet.Key{key})
	if msg == nil {
		span.RecordError(errInvalidOrExpired)
		span.SetStatus(codes.Error, errInvalidOrExpired.Error())
		return "", errInvalidOrExpired
	}

	span.SetStatus(codes.Ok, "success")
	return string(msg), nil
}
