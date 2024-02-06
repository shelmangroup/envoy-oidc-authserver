package session

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/grokify/go-pkce"

	pb "github.com/shelmangroup/envoy-oidc-authserver/internal/gen/session/v1"
)

func NewSessionData() *pb.SessionData {

	// Create a code_verifier with default 32 byte length.
	codeVerifier, _ := pkce.NewCodeVerifier(-1)
	// Create a code_challenge using `S256`
	codeChallenge := pkce.CodeChallengeS256(codeVerifier)

	return &pb.SessionData{
		CodeVerifier:  codeVerifier,
		CodeChallenge: codeChallenge,
	}
}

func GenerateSessionToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
