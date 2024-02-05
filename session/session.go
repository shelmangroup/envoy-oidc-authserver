package session

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/grokify/go-pkce"
)

type SessionData struct {
	RequestedURL string

	CodeVerifier  string
	CodeChallenge string

	SourceIP     string
	AccessToken  string
	RefreshToken string
	IDToken      string
	Expiry       time.Time
}

func NewSessionData() *SessionData {

	// Create a code_verifier with default 32 byte length.
	codeVerifier, _ := pkce.NewCodeVerifier(-1)
	// Create a code_challenge using `S256`
	codeChallenge := pkce.CodeChallengeS256(codeVerifier)

	return &SessionData{
		CodeVerifier:  codeVerifier,
		CodeChallenge: codeChallenge,
	}
}

func (s *SessionData) GetRequestedURL() string {
	if s == nil {
		s = &SessionData{}
	}
	return s.RequestedURL
}

func (s *SessionData) SetRequestedURL(requestedURL string) {
	s.RequestedURL = requestedURL
}

func GenerateSessionToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
