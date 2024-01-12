package store

import (
	"time"

	"github.com/grokify/go-pkce"
)

// TODO: replace with ProtoBuf
type SessionData struct {
	RequestedURL string
	Tokens       *Tokens

	CodeVerifier  string
	CodeChallenge string
}

type Tokens struct {
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

func (s *SessionData) GetTokens() *Tokens {
	if s == nil {
		s = &SessionData{}
	}
	return s.Tokens
}

func (s *SessionData) SetRequestedURL(requestedURL string) {
	s.RequestedURL = requestedURL
}

func (s *SessionData) SetTokens(t *Tokens) {
	s.Tokens = t
}
