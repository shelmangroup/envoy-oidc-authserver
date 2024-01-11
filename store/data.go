package store

import (
	"time"
)

// TODO: replace with ProtoBuf
type SessionData struct {
	RequestedURL string
	Tokens       *Tokens
}

type Tokens struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	Expiry       time.Time
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