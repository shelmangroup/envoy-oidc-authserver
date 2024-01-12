package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"time"
)

// TODO: support encryption of session data

type SessionStore struct {
	store    Store
	Lifetime time.Duration
	// TODO: Implement next level of store?
	// nextStore Store,
}

func NewSessionStore(store Store, lifetime time.Duration) *SessionStore {
	if lifetime == 0 {
		lifetime = 24 * time.Hour
	}

	if store == nil {
		store = NewWithCleanupInterval(10 * time.Minute)
	}

	return &SessionStore{
		store:    store,
		Lifetime: lifetime,
	}
}

func (s *SessionStore) Get(ctx context.Context, token string) (*SessionData, bool, error) {
	b, found, err := s.store.Get(token)
	if err != nil {
		return nil, false, err
	}
	if !found {
		return &SessionData{}, false, nil
	}
	d := &SessionData{}
	r := bytes.NewReader(b)
	// FIXME: use protobuf instead of gob
	if err := gob.NewDecoder(r).Decode(d); err != nil {
		return nil, false, err
	}
	return d, found, nil
}

func (s *SessionStore) Set(ctx context.Context, token string, d *SessionData) error {
	//gob encode struct
	var b bytes.Buffer
	if err := gob.NewEncoder(&b).Encode(d); err != nil {
		return err
	}
	return s.store.Set(token, b.Bytes(), time.Now().Add(s.Lifetime))
}

func (s *SessionStore) Delete(ctx context.Context, token string) error {
	return s.store.Delete(token)
}

func GenerateSessionToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
