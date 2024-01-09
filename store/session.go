package store

import (
	"context"
	"time"
)

type SessionStore struct {
	store    Store
	Lifetime time.Duration
	// Implement next level of store?
	// nextStore Store,
}

func NewSessionStore(store Store, lifetime time.Duration) *SessionStore {
	if lifetime == 0 {
		lifetime = 24 * time.Hour
	}

	if store == nil {
		store = NewMemStore()
	}

	return &SessionStore{
		store:    store,
		Lifetime: lifetime,
	}
}

func (s *SessionStore) Get(ctx context.Context, token string) ([]byte, bool, error) {
	return s.store.Get(token)
}

func (s *SessionStore) Set(ctx context.Context, token string, b []byte) error {
	return s.store.Set(token, b, time.Now().Add(s.Lifetime))
}

func (s *SessionStore) Delete(ctx context.Context, token string) error {
	return s.store.Delete(token)
}
