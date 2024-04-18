package session

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGenerateSessionToken(t *testing.T) {
	secret := sha256.Sum256([]byte("my_secret"))
	invalidSecret := sha256.Sum256([]byte("my_secret2"))
	s, err := GenerateSessionToken(context.Background(), secret)
	assert.NoError(t, err)
	assert.NotEmpty(t, s)
	token, err := VerifySessionToken(context.Background(), s, secret, 10*time.Second)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// wrong secret
	_, err = VerifySessionToken(context.Background(), s, invalidSecret, 10*time.Second)
	assert.Error(t, err)

	// invalid token
	_, err = VerifySessionToken(context.Background(), "invalid", secret, 10*time.Second)
	assert.Error(t, err)
}
