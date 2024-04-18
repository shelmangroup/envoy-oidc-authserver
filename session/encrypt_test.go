package session

import (
	"context"
	"crypto/sha256"
	"testing"

	pb "github.com/shelmangroup/envoy-oidc-authserver/internal/gen/session/v1"
	"github.com/stretchr/testify/assert"
)

// Test EncryptSession
func TestEncryptDecryptSession(t *testing.T) {
	// convert to 32 byte array
	key := sha256.Sum256([]byte("my_secret"))

	// faulty key
	faultyKey := sha256.Sum256([]byte("my_secret2"))

	buf, err := EncryptSession(context.Background(), key, &pb.SessionData{})
	assert.Nil(t, err)
	assert.NotNil(t, buf)

	s, err := DecryptSession(context.Background(), key, buf)
	assert.Nil(t, err)
	assert.NotNil(t, s)

	// faulty key
	s, err = DecryptSession(context.Background(), faultyKey, buf)
	assert.Error(t, err)
	assert.Nil(t, s)

	// faulty box length
	_, err = DecryptSession(context.Background(), key, []byte("too short"))
	assert.Error(t, err)
}
