package store

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStore(t *testing.T) {
	inmemStore := NewStore(&url.URL{}, 0)
	require.NotNil(t, inmemStore)
	u, err := url.Parse("redis://redis:password@myredis/0")
	require.NoError(t, err)
	redisStore := NewStore(u, 0)
	require.NotNil(t, redisStore)

	u, err = url.Parse("asdf:///0")
	require.NoError(t, err)
	assert.Panics(t, func() { NewStore(u, 0) })
}
