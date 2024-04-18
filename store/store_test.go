package store

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewStore(t *testing.T) {
	inmemStore := NewStore(nil, 0)
	require.NotNil(t, inmemStore)
	redisStore := NewStore([]string{"127.0.0.1:6379"}, 0)
	require.NotNil(t, redisStore)
}
