package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test OIDCProvider
func TestOIDCProvider(t *testing.T) {
	_, err := NewOIDCProvider("", "", "", "", nil)
	assert.Error(t, err)
}
