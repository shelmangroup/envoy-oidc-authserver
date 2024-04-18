package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test OIDCProvider
func TestOIDCProvider(t *testing.T) {
	_, err := NewOIDCProvider("", "", "", "", nil)
	assert.Error(t, err)

	// test google provider
	p, err := NewOIDCProvider("client_id", "client_secret", "http://localhost:8080", "https://accounts.google.com", []string{"email", "profile"})
	assert.NotNil(t, p)
	assert.Nil(t, err)

	url := p.IdpAuthURL("code_challenge123")
	assert.NotEmpty(t, url)
}
