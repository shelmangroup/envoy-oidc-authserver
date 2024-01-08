package oidc

import (
	"context"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type OIDCMockProvider struct {
	UnimplementedAuthProvider
}

// NewOIDCProvider creates a new oidc provider
func NewOIDCMockProvider(clientID, clientSecret, redirectURI, issuer string, scopes []string) (*OIDCMockProvider, error) {
	return &OIDCMockProvider{}, nil
}

// IdpAuthURL returns the url to redirect the user for authentication
func (o *OIDCMockProvider) IdpAuthURL() string {
	return "http://mock.idp/auth"
}

// RetriveTokens retrieves the tokens from the idp callback redirect and returns them
// `code` is the `code` query parameter from the idp callback redirect
func (o *OIDCMockProvider) RetriveTokens(ctx context.Context, code string) (*oidc.Tokens[*oidc.IDTokenClaims], error) {
	return &oidc.Tokens[*oidc.IDTokenClaims]{
		IDToken: "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTA2MTI5MDIyfQ",
	}, nil
}

// RefreshTokens refreshes the tokens and returns them
// clientAssertion is the client assertion jwt (tokens.AccessToken)
func (o *OIDCMockProvider) RefreshTokens(ctx context.Context, refreshToken, clientAssertion string) (*oidc.Tokens[*oidc.IDTokenClaims], error) {
	return &oidc.Tokens[*oidc.IDTokenClaims]{}, nil
}
