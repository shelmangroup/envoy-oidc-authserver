package oidc

import (
	"context"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
)

type OIDCMockProvider struct {
	UnimplementedAuthProvider
}

// NewOIDCProvider creates a new oidc provider
func NewOIDCMockProvider(clientID, clientSecret, redirectURI, issuer string, scopes []string) (*OIDCMockProvider, error) {
	return &OIDCMockProvider{}, nil
}

// IdpAuthURL returns the url to redirect the user for authentication
func (o *OIDCMockProvider) IdpAuthURL(codeChallenge string) string {
	return "http://mock.idp/auth"
}

// RetriveTokens retrieves the tokens from the idp callback redirect and returns them
// `code` is the `code` query parameter from the idp callback redirect
func (o *OIDCMockProvider) RetriveTokens(ctx context.Context, code, codeVerifier string) (*oidc.Tokens[*oidc.IDTokenClaims], error) {
	return &oidc.Tokens[*oidc.IDTokenClaims]{
		Token: &oauth2.Token{
			AccessToken:  "foo",
			RefreshToken: "bar",
			Expiry:       time.Now().Add(1 * time.Hour),
		},
		IDToken: "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTA2MTI5MDIyfQ",
	}, nil
}

func (o *OIDCMockProvider) VerifyTokens(ctx context.Context, accessToken, idTokeb string) (bool, error) {
	return false, nil
}

// RefreshTokens refreshes the tokens and returns them
// clientAssertion is the client assertion jwt (tokens.AccessToken)
func (o *OIDCMockProvider) RefreshTokens(ctx context.Context, refreshToken, clientAssertion string) (*oidc.Tokens[*oidc.IDTokenClaims], error) {
	return &oidc.Tokens[*oidc.IDTokenClaims]{
		Token: &oauth2.Token{
			AccessToken:  "foo",
			RefreshToken: "bar",
			Expiry:       time.Now().Add(2 * time.Hour),
		},
		IDToken: "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaW1111111111111111asda",
	}, nil
}
