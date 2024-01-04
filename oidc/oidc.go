package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptrace"
	"time"

	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"go.opentelemetry.io/contrib/instrumentation/net/http/httptrace/otelhttptrace"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

type OIDCProvider struct {
	provider rp.RelyingParty
}

// NewOIDCProvider creates a new oidc provider
func NewOIDCProvider(ctx context.Context, clientID, clientSecret, redirectURI, issuer string, scopes []string) (*OIDCProvider, error) {
	client := &http.Client{
		Timeout: time.Second * 5,
		Transport: otelhttp.NewTransport(
			http.DefaultTransport,
			otelhttp.WithClientTrace(func(ctx context.Context) *httptrace.ClientTrace {
				return otelhttptrace.NewClientTrace(ctx)
			}),
		),
	}

	//FIXME: This is not secure, but it is a test
	key := []byte("test1234test1234")
	cookieHandler := httphelper.NewCookieHandler(key, key, httphelper.WithUnsecure())

	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
		rp.WithHTTPClient(client),
		// rp.WithLogger(logger),
	}
	if clientSecret == "" {
		options = append(options, rp.WithPKCE(cookieHandler))
	}

	provider, err := rp.NewRelyingPartyOIDC(ctx, issuer, clientID, clientSecret, redirectURI, scopes, options...)
	if err != nil {
		return nil, err
	}

	return &OIDCProvider{provider: provider}, nil
}

// IdpAuthURL returns the url to redirect the user for authentication
func (o *OIDCProvider) IdpAuthURL() string {
	state := uuid.New().String()
	return rp.AuthURL(state, o.provider)
}

// RetriveTokens retrieves the tokens from the idp callback redirect and returns them
// `code` is the `code` query parameter from the idp callback redirect
func (o *OIDCProvider) RetriveTokens(ctx context.Context, code string) (*oidc.Tokens[*oidc.IDTokenClaims], error) {
	tokens, err := rp.CodeExchange[*oidc.IDTokenClaims](ctx, code, o.provider)
	if err != nil {
		return nil, err
	}

	if !tokens.Valid() {
		return nil, errors.New("invalid token")
	}

	return tokens, nil
}

// RefreshTokens refreshes the tokens and returns them
// clientAssertion is the client assertion jwt (tokens.AccessToken)
func (o *OIDCProvider) RefreshTokens(ctx context.Context, refreshToken, clientAssertion string) (*oidc.Tokens[*oidc.IDTokenClaims], error) {
	tokens, err := rp.RefreshTokens[*oidc.IDTokenClaims](ctx, o.provider, refreshToken, clientAssertion, oidc.ClientAssertionTypeJWTAssertion)
	if err != nil {
		return nil, err
	}
	return tokens, nil
}
