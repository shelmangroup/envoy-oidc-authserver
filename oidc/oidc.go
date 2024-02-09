package oidc

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptrace"
	"time"

	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"go.opentelemetry.io/contrib/instrumentation/net/http/httptrace/otelhttptrace"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// Create auth provicer interface
type UnimplementedAuthProvider interface {
	IdpAuthURL(codeChallenge string) string
	RetriveTokens(ctx context.Context, code, codeVerifier string) (*oidc.Tokens[*oidc.IDTokenClaims], error)
	RefreshTokens(ctx context.Context, refreshToken, clientAssertion string) (*oidc.Tokens[*oidc.IDTokenClaims], error)
	VerifyTokens(ctx context.Context, accessToken, idToken string) (bool, error)
}

type OIDCProvider struct {
	UnimplementedAuthProvider

	provider rp.RelyingParty
	isPKCE   bool
}

// NewOIDCProvider creates a new oidc provider
func NewOIDCProvider(clientID, clientSecret, redirectURI, issuer string, scopes []string) (*OIDCProvider, error) {
	ctx := context.Background()
	var pkce bool

	client := &http.Client{
		Timeout: time.Second * 5,
		Transport: otelhttp.NewTransport(
			http.DefaultTransport,
			otelhttp.WithClientTrace(func(ctx context.Context) *httptrace.ClientTrace {
				return otelhttptrace.NewClientTrace(ctx)
			}),
		),
	}

	options := []rp.Option{
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
		rp.WithHTTPClient(client),
	}

	if clientSecret == "" {
		pkce = true
	}

	provider, err := rp.NewRelyingPartyOIDC(ctx, issuer, clientID, clientSecret, redirectURI, scopes, options...)
	if err != nil {
		return nil, err
	}

	return &OIDCProvider{provider: provider, isPKCE: pkce}, nil
}

// IdpAuthURL returns the url to redirect the user for authentication
func (o *OIDCProvider) IdpAuthURL(codeChallenge string) string {
	state := uuid.New().String()
	var opts []rp.AuthURLOpt
	if o.isPKCE {
		opts = append(opts, rp.WithCodeChallenge(codeChallenge))
	}
	return rp.AuthURL(state, o.provider, opts...)
}

func (o *OIDCProvider) VerifyTokens(ctx context.Context, accessToken, idToken string) (bool, error) {
	var expired bool
	_, err := rp.VerifyTokens[*oidc.IDTokenClaims](ctx, accessToken, idToken, o.provider.IDTokenVerifier())
	if err != nil {
		if err == oidc.ErrExpired {
			expired = true
		} else {
			return false, err
		}
	}
	return expired, nil
}

// RetriveTokens retrieves the tokens from the idp callback redirect and returns them
// `code` is the `code` query parameter from the idp callback redirect
func (o *OIDCProvider) RetriveTokens(ctx context.Context, code, codeVerifier string) (*oidc.Tokens[*oidc.IDTokenClaims], error) {
	slog.Debug("retriving tokens", slog.String("authorization_code", code), slog.String("code_verifier", codeVerifier))
	var opts []rp.CodeExchangeOpt

	if o.isPKCE {
		slog.Debug("provider is PKCE")
		opts = append(opts, rp.WithCodeVerifier(codeVerifier))
	}

	tokens, err := rp.CodeExchange[*oidc.IDTokenClaims](ctx, code, o.provider, opts...)
	if err != nil {
		slog.Error("retriving token", slog.String("err", err.Error()))
		return nil, err
	}

	if !tokens.Valid() {
		return nil, errors.New("RetriveTokens: invalid token")
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
	if !tokens.Valid() {
		return nil, errors.New("RefreshTokens: invalid token")
	}
	return tokens, nil
}
