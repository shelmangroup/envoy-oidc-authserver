package oidc

import (
	"context"
	"errors"
	"log/slog"
	"net/http/httptrace"
	"strings"
	"time"

	"github.com/google/uuid"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"go.opentelemetry.io/contrib/instrumentation/net/http/httptrace/otelhttptrace"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// Create auth provicer interface
type UnimplementedAuthProvider interface {
	IdpAuthURL(codeChallenge string) string
	RetrieveTokens(ctx context.Context, code, codeVerifier string) (*oidc.Tokens[*oidc.IDTokenClaims], error)
	RefreshTokens(ctx context.Context, refreshToken, clientAssertion string) (*oidc.Tokens[*oidc.IDTokenClaims], error)
	VerifyTokens(ctx context.Context, accessToken, idToken string) (bool, error)
}

type OIDCProvider struct {
	UnimplementedAuthProvider

	provider rp.RelyingParty
	isPKCE   bool
}

var tracer = otel.Tracer("oidc")

// NewOIDCProvider creates a new oidc provider
func NewOIDCProvider(clientID, clientSecret, redirectURI, issuer string, scopes []string) (*OIDCProvider, error) {
	ctx := context.Background()
	var pkce bool

	otelTransport := otelhttp.NewTransport(
		cleanhttp.DefaultPooledTransport(),
		otelhttp.WithClientTrace(func(ctx context.Context) *httptrace.ClientTrace {
			return otelhttptrace.NewClientTrace(ctx)
		}),
	)
	retryClient := retryablehttp.NewClient()
	retryClient.HTTPClient.Transport = otelTransport
	retryClient.Logger = slog.Default()
	// TODO: make this configurable
	retryClient.RetryMax = 10
	retryClient.RetryWaitMax = 8 * time.Second

	options := []rp.Option{
		rp.WithLogger(slog.Default()),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
		rp.WithHTTPClient(retryClient.StandardClient()),
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
	ctx, span := tracer.Start(ctx, "VerifyTokens")
	defer span.End()

	claims, err := rp.VerifyTokens[*oidc.IDTokenClaims](ctx, accessToken, idToken, o.provider.IDTokenVerifier())
	if err != nil {
		if err == oidc.ErrExpired {
			span.SetStatus(codes.Ok, "token expired")
			return true, nil
		} else {
			span.RecordError(err)
			span.SetStatus(codes.Error, "verify tokens failed")
			return false, err
		}
	}

	if span.IsRecording() {
		span.SetAttributes(
			semconv.EnduserID(claims.GetUserInfo().Email),
		)
	}

	span.AddEvent("log", trace.WithAttributes(
		attribute.Bool("expired", false),
		attribute.String("expire", claims.GetExpiration().String()),
		attribute.String("subject", claims.GetSubject()),
		attribute.String("audience", strings.Join(claims.GetAudience(), ","))),
	)

	span.SetStatus(codes.Ok, "successfully verified token")
	return false, nil
}

// RetrieveTokens retrieves the tokens from the idp callback redirect and returns them
// `code` is the `code` query parameter from the idp callback redirect
func (o *OIDCProvider) RetrieveTokens(ctx context.Context, code, codeVerifier string) (*oidc.Tokens[*oidc.IDTokenClaims], error) {
	ctx, span := tracer.Start(ctx, "RetrieveTokens")
	defer span.End()

	var opts []rp.CodeExchangeOpt

	if o.isPKCE {
		slog.Debug("provider is PKCE")
		opts = append(opts, rp.WithCodeVerifier(codeVerifier))
	}

	tokens, err := rp.CodeExchange[*oidc.IDTokenClaims](ctx, code, o.provider, opts...)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		slog.Error("retrieving token", slog.String("err", err.Error()))
		return nil, err
	}

	if !tokens.Valid() {
		span.RecordError(errors.New("RetrieveTokens: invalid token"))
		span.SetStatus(codes.Error, "RetrieveTokens: invalid token")
		return nil, errors.New("RetrieveTokens: invalid token")
	}

	span.AddEvent("log",
		trace.WithAttributes(
			attribute.String("issuer", tokens.IDTokenClaims.GetIssuer()),
			attribute.Bool("is_pkce", o.isPKCE),
			attribute.String("expire", tokens.IDTokenClaims.GetExpiration().String()),
			attribute.String("subject", tokens.IDTokenClaims.GetSubject()),
		),
	)

	span.SetStatus(codes.Ok, "success")
	return tokens, nil
}

// RefreshTokens refreshes the tokens and returns them
// clientAssertion is the client assertion jwt (tokens.AccessToken)
func (o *OIDCProvider) RefreshTokens(ctx context.Context, refreshToken, clientAssertion string) (*oidc.Tokens[*oidc.IDTokenClaims], error) {
	ctx, span := tracer.Start(ctx, "RefreshTokens")
	defer span.End()

	tokens, err := rp.RefreshTokens[*oidc.IDTokenClaims](ctx, o.provider, refreshToken, clientAssertion, oidc.ClientAssertionTypeJWTAssertion)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	if !tokens.Valid() {
		span.RecordError(errors.New("RefreshTokens: invalid token"))
		span.SetStatus(codes.Error, "RefreshTokens: invalid token")
		return nil, errors.New("RefreshTokens: invalid token")
	}
	span.AddEvent("log",
		trace.WithAttributes(
			attribute.String("issuer", tokens.IDTokenClaims.GetIssuer()),
			attribute.Bool("is_pkce", o.isPKCE),
			attribute.String("expire", tokens.IDTokenClaims.GetExpiration().String()),
			attribute.String("subject", tokens.IDTokenClaims.GetSubject()),
		),
	)
	span.SetStatus(codes.Ok, "success")
	return tokens, nil
}
