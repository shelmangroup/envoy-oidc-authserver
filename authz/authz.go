package authz

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"buf.build/gen/go/envoyproxy/envoy/connectrpc/go/envoy/service/auth/v3/authv3connect"
	core "buf.build/gen/go/envoyproxy/envoy/protocolbuffers/go/envoy/config/core/v3"
	auth "buf.build/gen/go/envoyproxy/envoy/protocolbuffers/go/envoy/service/auth/v3"
	envoy_type "buf.build/gen/go/envoyproxy/envoy/protocolbuffers/go/envoy/type/v3"
	"connectrpc.com/connect"
	"connectrpc.com/otelconnect"
	"github.com/gogo/googleapis/google/rpc"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"

	"github.com/shelmangroup/shelman-authz/store"
)

const ServiceName = "shelman-authz"

type Service struct {
	authv3connect.UnimplementedAuthorizationHandler

	cfg   *Config
	store *store.SessionStore
}

func NewService(cfg *Config, store *store.SessionStore) *Service {
	return &Service{
		cfg:   cfg,
		store: store,
	}
}

func (s *Service) NewHandler() (string, http.Handler) {
	return authv3connect.NewAuthorizationHandler(s, connect.WithInterceptors(otelconnect.NewInterceptor()))
}

func (s *Service) Name() string {
	return authv3connect.AuthorizationName
}

func (s *Service) Check(ctx context.Context, req *connect.Request[auth.CheckRequest]) (*connect.Response[auth.CheckResponse], error) {
	httpReq := req.Msg.GetAttributes().GetRequest().GetHttp()
	var resp *auth.CheckResponse
	var provider *OIDCProvider

	slog.Debug("client headers", slog.Any("headers", httpReq.GetHeaders()))
	for k, v := range httpReq.GetHeaders() {
		slog.Debug("matching headers", slog.String("key", k), slog.String("value", v))
		provider = s.cfg.Match(k, v)
		if provider != nil {
			break
		}
	}

	if provider == nil {
		slog.Debug("no header matches any provider")
		return nil, errors.New("no header matches any provider")
	}

	resp, err := s.process(ctx, httpReq, provider)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(resp), nil
}

func (s *Service) process(ctx context.Context, req *auth.AttributeContext_HttpRequest, provider *OIDCProvider) (*auth.CheckResponse, error) {
	var headers []*core.HeaderValueOption
	var sessionCookie *http.Cookie
	sessionData := &store.SessionData{}
	sessionCookieName := provider.CookieNamePrefix + "-" + ServiceName
	requestedURL := req.GetScheme() + "://" + req.GetHost() + req.GetPath()
	idpAuthURL := provider.p.IdpAuthURL()

	slog.Debug("requestedURL", slog.String("requestedURL", requestedURL))

	// check if cookie exists
	sessionCookie, found := s.getSessionCookie(req, sessionCookieName)
	if !found {
		headers, err := s.newSession(ctx, requestedURL, idpAuthURL, sessionCookieName, sessionData)
		if err != nil {
			return nil, err
		}
		// set downstream headers and redirect to Idp
		return s.response(false, envoy_type.StatusCode_Found, headers, "redirect to Idp"), nil
	}

	// get session data from store
	slog.Debug("getting session data from store", slog.String("session_id", sessionCookie.Value))
	sessionData, _, err := s.store.Get(ctx, sessionCookie.Value)
	if err != nil {
		return nil, err
	}

	if strings.HasPrefix(requestedURL, provider.CallbackURI+"?") {
		code, err := s.getCodeQueryParam(requestedURL)
		if err != nil {
			return nil, err
		}
		slog.Debug("retriving token", slog.String("authorization_code", code))
		tokens, err := provider.p.RetriveTokens(ctx, code)
		if err != nil {
			return nil, err
		}
		sessionData.SetTokens(
			&store.Tokens{
				RefreshToken: tokens.RefreshToken,
				AccessToken:  tokens.AccessToken,
				IDToken:      tokens.IDToken,
				Expiry:       tokens.Expiry,
			},
		)
		slog.Debug("successfully acquried tokens, now storing it to session store", slog.String("expire", tokens.Expiry.String()))
		err = s.store.Set(ctx, sessionCookie.Value, sessionData)
		if err != nil {
			return nil, err
		}

		// set downstream headers and redirect client to requested URL from session store
		slog.Debug("redirecting client to first requested URL", slog.String("url", sessionData.GetRequestedURL()))
		headers = append(headers, s.setRedirectHeader(sessionData.GetRequestedURL()))
		return s.response(false, envoy_type.StatusCode_Found, headers, "redirect to requested url"), nil
	}

	tokens := sessionData.GetTokens()
	if tokens == nil {
		slog.Debug("no tokens found in session data, redirecting to Idp")
		headers, err := s.newSession(ctx, requestedURL, idpAuthURL, sessionCookieName, sessionData)
		if err != nil {
			return nil, err
		}
		return s.response(false, envoy_type.StatusCode_Found, headers, "redirect to Idp"), nil
	}
	// slog.Debug("tokens", slog.String("id_token", tokens.IDToken), slog.String("access_token", tokens.AccessToken), slog.String("refresh_token", tokens.RefreshToken), slog.String("expire", tokens.Expiry.String()))
	newTokens, updated, err := s.validateToken(ctx, provider, tokens)
	if err != nil {
		return nil, err
	}
	if updated {
		// Update the session data with the new tokens
		slog.Debug("Token refreshed updating in store", slog.String("expire", newTokens.Expiry.String()))
		sessionData.SetTokens(newTokens)
		err = s.store.Set(ctx, sessionCookie.Value, sessionData)
		if err != nil {
			return nil, err
		}
		tokens = newTokens
	}

	headers = append(headers, s.setAuthorizationHeader(tokens.IDToken))
	slog.Debug("token ok, carry on!", slog.String("session_id", sessionCookie.Value))
	return s.response(true, envoy_type.StatusCode_OK, headers, "success"), nil
}

// Validates and poteintially refreshes the token
func (s *Service) validateToken(ctx context.Context, provider *OIDCProvider, tokens *store.Tokens) (*store.Tokens, bool, error) {
	//Validate token
	if tokens.AccessToken != "" && !expired(tokens.Expiry) {
		return tokens, false, nil
	}

	t, err := provider.p.RefreshTokens(ctx, tokens.RefreshToken, tokens.AccessToken)
	if err != nil {
		return nil, false, err
	}
	return &store.Tokens{
		RefreshToken: t.RefreshToken,
		AccessToken:  t.AccessToken,
		IDToken:      t.IDToken,
		Expiry:       t.Expiry,
	}, true, nil
}

// check if token is expired
func expired(expiry time.Time) bool {
	if expiry.IsZero() {
		return false
	}
	expiryDelta := 10 * time.Second
	return expiry.Round(0).Add(-expiryDelta).Before(time.Now())
}

func (s *Service) newSession(ctx context.Context, requestedURL, idpAuthURL, sessionCookieName string, sessionData *store.SessionData) ([]*core.HeaderValueOption, error) {
	slog.Debug("cookie not found, redirecting to Idp")
	var headers []*core.HeaderValueOption

	sessionCookieToken, err := store.GenerateSessionToken()
	if err != nil {
		return nil, err
	}
	slog.Debug("setting requested url", slog.String("requested_url", requestedURL))
	sessionData.SetRequestedURL(requestedURL)

	slog.Debug("saving to store")
	err = s.store.Set(ctx, sessionCookieToken, sessionData)
	if err != nil {
		return nil, err
	}

	headers = append(headers, s.setRedirectHeader(idpAuthURL))
	// set cookie with session id and redirect to Idp
	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionCookieToken,
		Path:     "/",
		HttpOnly: true,
		// Secure:   true,
		// SameSite: http.SameSiteLaxMode,
	}
	return append(headers, s.setCookie(cookie)...), nil
}

func (s *Service) getSessionCookie(req *auth.AttributeContext_HttpRequest, cookieName string) (*http.Cookie, bool) {
	for _, cookie := range s.getCookies(req) {
		if cookie.Name == cookieName {
			if cookie.Valid() == nil {
				slog.Debug("cookie is valid")
				return cookie, true
			}
		}
	}
	return nil, false
}

// parse cookie header string into []*http.Cookie struct
func (s *Service) getCookies(req *auth.AttributeContext_HttpRequest) []*http.Cookie {
	cookieRaw := req.GetHeaders()["cookie"]
	slog.Debug("cookieRaw", slog.String("cookieRaw", cookieRaw))
	header := http.Header{}
	header.Add("Cookie", cookieRaw)
	r := http.Request{Header: header}
	return r.Cookies()
}

func (s *Service) setCookie(cookie *http.Cookie) []*core.HeaderValueOption {
	return []*core.HeaderValueOption{
		{
			Header: &core.HeaderValue{
				Key:   "Cache-Control",
				Value: "no-cache",
			},
		},
		{
			Header: &core.HeaderValue{
				Key:   "Pragma",
				Value: "no-cache",
			},
		},
		{
			Header: &core.HeaderValue{
				Key:   "Vary",
				Value: "Accept-Encoding",
			},
		},
		{
			Header: &core.HeaderValue{
				Key:   "Set-Cookie",
				Value: cookie.String(),
			},
		},
	}
}

func (s *Service) setRedirectHeader(location string) *core.HeaderValueOption {
	return &core.HeaderValueOption{
		Header: &core.HeaderValue{
			Key:   "Location",
			Value: location,
		},
	}
}

func (s *Service) setAuthorizationHeader(token string) *core.HeaderValueOption {
	return &core.HeaderValueOption{
		Header: &core.HeaderValue{
			Key:   "Authorization",
			Value: "Bearer " + token,
		},
	}
}

func (s *Service) getCodeQueryParam(fullURL string) (string, error) {
	u, err := url.Parse(fullURL)
	if err != nil {
		return "", err
	}
	return u.Query().Get("code"), nil
}

func (s *Service) response(success bool, httpStatusCode envoy_type.StatusCode, headers []*core.HeaderValueOption, body string) *auth.CheckResponse {
	var resp *auth.CheckResponse

	if success {
		resp = &auth.CheckResponse{
			Status: &rpcstatus.Status{
				Code: int32(rpc.OK),
			},
			HttpResponse: &auth.CheckResponse_OkResponse{
				OkResponse: &auth.OkHttpResponse{
					Headers: headers,
				},
			},
		}
	} else {
		resp = &auth.CheckResponse{
			Status: &rpcstatus.Status{
				Code: int32(rpc.PERMISSION_DENIED),
			},
			HttpResponse: &auth.CheckResponse_DeniedResponse{
				DeniedResponse: &auth.DeniedHttpResponse{
					Status: &envoy_type.HttpStatus{
						Code: httpStatusCode,
					},
					Headers: headers,
					Body:    body,
				},
			},
		}
	}

	return resp
}
