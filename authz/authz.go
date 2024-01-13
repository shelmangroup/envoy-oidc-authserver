package authz

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
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
	"go.opentelemetry.io/contrib/instrumentation/net/http/httptrace/otelhttptrace"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/net/http2"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"

	"github.com/shelmangroup/shelman-authz/store"
)

const ServiceName = "shelman-authz"

type Service struct {
	authv3connect.UnimplementedAuthorizationHandler

	cfg        *Config
	store      *store.SessionStore
	authClient authv3connect.AuthorizationClient
}

func NewService(cfg *Config, store *store.SessionStore, opaURL string) *Service {
	var c authv3connect.AuthorizationClient
	if opaURL != "" {
		u, err := url.Parse(opaURL)
		if err != nil {
			slog.Error("OPA URL is invalid", slog.String("err", err.Error()))
		}
		slog.Info("OPA is enabled, all requests will be sent to OPA for authorization", slog.String("url", u.String()))
		client := &http.Client{
			Timeout: time.Second * 5,
			Transport: otelhttp.NewTransport(
				&http2.Transport{
					AllowHTTP: true,
					DialTLS: func(network, addr string, _ *tls.Config) (net.Conn, error) {
						return net.Dial(network, addr)
					},
				},
				otelhttp.WithClientTrace(func(ctx context.Context) *httptrace.ClientTrace {
					return otelhttptrace.NewClientTrace(ctx)
				})),
		}
		c = authv3connect.NewAuthorizationClient(client, u.String(), connect.WithGRPC())
	}

	return &Service{
		cfg:        cfg,
		store:      store,
		authClient: c,
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
	reqHeaders := httpReq.GetHeaders()
	var resp *auth.CheckResponse
	var provider *OIDCProvider
	var hasAuthHeader bool

	slog.Debug("client request headers", slog.Any("headers", reqHeaders))

	if _, ok := reqHeaders["authorization"]; ok {
		slog.Debug("client request authorization header is present")
		hasAuthHeader = true
	}

	for name, value := range reqHeaders {
		provider = s.cfg.Match(name, value)
		if provider != nil {
			break
		}
	}
	if provider == nil {
		slog.Error("no header matches any provider")
		return connect.NewResponse(s.authResponse(false, envoy_type.StatusCode_Unauthorized, nil, "no header matches any auth provider")), nil
	}

	if provider.OPAEnabled && s.authClient != nil {
		slog.Debug("OPA is enabled, sending request to OPA for authorization")
		opaResp, err := s.authClient.Check(ctx, req)
		if err != nil {
			slog.Error("OPA check failed", slog.String("err", err.Error()))
			return nil, err
		}
		if opaResp.Msg.GetStatus().GetCode() == int32(rpc.PERMISSION_DENIED) {
			slog.Debug("OPA denied request")
			return opaResp, nil
		}
		if hasAuthHeader && provider.AllowAuthHeader && (opaResp.Msg.GetStatus().GetCode() == int32(rpc.OK)) {
			slog.Debug("request has auth header and OPA allowed the request")
			return opaResp, nil
		}
	}

	resp, err := s.authProcess(ctx, httpReq, provider)
	if err != nil {
		slog.Error("authProccess failed", slog.String("err", err.Error()))
		return nil, err
	}

	// TODO: merge opaResp headers with resp headers (only okResponse headers)

	// Return response to envoy
	return connect.NewResponse(resp), nil
}

func (s *Service) authProcess(ctx context.Context, req *auth.AttributeContext_HttpRequest, provider *OIDCProvider) (*auth.CheckResponse, error) {
	var headers []*core.HeaderValueOption
	var sessionCookie *http.Cookie
	var sessionData *store.SessionData
	sessionCookieName := provider.CookieNamePrefix + "-" + ServiceName

	requestedURL := req.GetScheme() + "://" + req.GetHost() + req.GetPath()
	slog.Debug("client request url", slog.String("url", requestedURL))

	// check if cookie exists and fetch session data from store
	sessionData, sessionCookie, err := s.getSessionCookieData(ctx, req, sessionCookieName)
	if err != nil {
		sessionData = store.NewSessionData()
		idpAuthURL := provider.p.IdpAuthURL(sessionData.CodeChallenge)
		headers, err := s.newSession(ctx, requestedURL, idpAuthURL, sessionCookieName, sessionData)
		if err != nil {
			return nil, err
		}
		// set downstream headers and redirect to Idp
		return s.authResponse(false, envoy_type.StatusCode_Found, headers, "redirect to Idp"), nil
	}

	// If the request is for the callback URI, then we need to exchange the code for tokens
	if strings.HasPrefix(requestedURL, provider.CallbackURI+"?") && sessionData != nil {
		code, err := s.getCodeQueryParam(requestedURL)
		if err != nil {
			return nil, err
		}
		tokens, err := provider.p.RetriveTokens(ctx, code, sessionData.CodeVerifier)
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
		return s.authResponse(false, envoy_type.StatusCode_Found, headers, "redirect to requested url"), nil
	}

	tokens := sessionData.GetTokens()
	if tokens == nil {
		slog.Debug("no tokens found in session data deleting session data from store")
		err = s.store.Delete(ctx, sessionCookie.Value)
		if err != nil {
			slog.Error("error deleting session data from store", slog.String("err", err.Error()))
			return nil, err
		}
		return nil, errors.New("no tokens found in session data")
	}

	refreshedTokens, err := s.validateTokens(ctx, provider, tokens)
	if err != nil {
		slog.Error("error validating token", slog.String("err", err.Error()))
		return nil, err
	}
	if refreshedTokens != nil {
		// Update the session data with the new tokens
		slog.Debug("Token refreshed updating in store", slog.String("expire", refreshedTokens.Expiry.String()))
		sessionData.SetTokens(refreshedTokens)
		err = s.store.Set(ctx, sessionCookie.Value, sessionData)
		if err != nil {
			slog.Error("error updating session data in store", slog.String("err", err.Error()))
			return nil, err
		}
	}

	slog.Debug("setting authorization header to upstream request", slog.String("session_id", sessionCookie.Value))
	headers = append(headers, s.setAuthorizationHeader(sessionData.GetTokens().IDToken))
	return s.authResponse(true, envoy_type.StatusCode_OK, headers, "success"), nil
}

// Validates and poteintially refreshes the token
func (s *Service) validateTokens(ctx context.Context, provider *OIDCProvider, tokens *store.Tokens) (*store.Tokens, error) {
	if tokens.AccessToken != "" && !expired(tokens.Expiry) {
		return nil, nil
	}

	t, err := provider.p.RefreshTokens(ctx, tokens.RefreshToken, tokens.AccessToken)
	if err != nil {
		return nil, err
	}

	return &store.Tokens{
		RefreshToken: t.RefreshToken,
		AccessToken:  t.AccessToken,
		IDToken:      t.IDToken,
		Expiry:       t.Expiry,
	}, nil
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
	slog.Debug("Creating new session")
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
		SameSite: http.SameSiteLaxMode,
	}
	return append(headers, s.setCookie(cookie)...), nil
}

func (s *Service) getSessionCookieData(ctx context.Context, req *auth.AttributeContext_HttpRequest, cookieName string) (*store.SessionData, *http.Cookie, error) {
	var sessionData *store.SessionData
	var cookie *http.Cookie

	for _, c := range s.getCookies(req) {
		if c.Name == cookieName {
			if c.Valid() != nil {
				return nil, nil, errors.New("cookie is invalid")
			}
			slog.Debug("found a cookie 👌", slog.String("cookie_name", c.Name))
			cookie = c
		}
	}

	slog.Debug("getting session data from store", slog.String("session_id", cookie.Value))
	sessionData, found, err := s.store.Get(ctx, cookie.Value)
	if err != nil {
		slog.Error("error getting session data from store", slog.String("err", err.Error()), slog.String("session_id", cookie.Value))
		return nil, nil, err
	}
	if !found {
		slog.Debug("session data not found in store", slog.String("session_id", cookie.Value))
		return nil, nil, errors.New("session data not found in store")
	}
	return sessionData, cookie, nil
}

// parse cookie header string into []*http.Cookie struct
func (s *Service) getCookies(req *auth.AttributeContext_HttpRequest) []*http.Cookie {
	cookieRaw := req.GetHeaders()["cookie"]
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

func (s *Service) authResponse(success bool, httpStatusCode envoy_type.StatusCode, headers []*core.HeaderValueOption, body string) *auth.CheckResponse {
	if success {
		return &auth.CheckResponse{
			Status: &rpcstatus.Status{
				Code: int32(rpc.OK),
			},
			HttpResponse: &auth.CheckResponse_OkResponse{
				OkResponse: &auth.OkHttpResponse{
					Headers: headers,
				},
			},
		}
	}
	return &auth.CheckResponse{
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
