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
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/shelmangroup/envoy-oidc-authserver/internal/gen/session/v1"
	"github.com/shelmangroup/envoy-oidc-authserver/session"
	"github.com/shelmangroup/envoy-oidc-authserver/store"
)

const ServiceName = "envoy-authz"

type Service struct {
	authv3connect.UnimplementedAuthorizationHandler

	cfg        *Config
	secretKey  []byte
	store      *store.Store
	authClient authv3connect.AuthorizationClient
}

func NewService(cfg *Config, opaURL, secretKey string) *Service {
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
		authClient: c,
		store:      store.NewStore(),
		secretKey:  []byte(secretKey),
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
		return connect.NewResponse(s.authResponse(false, envoy_type.StatusCode_Unauthorized, nil, nil, "no header matches any auth provider")), nil
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
		resp = s.authResponse(false, envoy_type.StatusCode_BadGateway, nil, nil, err.Error())
	}

	// TODO: merge opaResp headers with resp headers (only okResponse headers)

	// Return response to envoy
	return connect.NewResponse(resp), nil
}

func (s *Service) authProcess(ctx context.Context, req *auth.AttributeContext_HttpRequest, provider *OIDCProvider) (*auth.CheckResponse, error) {
	var headers []*core.HeaderValueOption
	var sessionData *pb.SessionData
	sessionCookieName := provider.CookieNamePrefix + "-" + ServiceName
	sourceIP := realIP(req.GetHeaders())

	requestedURL := req.GetScheme() + "://" + req.GetHost() + req.GetPath()
	slog.Debug("client request url", slog.String("url", requestedURL))

	// check if cookie exists and fetch session data from cookie
	sessionData, sessionId := s.getSessionCookieData(ctx, req, sourceIP, sessionCookieName)
	if sessionData == nil || sessionId == "" {
		slog.Debug("session data not found in cookie, creating new")
		headers, err := s.newSession(ctx, sourceIP, requestedURL, sessionCookieName, provider)
		if err != nil {
			return nil, err
		}
		// set downstream headers and redirect to Idp
		return s.authResponse(false, envoy_type.StatusCode_Found, headers, nil, "redirect to Idp"), nil
	}

	slog.Debug("session data found in cookie", slog.String("session_id", sessionId), slog.String("req_url", requestedURL))

	// If the request is for the callback URI, then we need to exchange the code for tokens
	if strings.HasPrefix(requestedURL, provider.CallbackURI+"?") && sessionData.AccessToken == "" {
		err := s.retriveTokens(ctx, provider, sessionData, requestedURL, sessionCookieName, sessionId)
		if err != nil {
			return nil, err
		}
		// set downstream headers and redirect client to requested URL from session cookie
		slog.Debug("redirecting client to first requested URL", slog.String("url", sessionData.GetRequestedUrl()))
		headers = append(headers, s.setRedirectHeader(sessionData.GetRequestedUrl()))
		return s.authResponse(false, envoy_type.StatusCode_Found, headers, nil, "redirect to requested url"), nil
	}

	err := s.validateTokens(ctx, provider, sessionData, sessionCookieName, sessionId)
	if err != nil {
		slog.Warn("couldn't validating tokens", slog.String("err", err.Error()))
		headers, err := s.newSession(ctx, sourceIP, requestedURL, sessionCookieName, provider)
		if err != nil {
			return nil, err
		}
		return s.authResponse(false, envoy_type.StatusCode_Found, headers, nil, "redirect to Idp"), nil
	}

	slog.Debug("setting authorization header to upstream request", slog.String("session_id", sessionId))
	headers = append(headers, s.setAuthorizationHeader(sessionData.IdToken))
	return s.authResponse(true, envoy_type.StatusCode_OK, headers, nil, "success"), nil
}

func (s *Service) retriveTokens(ctx context.Context, provider *OIDCProvider, sessionData *pb.SessionData, requestedURL, sessionCookieName, sessionId string) error {
	code, err := s.getCodeQueryParam(requestedURL)
	if err != nil {
		return err
	}
	tokens, err := provider.p.RetriveTokens(ctx, code, sessionData.CodeVerifier)
	if err != nil {
		return err
	}

	// Copy the tokens into the session data
	sessionData.RefreshToken = tokens.RefreshToken
	sessionData.AccessToken = tokens.AccessToken
	sessionData.IdToken = tokens.IDToken
	sessionData.Expiry = timestamppb.New(tokens.Expiry)

	// slog.Debug("successfully acquried tokens, now storing it to session cookie", slog.Any("sessionData", sessionData))

	enc, err := session.EncodeToken(ctx, [32]byte(s.secretKey), sessionData)
	if err != nil {
		slog.Error("error encrypting session data", slog.String("err", err.Error()))
		return err
	}
	slog.Debug("Encrypted SessionData", slog.Int("byte_len", len(enc)))

	// store session data in cache
	if err := s.store.Set(ctx, sessionId, enc); err != nil {
		return err
	}

	return nil
}

// Validates and poteintially refreshes the token
func (s *Service) validateTokens(ctx context.Context, provider *OIDCProvider, d *pb.SessionData, sessionCookieName, sessionId string) error {
	expired, err := provider.p.VerifyTokens(ctx, d.AccessToken, d.IdToken)
	if err != nil {
		return err
	}
	if !expired {
		return nil
	}

	if expired && d.RefreshToken == "" {
		return errors.New("token expired and no refresh token found, add scope=offline_access to the auth request to get a refresh token")
	}
	t, err := provider.p.RefreshTokens(ctx, d.RefreshToken, d.AccessToken)
	if err != nil {
		return err
	}

	d.RefreshToken = t.RefreshToken
	d.AccessToken = t.AccessToken
	d.IdToken = t.IDToken
	d.Expiry = timestamppb.New(t.Expiry)

	slog.Debug("Token refreshed, updating session cookie", slog.String("expire", t.Expiry.String()))
	enc, err := session.EncodeToken(ctx, [32]byte(s.secretKey), d)
	if err != nil {
		slog.Error("error encrypting session data", slog.String("err", err.Error()))
		return err
	}

	if err := s.store.Set(ctx, sessionId, enc); err != nil {
		return err
	}

	return nil
}

func (s *Service) newSession(ctx context.Context, sourceIP, requestedURL, sessionCookieName string, provider *OIDCProvider) ([]*core.HeaderValueOption, error) {
	slog.Debug("Creating new session")
	var headers []*core.HeaderValueOption

	sessionData := session.NewSessionData()
	sessionCookieToken, err := session.GenerateSessionToken()
	if err != nil {
		return nil, err
	}
	slog.Debug("setting requested url", slog.String("requested_url", requestedURL))
	sessionData.RequestedUrl = requestedURL
	sessionData.SourceIp = sourceIP

	enc, err := session.EncodeToken(ctx, [32]byte(s.secretKey), sessionData)
	if err != nil {
		return nil, err
	}

	// store session data in cache
	if err := s.store.Set(ctx, sessionCookieToken, enc); err != nil {
		return nil, err
	}

	idpAuthURL := provider.p.IdpAuthURL(sessionData.CodeChallenge)
	headers = append(headers, s.setRedirectHeader(idpAuthURL))
	// set cookie with session id and redirect to Idp
	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionCookieToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   provider.SecureCookie,
		SameSite: http.SameSiteLaxMode,
	}
	return append(headers, s.setCookie(cookie)...), nil
}

func (s *Service) getSessionCookieData(ctx context.Context, req *auth.AttributeContext_HttpRequest, sourceIP, cookieName string) (*pb.SessionData, string) {
	var sessionData *pb.SessionData
	var cookie *http.Cookie

	for _, c := range s.getCookies(req) {
		if c.Name == cookieName {
			if c.Valid() != nil {
				return nil, ""
			}
			slog.Debug("found a cookie 👌", slog.String("cookie_name", c.Name))
			cookie = c
		}
	}

	if cookie == nil {
		slog.Debug("no cookie found")
		return nil, ""
	}

	sessionId := cookie.Value
	slog.Debug("client source ip", slog.String("session_id", sessionId), slog.String("ip", sourceIP))

	d, err := s.store.Cache.Get(ctx, sessionId)
	if err != nil {
		slog.Error("error getting session data from cache", slog.String("err", err.Error()))
		return nil, ""
	}

	sessionData, err = session.DecodeToken(ctx, [32]byte(s.secretKey), d)
	if err != nil {
		slog.Error("error decrypt session data", slog.String("err", err.Error()))
		return nil, ""
	}
	slog.Debug("getting session data from session cookie", slog.String("session_id", sessionId), slog.String("session_data_expiry", sessionData.Expiry.AsTime().String()))

	if sessionData.SourceIp != sourceIP {
		slog.Warn("source ip missmatch, re-auth needed!", slog.String("session_id", sessionId), slog.String("session_ip", sessionData.SourceIp), slog.String("req_ip", sourceIP))
		return nil, ""
	}

	return sessionData, sessionId
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

func (s *Service) authResponse(success bool, httpStatusCode envoy_type.StatusCode, headers, respHeaders []*core.HeaderValueOption, body string) *auth.CheckResponse {
	if success {
		return &auth.CheckResponse{
			Status: &rpcstatus.Status{
				Code: int32(rpc.OK),
			},
			HttpResponse: &auth.CheckResponse_OkResponse{
				OkResponse: &auth.OkHttpResponse{
					Headers:              headers,
					ResponseHeadersToAdd: respHeaders,
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

func realIP(headers map[string]string) string {
	var ip string

	var envoyExternalAddress = "x-envoy-external-address"
	var xForwardedFor = "x-forwarded-for"
	var xRealIP = "x-real-ip"

	if tcip, ok := headers[envoyExternalAddress]; ok {
		ip = tcip
	} else if xrip, ok := headers[xRealIP]; ok {
		ip = xrip
	} else if xff, ok := headers[xForwardedFor]; ok {
		i := strings.Index(xff, ",")
		if i == -1 {
			i = len(xff)
		}
		ip = xff[:i]
	}
	if ip == "" || net.ParseIP(ip) == nil {
		return ""
	}
	return ip
}
