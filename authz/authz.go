package authz

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"html/template"
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
	cache_store "github.com/eko/gocache/lib/v4/store"
	"github.com/gogo/googleapis/google/rpc"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.23.1"
	"go.opentelemetry.io/otel/trace"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"

	pb "github.com/shelmangroup/envoy-oidc-authserver/internal/gen/session/v1"
	"github.com/shelmangroup/envoy-oidc-authserver/policy"
	"github.com/shelmangroup/envoy-oidc-authserver/session"
	"github.com/shelmangroup/envoy-oidc-authserver/store"
)

const ServiceName = "envoy-authz"

var tracer = otel.Tracer("authz")

type Service struct {
	authv3connect.UnimplementedAuthorizationHandler

	cfg               *Config
	store             *store.Store
	secretKey         [32]byte
	sessionExpiration time.Duration
}

func NewService(cfg *Config, secretKey string, redisURL *url.URL) *Service {
	// Parse the session expiration time
	ttl, err := time.ParseDuration(cfg.SessionExpiration)
	if err != nil {
		slog.Error("error parsing session expiration", slog.String("err", err.Error()))
		panic(err)
	}

	return &Service{
		cfg:               cfg,
		sessionExpiration: ttl,
		store:             store.NewStore(redisURL, ttl),
		secretKey:         sha256.Sum256([]byte(secretKey)),
	}
}

func (s *Service) NewHandler() (string, http.Handler) {
	otel, _ := otelconnect.NewInterceptor(otelconnect.WithTrustRemote())
	return authv3connect.NewAuthorizationHandler(s, connect.WithInterceptors(otel))
}

func (s *Service) Name() string {
	return authv3connect.AuthorizationName
}

func (s *Service) Check(ctx context.Context, req *connect.Request[auth.CheckRequest]) (*connect.Response[auth.CheckResponse], error) {
	ctx, span := tracer.Start(ctx, "Check")
	defer span.End()

	httpReq := req.Msg.GetAttributes().GetRequest().GetHttp()
	reqHeaders := httpReq.GetHeaders()
	var resp *auth.CheckResponse
	var provider *OIDCProvider

	slog.Debug("client request headers", slog.Any("headers", reqHeaders))

	for name, value := range reqHeaders {
		provider = s.cfg.Match(name, value)
		if provider != nil {
			break
		}
	}
	if provider == nil {
		slog.Error("no header matches any provider")
		span.RecordError(errors.New("no header matches any auth provider"))
		span.SetStatus(codes.Error, "no header matches any auth provider")
		return connect.NewResponse(s.authResponse(false, envoy_type.StatusCode_Unauthorized, nil, nil, "no header matches any auth provider")), nil
	}

	requestedURL := httpReq.GetScheme() + "://" + httpReq.GetHost() + httpReq.GetPath()
	if span.IsRecording() {
		span.SetAttributes(
			semconv.URLFull(requestedURL),
			semconv.SourceAddress(httpReq.GetHeaders()["x-forwarded-for"]),
		)
	}

	span.AddEvent("provider config",
		trace.WithAttributes(
			attribute.String("issuer_url", provider.IssuerURL),
			attribute.String("client_id", provider.ClientID),
			attribute.String("callback_uri", provider.CallbackURI),
			attribute.String("cookie_name_prefix", provider.CookieNamePrefix),
			attribute.String("pre_auth_policy", provider.PreAuthPolicy),
			attribute.String("post_auth_policy", provider.PostAuthPolicy),
			attribute.Bool("secure_cookie", provider.DisableSecureCookie),
			attribute.StringSlice("scopes", provider.Scopes),
			attribute.String("header_match_name", provider.HeaderMatch.Name),
		),
	)

	// if PreAuthPolicy is defined evaluate the request
	if provider.preAuthPolicy != nil {
		resInput, err := policy.RequestOrResponseToInput(req.Msg)
		if err != nil {
			span.RecordError(err, trace.WithStackTrace(true))
			span.SetStatus(codes.Error, err.Error())
			return connect.NewResponse(s.authResponse(false, envoy_type.StatusCode_BadGateway, nil, nil, err.Error())), nil
		}

		allowed, bypassAuth, err := provider.preAuthPolicy.Eval(ctx, resInput)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return connect.NewResponse(s.authResponse(false, envoy_type.StatusCode_BadGateway, nil, nil, err.Error())), nil
		}
		slog.Debug("PreAuth policy result", slog.Bool("allowed", allowed))

		if !allowed {
			span.SetStatus(codes.Error, "PreAuth policy denied the request")
			return connect.NewResponse(s.authResponse(false, envoy_type.StatusCode_Forbidden, nil, nil, "PreAuth policy denied the request")), nil
		}

		if bypassAuth {
			span.SetStatus(codes.Ok, "bypassAuth policy allowed the request")
			return connect.NewResponse(s.authResponse(true, envoy_type.StatusCode_OK, nil, nil, "skipAuth policy allowed the request")), nil
		}
	}

	// Call the auth flow
	resp, err := s.authProcess(ctx, httpReq, provider)
	if err != nil {
		span.RecordError(err, trace.WithStackTrace(true))
		span.SetStatus(codes.Error, err.Error())
		resp = s.authResponse(false, envoy_type.StatusCode_BadGateway, nil, nil, err.Error())
	}

	// if PostAuthPolicy is defined evaluate the response
	if provider.postAuthPolicy != nil && resp.GetStatus().GetCode() == int32(rpc.OK) {
		respInput, err := policy.RequestOrResponseToInput(resp)
		if err != nil {
			span.RecordError(err, trace.WithStackTrace(true))
			span.SetStatus(codes.Error, err.Error())
			return connect.NewResponse(s.authResponse(false, envoy_type.StatusCode_BadGateway, nil, nil, err.Error())), nil
		}

		allowed, _, err := provider.postAuthPolicy.Eval(ctx, respInput)
		if err != nil {
			span.RecordError(err, trace.WithStackTrace(true))
			span.SetStatus(codes.Error, err.Error())
			return connect.NewResponse(s.authResponse(false, envoy_type.StatusCode_BadGateway, nil, nil, err.Error())), nil
		}
		if !allowed {
			span.SetStatus(codes.Error, "PostAuth policy denied the request")
			return connect.NewResponse(s.authResponse(false, envoy_type.StatusCode_Forbidden, nil, nil, "PostAuth policy denied the request")), nil
		}
	}

	// Return response to envoy
	span.SetStatus(codes.Ok, "success")
	return connect.NewResponse(resp), nil
}

func (s *Service) authProcess(ctx context.Context, req *auth.AttributeContext_HttpRequest, provider *OIDCProvider) (*auth.CheckResponse, error) {
	ctx, span := tracer.Start(ctx, "authProcess")
	defer span.End()

	var headers []*core.HeaderValueOption
	sessionCookieName := provider.CookieNamePrefix + "-" + ServiceName

	requestedURL := req.GetScheme() + "://" + req.GetHost() + req.GetPath()
	xRequestedWith := req.GetHeaders()["x-requested-with"]
	var isAjax bool
	if xRequestedWith == "XMLHttpRequest" {
		isAjax = true
	}

	span.AddEvent("request headers",
		trace.WithAttributes(
			attribute.String(":authority", req.GetHeaders()[":authority"]),
			attribute.String("host", req.GetHost()),
			attribute.String("path", req.GetPath()),
			attribute.String("scheme", req.GetScheme()),
			attribute.String("method", req.GetMethod()),
			attribute.String("x-requested-with", xRequestedWith),
			attribute.String("x-forwarded-for", req.GetHeaders()["x-forwarded-for"]),
			attribute.String("user-agent", req.GetHeaders()["user-agent"]),
			attribute.Bool("ajax_request", isAjax),
		),
	)

	// check if cookie exists and fetch session data from cookie
	sessionToken, sessionData := s.getSessionCookieData(ctx, req, sessionCookieName)
	if sessionToken == "" || sessionData == nil {
		if isAjax {
			return s.authResponse(false, envoy_type.StatusCode_Unauthorized, nil, nil, "unauthorized"), nil
		}
		slog.Debug("session data not found in cookie, creating new")
		headers, err := s.newSession(ctx, requestedURL, sessionCookieName, provider)
		if err != nil {
			span.RecordError(err, trace.WithStackTrace(true))
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}
		// set downstream headers and redirect to Idp
		return s.authResponse(false, envoy_type.StatusCode_Found, headers, nil, "redirect to Idp"), nil
	}

	slog.Debug("session data found in cookie", slog.String("url", requestedURL))

	// If the request is for the callback URI, then we need to exchange the code for tokens
	if strings.HasPrefix(requestedURL, provider.CallbackURI+"?") && sessionData.AccessToken == "" {
		err := s.retrieveTokens(ctx, provider, sessionData, requestedURL, sessionToken)
		if err != nil {
			span.RecordError(err, trace.WithStackTrace(true))
			span.SetStatus(codes.Error, err.Error())
			// FIXME: might be a better way to handle this error case?
			// This will redirect the client back to the first requested URL
			// and request against the idp will be retried, which means less
			// confusing for the user.
			if strings.HasPrefix(err.Error(), `oauth2: "invalid_grant"`) {
				// Redirect the client back to the base URL
				baseUrl, _ := url.Parse(provider.CallbackURI)
				sessionData.RequestedUrl = baseUrl.Scheme + "://" + baseUrl.Host
				slog.Error("Invalid grant",
					slog.String("err", err.Error()),
					slog.String("url", requestedURL),
					slog.String("redirect_url", sessionData.GetRequestedUrl()),
				)
			} else {
				return nil, err
			}
		}
		// set downstream headers and redirect client to requested URL from session cookie
		slog.Debug("redirecting client to first requested URL", slog.String("url", sessionData.GetRequestedUrl()))
		headers = append(headers, s.setRedirectHeader(sessionData.GetRequestedUrl()))
		return s.authResponse(false, envoy_type.StatusCode_Found, headers, nil, "redirect to requested url"), nil
	}

	// If the request is for the logout URI, then we need to delete the session
	if req.GetPath() == provider.Logout.Path {
		slog.Debug("logout request", slog.String("path", req.GetPath()))
		storeKey, err := session.VerifySessionToken(ctx, sessionToken, s.secretKey, s.sessionExpiration)
		if err != nil {
			return nil, err
		}
		if err := s.store.Delete(ctx, storeKey); err != nil {
			return nil, err
		}
		headers = append(headers, s.setRedirectHeader(provider.Logout.RedirectURI))
		return s.authResponse(false, envoy_type.StatusCode_Found, headers, nil, "redirect to logout url"), nil
	}

	sessionData, err := s.validateTokens(ctx, provider, sessionData, sessionToken)
	if err != nil {
		if isAjax {
			return s.authResponse(false, envoy_type.StatusCode_Unauthorized, nil, nil, "unauthorized"), nil
		}
		headers, err := s.newSession(ctx, requestedURL, sessionCookieName, provider)
		if err != nil {
			span.RecordError(err, trace.WithStackTrace(true))
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}
		return s.authResponse(false, envoy_type.StatusCode_Found, headers, nil, "redirect to Idp"), nil
	}

	if !provider.DisablePassAuthorizationHeader {
		slog.Debug("setting authorization header to upstream request")
		headers = append(headers, s.setAuthorizationHeader(sessionData.IdToken))
	}
	span.SetStatus(codes.Ok, "success")
	return s.authResponse(true, envoy_type.StatusCode_OK, headers, nil, "success"), nil
}

func (s *Service) retrieveTokens(ctx context.Context, provider *OIDCProvider, sessionData *pb.SessionData, requestedURL, sessionToken string) error {
	code, err := s.getCodeQueryParam(requestedURL)
	if err != nil {
		return err
	}

	storeKey, err := session.VerifySessionToken(ctx, sessionToken, s.secretKey, s.sessionExpiration)
	if err != nil {
		return err
	}

	codeVerifier := storeKey[:43]
	t, err := provider.p.RetrieveTokens(ctx, code, codeVerifier)
	if err != nil {
		return err
	}

	// Copy the tokens into the session data
	sessionData.RefreshToken = t.RefreshToken
	sessionData.AccessToken = t.AccessToken
	sessionData.IdToken = t.IDToken

	slog.Debug("Token retrieved, updating session", slog.Any("expire", t.IDTokenClaims.GetExpiration()))
	enc, err := session.EncryptSession(ctx, [32]byte(s.secretKey), sessionData)
	if err != nil {
		slog.Error("error encrypting session data", slog.String("err", err.Error()))
		return err
	}
	if err := s.store.Set(ctx, storeKey, enc); err != nil {
		return err
	}

	return nil
}

// Validates and poteintially refreshes the token
func (s *Service) validateTokens(ctx context.Context, provider *OIDCProvider, sessionData *pb.SessionData, sessionToken string) (*pb.SessionData, error) {
	expired, err := provider.p.VerifyTokens(ctx, sessionData.AccessToken, sessionData.IdToken)
	if err != nil {
		return nil, err
	}
	if !expired {
		return sessionData, nil
	}

	if expired && sessionData.RefreshToken == "" {
		return nil, errors.New("token expired and no refresh token found, add scope=offline_access to the auth request to get a refresh token")
	}
	t, err := provider.p.RefreshTokens(ctx, sessionData.RefreshToken, sessionData.AccessToken)
	if err != nil {
		return nil, err
	}

	// Update the session data with the new tokens
	sessionData.RefreshToken = t.RefreshToken
	sessionData.AccessToken = t.AccessToken
	sessionData.IdToken = t.IDToken

	slog.Debug("Token refreshed, updating session", slog.Any("expire", t.IDTokenClaims.GetExpiration()))
	enc, err := session.EncryptSession(ctx, [32]byte(s.secretKey), sessionData)
	if err != nil {
		slog.Error("error encrypting session data", slog.String("err", err.Error()))
		return nil, err
	}
	storeKey, err := session.VerifySessionToken(ctx, sessionToken, s.secretKey, s.sessionExpiration)
	if err != nil {
		return nil, err
	}
	if err := s.store.Set(ctx, storeKey, enc); err != nil {
		return nil, err
	}

	return sessionData, nil
}

func (s *Service) newSession(ctx context.Context, requestedURL, sessionCookieName string, provider *OIDCProvider) ([]*core.HeaderValueOption, error) {
	slog.Debug("Creating new session")
	var headers []*core.HeaderValueOption

	sessionData := session.NewSessionData()
	sessionToken, err := session.GenerateSessionToken(ctx, s.secretKey)
	if err != nil {
		return nil, err
	}
	slog.Debug("setting requested url", slog.String("url", requestedURL))
	sessionData.RequestedUrl = requestedURL

	enc, err := session.EncryptSession(ctx, [32]byte(s.secretKey), sessionData)
	if err != nil {
		return nil, err
	}

	storeKey, err := session.VerifySessionToken(ctx, sessionToken, s.secretKey, s.sessionExpiration)
	if err != nil {
		return nil, err
	}

	// User has 5 minutes to authenticate
	if err := s.store.Set(ctx, storeKey, enc, cache_store.WithExpiration(5*time.Minute)); err != nil {
		return nil, err
	}

	codeChallenge := storeKey[43:]
	idpAuthURL := provider.p.IdpAuthURL(codeChallenge)
	headers = append(headers, s.setRedirectHeader(idpAuthURL))

	// set cookie with session id and redirect to Idp
	var secureCookie bool
	if !provider.DisableSecureCookie {
		secureCookie = true
	}
	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   secureCookie,
		SameSite: http.SameSiteLaxMode,
	}

	return append(headers, s.setCookie(cookie)...), nil
}

func (s *Service) getSessionCookieData(ctx context.Context, req *auth.AttributeContext_HttpRequest, cookieName string) (string, *pb.SessionData) {
	var sessionData *pb.SessionData
	var sessionToken string

	for _, c := range s.getCookies(req) {
		if c.Name == cookieName {
			if c.Valid() != nil {
				return "", nil
			}
			slog.Debug("found a cookie 👌", slog.String("cookie_name", c.Name))
			sessionToken = c.Value
		}
	}

	if sessionToken == "" {
		slog.Debug("no sessionToken found in cookie")
		return "", nil
	}

	storeKey, err := session.VerifySessionToken(ctx, sessionToken, s.secretKey, s.sessionExpiration)
	if err != nil {
		return "", nil
	}

	enc, err := s.store.Get(ctx, storeKey)
	if err != nil {
		slog.Warn("error getting session data from cache", slog.String("err", err.Error()))
		return "", nil
	}

	switch v := enc.(type) {
	case []byte:
		enc = v
	case string:
		enc = []byte(v)
	}

	sessionData, err = session.DecryptSession(ctx, [32]byte(s.secretKey), enc.([]byte))
	if err != nil {
		slog.Error("error decrypt session data", slog.String("err", err.Error()))
		return "", nil
	}

	return sessionToken, sessionData
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
				Headers: append(headers,
					&core.HeaderValueOption{
						Header: &core.HeaderValue{
							Key:   "Content-Type",
							Value: "text/html; charset=utf-8",
						},
					}),
				Body: s.genErrorHtmlPage(body),
			},
		},
	}
}

func (s *Service) genErrorHtmlPage(msg string) string {
	tplData := struct {
		Message string
	}{
		Message: msg,
	}

	// Define our template
	t := template.Must(template.New("error").Parse(`
    <!DOCTYPE html>
    <html>
     <head>
      <title>Error</title>
      <link href="https://fonts.googleapis.com/css2?family=Fira+Code&display=swap" rel="stylesheet">
      <style>
        body {
          background-color: #333;
          color: white;
          text-align: center;
          font-family: 'Fira Code', monospace;
        }

        .main {
          display: block;
          position: relative;
          margin: 50px auto 0 auto;
          width: 600px;
        }

        .main h1 {
          font-size: 80px;
          line-height: 36px;
          color: #fff;
        }

        .box {
          width: 400px;
          display: flex;
          border: 2px solid #000;
          margin: 0 auto 15px;
          text-align: center;
          padding: 30px;
          font-weight: bold;
          border-radius: 10px;
        }

        .error {
          background-color: #EBB1B1;
          border-color: #973939;
          color: #973939;
        }
      </style>
     </head>
     <body>
      <div class="main">
      <h1>$#*!🤦</h1>
        <div class="error box"> {{ .Message }} </div>
      </div>
     </body>
    </html>
  `))

	// Render our template
	body := new(bytes.Buffer)
	_ = t.Execute(body, tplData)
	return body.String()
}
