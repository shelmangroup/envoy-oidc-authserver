package authz

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"buf.build/gen/go/envoyproxy/envoy/connectrpc/go/envoy/service/auth/v3/authv3connect"
	core "buf.build/gen/go/envoyproxy/envoy/protocolbuffers/go/envoy/config/core/v3"
	auth "buf.build/gen/go/envoyproxy/envoy/protocolbuffers/go/envoy/service/auth/v3"
	envoy_type "buf.build/gen/go/envoyproxy/envoy/protocolbuffers/go/envoy/type/v3"
	"connectrpc.com/connect"
	"connectrpc.com/otelconnect"
	"github.com/gogo/googleapis/google/rpc"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
)

const ServiceName = "shelman-authz"

type Service struct {
	authv3connect.UnimplementedAuthorizationHandler

	cfg *Config
	//TODO: add a session store
}

func NewService(cfg *Config) *Service {
	return &Service{
		cfg: cfg,
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

	for k, v := range httpReq.GetHeaders() {
		provider = s.cfg.Match(k, v)
		if provider != nil {
			break
		}
	}

	if provider == nil {
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
	sessionCookieName := provider.CookieNamePrefix + "-" + ServiceName
	requestedURL := req.GetScheme() + "://" + req.GetHost() + req.GetPath()
	if req.GetQuery() != "" {
		requestedURL += "?" + req.GetQuery()
	}

	// check if cookie exists
	for _, cookie := range s.getCookies(req) {
		if cookie.Name == sessionCookieName {
			if cookie.Valid() == nil {
				sessionCookie = cookie
			}
		}
	}

	if sessionCookie == nil {
		// TODO: create a new session in session store
		// TODO: save requestedURL in session store
		headers = append(headers, s.setRedirectHeader(provider.p.IdpAuthURL()))

		// set cookie with session id and redirect to Idp
		cookie := &http.Cookie{
			Name:     sessionCookieName,
			Value:    "<sessionid>",
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		}
		headers = append(headers, s.setCookie(cookie))
		// set downstream headers and redirect to Idp
		return s.buildResponse(false, envoy_type.StatusCode_Found, headers, "redirect to Idp"), nil
	}

	// TODO: find session in session store and initialize it

	if requestedURL == provider.CallbackURI {
		code, err := s.getCodeQueryParam(req.GetQuery())
		if err != nil {
			return nil, err
		}
		_, err = provider.p.RetriveTokens(ctx, code)
		if err != nil {
			return nil, err
		}
		// TODO: store tokens in session store

		// set downstream headers and redirect client to requested URL from session store
		headers = append(headers, s.setRedirectHeader("<TODO: session store requestedURL>"))
		return s.buildResponse(false, envoy_type.StatusCode_Found, headers, "redirect to requested url"), nil
	}

	// TODO: get tokens from store and refresh if needed abd set upstream auth headers and return success response

	// default denied response
	return s.buildResponse(false, envoy_type.StatusCode_Unauthorized, nil, "permission denied"), nil
}

// parse cookie header string into []*http.Cookie struct
func (s *Service) getCookies(req *auth.AttributeContext_HttpRequest) []*http.Cookie {
	cookieRaw := req.GetHeaders()["Cookie"]
	header := http.Header{}
	header.Add("Cookie", cookieRaw)
	r := http.Request{Header: header}
	return r.Cookies()
}

func (s *Service) setCookie(cookie *http.Cookie) *core.HeaderValueOption {
	return &core.HeaderValueOption{
		Header: &core.HeaderValue{
			Key:   "Set-Cookie",
			Value: cookie.String(),
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

func (s *Service) getCodeQueryParam(queryString string) (string, error) {
	queryParams, err := url.ParseQuery(queryString)
	if err != nil {
		return "", err
	}
	code := queryParams.Get("code")
	return code, nil
}

func (s *Service) buildResponse(success bool, httpStatusCode envoy_type.StatusCode, headers []*core.HeaderValueOption, body string) *auth.CheckResponse {
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
