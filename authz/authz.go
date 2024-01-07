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

type Service struct {
	authv3connect.UnimplementedAuthorizationHandler

	cfg *Config
	//FIXME: add a session store
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
	//TODO: implement me
	fullURL := req.GetScheme() + "://" + req.GetHost() + req.GetPath()
	if fullURL == provider.CallbackURI {
		code, err := s.getCodeQueryParam(req.GetQuery())
		if err != nil {
			return nil, err
		}
		_, err = provider.p.RetriveTokens(ctx, code)
		if err != nil {
			return nil, err
		}
		// next: store tokens in redis?
	}

	// default denied response
	return s.buildResponse(false, envoy_type.StatusCode_Unauthorized, nil, "permission denied"), nil
}

func (s *Service) setCookie(cookie *http.Cookie) *core.HeaderValueOption {
	return &core.HeaderValueOption{
		Header: &core.HeaderValue{
			Key:   "Set-Cookie",
			Value: cookie.String(),
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
