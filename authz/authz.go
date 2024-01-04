package authz

import (
	"context"
	"net/http"

	"connectrpc.com/connect"
	"connectrpc.com/otelconnect"
	"github.com/gogo/googleapis/google/rpc"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"

	"buf.build/gen/go/envoyproxy/envoy/connectrpc/go/envoy/service/auth/v3/authv3connect"
	core "buf.build/gen/go/envoyproxy/envoy/protocolbuffers/go/envoy/config/core/v3"
	auth "buf.build/gen/go/envoyproxy/envoy/protocolbuffers/go/envoy/service/auth/v3"
	envoy_type "buf.build/gen/go/envoyproxy/envoy/protocolbuffers/go/envoy/type/v3"
)

type Service struct {
	authv3connect.UnimplementedAuthorizationHandler

	// Add more state fields here
}

func NewService() *Service {
	return &Service{}
}

func (s *Service) NewHandler() (string, http.Handler) {
	return authv3connect.NewAuthorizationHandler(s, connect.WithInterceptors(otelconnect.NewInterceptor()))
}

func (s *Service) Name() string {
	return authv3connect.AuthorizationName
}

func (s *Service) Check(ctx context.Context, req *connect.Request[auth.CheckRequest]) (*connect.Response[auth.CheckResponse], error) {

	httpReq := req.Msg.GetAttributes().GetRequest().GetHttp()

	resp := &auth.CheckResponse{}

	// dummy if statement to show that we can use the request data to make authorization decisions
	if httpReq.GetHost() == "localhost" {
		resp = &auth.CheckResponse{
			Status: &rpcstatus.Status{
				Code: int32(rpc.OK),
			},
			HttpResponse: &auth.CheckResponse_OkResponse{
				OkResponse: &auth.OkHttpResponse{
					Headers: []*core.HeaderValueOption{
						{
							Header: &core.HeaderValue{
								Key:   "x-custom-header-from-authz",
								Value: "some value",
							},
						},
					},
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
						Code: envoy_type.StatusCode_Unauthorized,
					},
					Body: "PERMISSION_DENIED",
				},
			},
		}
	}

	return connect.NewResponse(resp), nil
}
