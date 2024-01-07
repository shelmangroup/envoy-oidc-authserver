package authz

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/gogo/googleapis/google/rpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	auth "buf.build/gen/go/envoyproxy/envoy/protocolbuffers/go/envoy/service/auth/v3"
)

func TestCheckService(t *testing.T) {
	testCfg, err := initialize(&Config{
		Providers: []OIDCProvider{
			{
				IssuerURL:        "http://127.0.0.1:5556/dex",
				CallbackURI:      "http://foo.bar/callback",
				ClientID:         "foo",
				ClientSecret:     "bar",
				Scopes:           []string{"openid", "profile", "email"},
				CookieNamePrefix: "foo",
				Match: Match{
					HeaderName: "authority",
					ExactMatch: "foo.bar",
				},
			},
		},
	})
	require.NoError(t, err, "init cfg should not have failed")

	authz := Service{cfg: testCfg}

	testReq := connect.NewRequest(
		&auth.CheckRequest{
			Attributes: &auth.AttributeContext{
				Request: &auth.AttributeContext_Request{
					Http: &auth.AttributeContext_HttpRequest{
						Scheme: "http",
						Host:   "foo.bar",
						Path:   "/",
						Headers: map[string]string{
							"authority": "foo.bar",
						},
					},
				},
			},
		},
	)

	// Check Authorization response.
	resp, err := authz.Check(context.TODO(), testReq)
	require.NoError(t, err, "check should not have failed")
	assert.Equal(t, int32(rpc.PERMISSION_DENIED), resp.Msg.Status.Code)
}
