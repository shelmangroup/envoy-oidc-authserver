package authz

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/gogo/googleapis/google/rpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	auth "buf.build/gen/go/envoyproxy/envoy/protocolbuffers/go/envoy/service/auth/v3"
	envoy_type "buf.build/gen/go/envoyproxy/envoy/protocolbuffers/go/envoy/type/v3"
)

func TestCheckService(t *testing.T) {
	testCfg, err := initializeMock(&Config{
		Providers: []OIDCProvider{
			{
				IssuerURL:        "http://mock.idp/auth",
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

	// Check Authorization response without callback and no cookie req.
	noCookieReq := connect.NewRequest(
		&auth.CheckRequest{
			Attributes: &auth.AttributeContext{
				Request: &auth.AttributeContext_Request{
					Http: &auth.AttributeContext_HttpRequest{
						Scheme: "http",
						Host:   "foo.bar",
						Path:   "/",
						Headers: map[string]string{
							"authority": "foo.bar",
							//"Cookie":    "foo123=bar",
						},
					},
				},
			},
		},
	)
	resp, err := authz.Check(context.TODO(), noCookieReq)
	require.NoError(t, err, "check should not have failed")
	assert.Equal(t, int32(rpc.PERMISSION_DENIED), resp.Msg.Status.Code)
	// redirect to Idp should happen
	assert.Equal(t, envoy_type.StatusCode_Found, resp.Msg.GetDeniedResponse().GetStatus().GetCode())
	assert.Equal(t, testCfg.Providers[0].p.IdpAuthURL(), resp.Msg.GetDeniedResponse().GetHeaders()[0].GetHeader().GetValue())

	// Check Authorization response with callback and cookie req.
	cookieReq := connect.NewRequest(
		&auth.CheckRequest{
			Attributes: &auth.AttributeContext{
				Request: &auth.AttributeContext_Request{
					Http: &auth.AttributeContext_HttpRequest{
						Scheme: "http",
						Host:   "foo.bar",
						Path:   "/callback",
						Headers: map[string]string{
							"authority": "foo.bar",
							"Cookie":    "foo123=bar",
						},
					},
				},
			},
		},
	)
	resp, err = authz.Check(context.TODO(), cookieReq)
	require.NoError(t, err, "check with callback should not have failed")
	assert.Equal(t, int32(rpc.PERMISSION_DENIED), resp.Msg.Status.Code)
	// Should redirect to requested URL
	// assert.Equal(t, testCfg.Providers[0].CallbackURI, resp.Msg.GetDeniedResponse().GetHeaders()[1].GetHeader().GetValue())
}
