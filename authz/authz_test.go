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

	"github.com/shelmangroup/envoy-oidc-authserver/oidc"
	"github.com/shelmangroup/envoy-oidc-authserver/store"
)

func initializeMock(cfg *Config) (*Config, error) {
	// Create OIDC providers
	for i, c := range cfg.Providers {
		provider, err := oidc.NewOIDCMockProvider(
			c.ClientID,
			c.ClientSecret,
			c.CallbackURI,
			c.IssuerURL,
			c.Scopes,
		)
		if err != nil {
			return nil, err
		}
		cfg.Providers[i].p = provider
	}
	return cfg, nil
}

func TestCheckServiceAuthFlow(t *testing.T) {
	testCfg, err := initializeMock(&Config{
		Providers: []OIDCProvider{
			{
				IssuerURL:        "http://mock.idp/auth",
				CallbackURI:      "http://foo.bar/callback",
				ClientID:         "foo",
				ClientSecret:     "bar",
				Scopes:           []string{"openid", "profile", "email"},
				CookieNamePrefix: "foo",
				HeaderMatch: HeaderMatch{
					Name:  ":authority",
					Exact: "foo.bar",
				},
			},
		},
	})
	require.NoError(t, err, "init cfg should not have failed")

	secretKey := []byte("G_TdvPJ9T8C4p&A?Wr3YAUYW$*9vn4?t")
	authz := Service{cfg: testCfg, store: store.NewStore(nil, 0), secretKey: secretKey}

	//1. Check Authorization response without callback and no cookie req.
	initialRequestedURL := "http://foo.bar/"
	noCookieReq := connect.NewRequest(
		&auth.CheckRequest{
			Attributes: &auth.AttributeContext{
				Request: &auth.AttributeContext_Request{
					Http: &auth.AttributeContext_HttpRequest{
						Scheme: "http",
						Host:   "foo.bar",
						Path:   "/",
						Headers: map[string]string{
							":authority": "foo.bar",
						},
					},
				},
			},
		},
	)
	resp, err := authz.Check(context.TODO(), noCookieReq)
	require.NoError(t, err, "check should not have failed")
	assert.Equal(t, int32(rpc.PERMISSION_DENIED), resp.Msg.GetStatus().GetCode())
	// redirect to Idp should happen
	assert.Equal(t, envoy_type.StatusCode_Found, resp.Msg.GetDeniedResponse().GetStatus().GetCode())
	assert.Equal(t, testCfg.Providers[0].p.IdpAuthURL(""), resp.Msg.GetDeniedResponse().GetHeaders()[0].GetHeader().GetValue())

	//2. Check Authorization response with callback and cookie req.
	cookie := resp.Msg.GetDeniedResponse().GetHeaders()[4].GetHeader().GetValue()
	cookieReq := connect.NewRequest(
		&auth.CheckRequest{
			Attributes: &auth.AttributeContext{
				Request: &auth.AttributeContext_Request{
					Http: &auth.AttributeContext_HttpRequest{
						Scheme: "http",
						Host:   "foo.bar",
						Path:   "/callback?code=1234567890&state=1234567890",
						Headers: map[string]string{
							":authority": "foo.bar",
							"cookie":     cookie,
						},
					},
				},
			},
		},
	)
	resp, err = authz.Check(context.TODO(), cookieReq)
	require.NoError(t, err, "check with callback should not have failed")
	assert.Equal(t, int32(rpc.PERMISSION_DENIED), resp.Msg.Status.Code)
	assert.Equal(t, initialRequestedURL, resp.Msg.GetDeniedResponse().GetHeaders()[0].GetHeader().GetValue())

	//3. Success with Auth header set
	successReq := connect.NewRequest(
		&auth.CheckRequest{
			Attributes: &auth.AttributeContext{
				Request: &auth.AttributeContext_Request{
					Http: &auth.AttributeContext_HttpRequest{
						Scheme: "http",
						Host:   "foo.bar",
						Path:   "/",
						Headers: map[string]string{
							":authority": "foo.bar",
							"cookie":     cookie,
						},
					},
				},
			},
		},
	)
	resp, err = authz.Check(context.TODO(), successReq)
	require.NoError(t, err, "check success should not have failed")
	assert.Equal(t, int32(rpc.OK), resp.Msg.Status.Code)
	assert.Equal(t, "Bearer eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTA2MTI5MDIyfQ", resp.Msg.GetOkResponse().GetHeaders()[0].GetHeader().GetValue())
}
