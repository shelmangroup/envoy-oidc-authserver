package policy

import (
	"context"
	"strconv"
	"testing"

	corev3 "buf.build/gen/go/envoyproxy/envoy/protocolbuffers/go/envoy/config/core/v3"
	authv3 "buf.build/gen/go/envoyproxy/envoy/protocolbuffers/go/envoy/service/auth/v3"
	"github.com/stretchr/testify/require"
)

const (
	prePolicy = `
    package authz
    import rego.v1
    import input.attributes.request.http as req

    default allow = false
    default bypass_auth = false

    allow if {
      req.path == "/"
      print("allowed")
    }

    bypass_auth if {
      req.path == "/"
    }
`

	postPolicy = `
    package authz
    import rego.v1

    default allow = false

    allow if {
      input.parsed_jwt == "abc123"
    }
`
)

func TestEvalCheckRequest(t *testing.T) {
	ctx := context.Background()
	p, err := NewPolicy("PreAuth", prePolicy)
	require.NoError(t, err)

	_, err = NewPolicy("PreAuth", "")
	require.Error(t, err)

	scenarios := []struct {
		path     string
		expected bool
	}{
		{path: "/", expected: true},
		{path: "/fail", expected: false},
	}

	for i, scenario := range scenarios {
		t.Run("Eval"+strconv.Itoa(i), func(t *testing.T) {
			req := &authv3.CheckRequest{
				Attributes: &authv3.AttributeContext{
					Request: &authv3.AttributeContext_Request{
						Http: &authv3.AttributeContext_HttpRequest{
							Scheme: "http",
							Host:   "foo.bar",
							Path:   scenario.path,
							Headers: map[string]string{
								":authority": "foo.bar",
							},
						},
					},
				},
			}

			input, err := RequestOrResponseToInput(req)
			require.NoError(t, err)

			_, err = RequestOrResponseToInput(nil)
			require.Error(t, err)

			decision, err := p.Eval(ctx, input)
			require.NoError(t, err)
			allowed := decision["allow"].(bool)
			require.Equal(t, scenario.expected, allowed)
			bypass := decision["bypass_auth"].(bool)
			require.Equal(t, scenario.expected, bypass)
		})
	}
}

func TestEvalCheckResponse(t *testing.T) {
	ctx := context.Background()
	p, err := NewPolicy("PostAuth", postPolicy)
	require.NoError(t, err)

	_, err = NewPolicy("PostAuth", "")
	require.Error(t, err)

	scenarios := []struct {
		jwt      string
		expected bool
	}{
		{jwt: "abc123", expected: true},
		{jwt: "should_fail", expected: false},
	}

	for i, scenario := range scenarios {
		t.Run("Eval"+strconv.Itoa(i), func(t *testing.T) {
			res := &authv3.CheckResponse{
				HttpResponse: &authv3.CheckResponse_OkResponse{
					OkResponse: &authv3.OkHttpResponse{
						Headers: []*corev3.HeaderValueOption{
							{
								Header: &corev3.HeaderValue{
									Key:   "Authorization",
									Value: "Bearer " + scenario.jwt,
								},
							},
						},
					},
				},
			}

			input, err := RequestOrResponseToInput(res)
			require.NoError(t, err)

			decision, err := p.Eval(ctx, input)
			require.NoError(t, err)
			allowed := decision["allow"].(bool)
			require.Equal(t, scenario.expected, allowed)
		})
	}
}
