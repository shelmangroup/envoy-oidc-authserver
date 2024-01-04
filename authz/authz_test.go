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
	authz := Service{}

	req := connect.NewRequest(
		&auth.CheckRequest{
			Attributes: &auth.AttributeContext{
				Request: &auth.AttributeContext_Request{
					Http: &auth.AttributeContext_HttpRequest{
						Host: "localhost",
					},
				},
			},
		},
	)

	// Check Authorization response.
	resp, err := authz.Check(context.TODO(), req)
	require.NoError(t, err, "check should not have failed")
	assert.Equal(t, int32(rpc.OK), resp.Msg.Status.Code)
}
