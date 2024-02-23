package policy

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	auth "buf.build/gen/go/envoyproxy/envoy/protocolbuffers/go/envoy/service/auth/v3"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/util"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	tracer = otel.Tracer("policy")
)

// Eval evaluates the policy with the given input and returns the result.
func Eval(ctx context.Context, input map[string]interface{}, policy string) (bool, error) {
	ctx, span := tracer.Start(ctx, "PolicyEval")
	defer span.End()

	q, err := rego.New(
		rego.Query("data.authz.allow"),
		rego.Module("opaPolicy", policy),
	).PrepareForEval(ctx)

	if err != nil {
		span.RecordError(err, trace.WithStackTrace(true))
		span.SetStatus(codes.Error, err.Error())
		return false, err
	}

	rs, err := q.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		span.RecordError(err, trace.WithStackTrace(true))
		span.SetStatus(codes.Error, err.Error())
		return false, err
	}

	span.AddEvent("decision log",
		trace.WithAttributes(
			attribute.String("policy", policy),
			attribute.String("input", fmt.Sprintf("%+v", input)),
			attribute.Bool("is_allowed", rs.Allowed()),
		),
	)
	slog.Debug("policy", slog.Any("input", input))

	if !rs.Allowed() {
		span.SetStatus(codes.Error, "policy denied")
		return false, nil
	}

	span.SetStatus(codes.Ok, "allowed")
	return true, nil
}

func RequestOrResponseToInput(req any) (map[string]interface{}, error) {
	var input map[string]interface{}

	// type switch for CheckRequest or CheckResponse
	switch v := req.(type) {
	case *auth.CheckRequest:
		bs, err := protojson.Marshal(v)
		if err != nil {
			return nil, err
		}
		err = util.UnmarshalJSON(bs, &input)
		if err != nil {
			return nil, err
		}
	case *auth.CheckResponse:
		bs, err := protojson.Marshal(v)
		if err != nil {
			return nil, err
		}
		err = util.UnmarshalJSON(bs, &input)
		if err != nil {
			return nil, err
		}
		for _, h := range v.GetOkResponse().GetHeaders() {
			if h.GetHeader().GetKey() == "Authorization" {
				input["parsed_jwt"] = strings.Split(h.GetHeader().GetValue(), " ")[1]
				break
			}
		}
	}

	return input, nil
}
