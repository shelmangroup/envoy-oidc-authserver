package policy

import (
	"context"
	"log/slog"
	"strings"

	auth "buf.build/gen/go/envoyproxy/envoy/protocolbuffers/go/envoy/service/auth/v3"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/util"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/encoding/protojson"
)

var tracer = otel.Tracer("policy")

type Policy struct {
	rego *rego.Rego
	name string
}

// NewPolicy creates a new Policy with the given policy.
func NewPolicy(name, policy string) *Policy {
	return &Policy{
		rego: rego.New(rego.Query("data.authz.allow"), rego.Module("OpenPolicyAgent", policy)),
		name: name,
	}
}

// Eval evaluates the policy with the given input and returns the result.
func (p *Policy) Eval(ctx context.Context, input map[string]any) (bool, error) {
	ctx, span := tracer.Start(ctx, p.name+"PolicyEval")
	defer span.End()

	v, err := ast.InterfaceToValue(input)
	if err != nil {
		return false, err
	}

	q, err := p.rego.PrepareForEval(ctx)
	if err != nil {
		span.RecordError(err, trace.WithStackTrace(true))
		span.SetStatus(codes.Error, err.Error())
		return false, err
	}

	rs, err := q.Eval(ctx, rego.EvalParsedInput(v))
	if err != nil {
		span.RecordError(err, trace.WithStackTrace(true))
		span.SetStatus(codes.Error, err.Error())
		return false, err
	}

	span.AddEvent("decision_log",
		trace.WithAttributes(
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

func RequestOrResponseToInput(req any) (map[string]any, error) {
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
