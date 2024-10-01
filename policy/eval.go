package policy

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	auth "buf.build/gen/go/envoyproxy/envoy/protocolbuffers/go/envoy/service/auth/v3"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown/builtins"
	iCache "github.com/open-policy-agent/opa/topdown/cache"
	"github.com/open-policy-agent/opa/topdown/print"
	"github.com/open-policy-agent/opa/util"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/encoding/protojson"
)

var tracer = otel.Tracer("policy")

type Policy struct {
	q      rego.PreparedEvalQuery
	icache iCache.InterQueryCache
	name   string
}

type tracePrintHook struct {
	Name string
}

func (h tracePrintHook) Print(c print.Context, msg string) error {
	_, span := tracer.Start(c.Context, h.Name+"PrintHook")
	defer span.End()
	span.AddEvent("PrintHook",
		trace.WithAttributes(
			attribute.String("msg", msg),
			attribute.Int("row", c.Location.Row),
		),
	)
	span.SetStatus(codes.Ok, "ok")
	slog.Debug(h.Name, slog.String("msg", msg), slog.Int("row", c.Location.Row))
	return nil
}

// NewPolicy creates a new Policy with the given policy.
func NewPolicy(name, policy string) (*Policy, error) {
	ctx := context.Background()
	ph := &tracePrintHook{
		Name: name,
	}

	r, err := rego.New(
		rego.Query("data.authz"),
		rego.Module("OpenPolicyAgent", policy),
		rego.EnablePrintStatements(true),
		rego.PrintHook(ph),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}

	return &Policy{
		q:      r,
		icache: iCache.NewInterQueryCache(nil),
		name:   name,
	}, nil
}

// Eval evaluates the policy with the given input and returns the decision log.
func (p *Policy) Eval(ctx context.Context, input map[string]any) (map[string]any, error) {
	ctx, span := tracer.Start(ctx, p.name+"PolicyEval")
	defer span.End()

	slog.Debug("policy", slog.Any("input", input))

	rs, err := p.q.Eval(
		ctx,
		rego.EvalInput(input),
		rego.EvalInterQueryBuiltinCache(p.icache),
		rego.EvalNDBuiltinCache(builtins.NDBCache{}),
	)
	if err != nil {
		span.RecordError(err, trace.WithStackTrace(true))
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if len(rs) == 0 {
		return nil, errors.New("no results returned! No default value for `allow` and/or `bypass_auth` in policy?")
	}

	var decision map[string]interface{}
	switch d := rs[0].Expressions[0].Value.(type) {
	case map[string]interface{}:
		decision = d
	default:
		return nil, errors.New("invalid decision type")
	}

	slog.Debug("policy eval", slog.Any("decision_log", decision))

	return decision, nil
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
	default:
		return nil, errors.New("unknown type")
	}

	return input, nil
}
