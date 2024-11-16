package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	auth "buf.build/gen/go/envoyproxy/envoy/protocolbuffers/go/envoy/service/auth/v3"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown/builtins"
	"github.com/open-policy-agent/opa/topdown/cache"
	"github.com/open-policy-agent/opa/topdown/print"
	"github.com/open-policy-agent/opa/util"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/encoding/protojson"
)

var tracer = otel.Tracer("policy")

const PolicyQuery = "data.authz"

type DecisionLog map[string]any

type Policy struct {
	q          rego.PreparedEvalQuery
	queryCache cache.InterQueryCache
	name       string
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

// NewPolicy creates a policy from the given policy document
func NewPolicy(name, policy string) (*Policy, error) {
	ph := &tracePrintHook{
		Name: name,
	}

	r, err := rego.New(
		rego.Query(PolicyQuery),
		rego.Module("OpenPolicyAgent", policy),
		rego.EnablePrintStatements(true),
		rego.PrintHook(ph),
	).PrepareForEval(context.Background())
	if err != nil {
		return nil, err
	}

	return &Policy{
		q:          r,
		queryCache: cache.NewInterQueryCache(nil),
		name:       name,
	}, nil
}

// Eval evaluates the policy with the given input and returns the decision log.
func (p *Policy) Eval(ctx context.Context, input map[string]any) (DecisionLog, error) {
	ctx, span := tracer.Start(ctx, p.name+"PolicyEval")
	defer span.End()

	var decision DecisionLog

	slog.Debug("policy", slog.Any("input", input))

	rs, err := p.q.Eval(
		ctx,
		rego.EvalInput(input),
		rego.EvalInterQueryBuiltinCache(p.queryCache),
		rego.EvalNDBuiltinCache(builtins.NDBCache{}),
	)
	if err != nil {
		span.RecordError(err, trace.WithStackTrace(true))
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if len(rs) == 0 {
		span.SetStatus(codes.Error, "no results returned")
		return nil, errors.New("no results returned")
	}

	switch d := rs[0].Expressions[0].Value.(type) {
	case map[string]any:
		decision = d
	default:
		span.SetStatus(codes.Error, "invalid decision type")
		return nil, errors.New("invalid decision type")
	}

	slog.Debug("policy eval", slog.Any("decision_log", decision))

	// Span event for decision log
	span.AddEvent("Policy evaluation",
		trace.WithAttributes(
			attribute.String("decision log", fmt.Sprint(decision)),
		),
	)
	span.SetStatus(codes.Ok, "ok")

	return decision, nil
}

func RequestOrResponseToInput(req any) (map[string]any, error) {
	var input map[string]any

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
