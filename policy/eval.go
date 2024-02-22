package policy

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
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
func Eval(ctx context.Context, req *auth.CheckRequest, policy string) (bool, error) {
	ctx, span := tracer.Start(ctx, "PolicyEval")
	defer span.End()

	input, err := requestToInput(req)
	if err != nil {
		span.RecordError(err, trace.WithStackTrace(true))
		span.SetStatus(codes.Error, err.Error())
		return false, err
	}

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

func requestToInput(req *auth.CheckRequest) (map[string]interface{}, error) {
	var input map[string]interface{}
	var bs []byte

	bs, err := protojson.Marshal(req)
	if err != nil {
		return nil, err
	}

	err = util.UnmarshalJSON(bs, &input)
	if err != nil {
		return nil, err
	}

	path := req.GetAttributes().GetRequest().GetHttp().GetPath()
	parsedPath, parsedQuery, err := getParsedPathAndQuery(path)
	if err != nil {
		return nil, err
	}

	input["parsed_path"] = parsedPath
	input["parsed_query"] = parsedQuery

	return input, nil
}

func getParsedPathAndQuery(path string) ([]interface{}, map[string]interface{}, error) {
	parsedURL, err := url.Parse(path)
	if err != nil {
		return nil, nil, err
	}

	parsedPath := strings.Split(strings.TrimLeft(parsedURL.Path, "/"), "/")
	parsedPathInterface := make([]interface{}, len(parsedPath))
	for i, v := range parsedPath {
		parsedPathInterface[i] = v
	}

	parsedQueryInterface := make(map[string]interface{})
	for paramKey, paramValues := range parsedURL.Query() {
		queryValues := make([]interface{}, len(paramValues))
		for i, v := range paramValues {
			queryValues[i] = v
		}
		parsedQueryInterface[paramKey] = queryValues
	}

	return parsedPathInterface, parsedQueryInterface, nil
}
