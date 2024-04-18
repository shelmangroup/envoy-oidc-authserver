package telemetry

import (
	"context"
	"errors"
	"log/slog"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.23.1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Global variables
var (
	ErrNoTracerProvider = errors.New("no tracer provider")
)

// SetupTracing sets up the OpenTelemetry tracing system.
func SetupTracing(otlpAddr string, sampleRatio float64) func() {
	ctx := context.Background()
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName("envoy-oidc-authserver"),
		),
	)
	if err != nil {
		slog.Error("Failed to setup otel tracing", err)
		return nil
	}

	conn, err := grpc.DialContext(ctx, otlpAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		slog.Error("Failed to connect to the otel tracing agent", err)
		return nil
	}
	// Set up a trace exporter
	traceExporter, err := otlptracegrpc.New(ctx, otlptracegrpc.WithGRPCConn(conn))
	if err != nil {
		slog.Error("Failed to create the trace exporter", err)
		return nil
	}

	// Use RatioBasedSampler to sample a fixed rate of traces.
	var sampler sdktrace.Sampler
	if sampleRatio == 1.0 {
		sampler = sdktrace.AlwaysSample()
	} else {
		sampler = sdktrace.TraceIDRatioBased(sampleRatio)
	}

	// Register the trace exporter with a TracerProvider, using a batch
	// span processor to aggregate spans before export.
	bsp := sdktrace.NewBatchSpanProcessor(traceExporter)
	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sampler),
		sdktrace.WithResource(res),
		sdktrace.WithSpanProcessor(bsp),
	)
	otel.SetTracerProvider(tracerProvider)

	// Register the trace context and baggage propagators so data is propagated across services/processes.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return func() {
		err := tracerProvider.Shutdown(ctx)
		if err != nil {
			slog.Error("Failed to shutdown the tracer provider", err)
		}
	}
}
