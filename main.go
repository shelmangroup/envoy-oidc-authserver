package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"
	"github.com/peterbourgon/ff/v4/ffyaml"

	"github.com/shelmangroup/envoy-oidc-authserver/authz"
	"github.com/shelmangroup/envoy-oidc-authserver/logging"
	"github.com/shelmangroup/envoy-oidc-authserver/server"
	"github.com/shelmangroup/envoy-oidc-authserver/telemetry"
)

func main() {
	fs := ff.NewFlagSet("envoy-oidc-authserver")
	addr := fs.String('s', "listen-addr", ":8080", "address to listen on")
	otlpAddr := fs.StringLong("otlp-addr", "", "address to send OTLP traces to")
	otlpSampleRatio := fs.Float64Long("otlp-sample-ratio", 1.0, "OTLP sample ratio, default is always sample")
	redisAddrs := fs.StringSet('r', "redis-addrs", "sentinel addresses to use for Redis cache, omit for in memory cache")
	secretKey := fs.StringLong("secret-key", "", "secret key used to encrypt session tokens")
	providersConfig := fs.String('c', "providers-config", "", "OIDC procider configuration file")
	logJson := fs.BoolLong("log-json", "log in JSON format")
	logLevel := fs.StringLong("log-level", "info", "log level (debug, info, warn, error)")

	if err := ff.Parse(fs, os.Args[1:],
		ff.WithEnvVarPrefix("ENVOY_AUTHZ"),
		ff.WithEnvVarSplit(","),
		ff.WithConfigFileFlag("config"),
		ff.WithConfigFileParser(ffyaml.Parse),
	); err != nil {
		fmt.Printf("%s", ffhelp.Flags(fs))
		slog.Error("flags", slog.String("err", err.Error()))
		os.Exit(1)
	}

	// Secret key need to be 32 bytes
	if len(*secretKey) != 32 {
		slog.Error("Secret key must be 32 bytes long", slog.Int("current_len", len(*secretKey)))
		os.Exit(1)
	}

	logger, err := logging.NewLogger(*logLevel, *logJson)
	if err != nil {
		slog.Error("Logging error", err)
		os.Exit(1)
	}
	slog.SetDefault(logger)

	slog.Info("Hello from Shelman Group Envoy OIDC Authserver!")

	// Setup tracing
	if *otlpAddr != "" {
		shutdown := telemetry.SetupTracing(*otlpAddr, *otlpSampleRatio)
		defer shutdown()
	}

	// Load OIDC provider config file
	c, err := authz.ConfigFromYamlFile(*providersConfig)
	if err != nil {
		slog.Error("Provider configuration error", err)
		os.Exit(1)
	}

	// Create new server
	s := server.NewServer(*addr, authz.NewService(c, *secretKey, *redisAddrs))
	defer func() {
		err := s.Shutdown()
		if err != nil {
			slog.Error("HTTP Server shutdown error", err)
		}
	}()

	// Start the server
	go func() {
		if err := s.Serve(); err != nil {
			slog.Error("HTTP Server error", slog.String("err", err.Error()))
			os.Exit(1)
		}
	}()

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	// Block until we receive our signal.
	<-done
}
