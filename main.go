package main

import (
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/peterbourgon/ff/v3"
	"github.com/peterbourgon/ff/v3/ffyaml"

	"github.com/shelmangroup/envoy-oidc-authserver/authz"
	"github.com/shelmangroup/envoy-oidc-authserver/logging"
	"github.com/shelmangroup/envoy-oidc-authserver/server"
	"github.com/shelmangroup/envoy-oidc-authserver/telemetry"
)

func main() {
	fs := flag.NewFlagSet("envoy-oidc-authserver", flag.ContinueOnError)
	addr := fs.String("listen-addr", ":8080", "address to listen on")
	otlpAddr := fs.String("otlp-addr", ":4317", "address to send OTLP traces to")
	opaURL := fs.String("opa-url", "", "base url to send OPA requests to")
	secretKey := fs.String("secret-key", "", "secret key used to encrypt JWT tokens")
	providersConfig := fs.String("providers-config", "", "oidc config file")
	logJson := fs.Bool("log-json", false, "log in JSON format")
	logLevel := fs.String("log-level", "info", "log level (debug, info, warn, error)")

	err := ff.Parse(fs, os.Args[1:],
		ff.WithEnvVarPrefix("ENVOY_AUTHZ"),
		ff.WithConfigFileFlag("config"),
		ff.WithConfigFileParser(ffyaml.Parser),
	)
	if err != nil {
		slog.Error("Configuration error", err)
		os.Exit(1)
	}

	// check secret key to be 32 bytes
	if len(*secretKey) != 32 {
		slog.Error("Secret key must be 32 bytes")
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
	shutdown := telemetry.SetupTracing(*otlpAddr, "dev")
	defer shutdown()

	// read config file
	c, err := authz.ConfigFromXmlFile(*providersConfig)
	if err != nil {
		slog.Error("Provider configuration error", err)
		os.Exit(1)
	}

	// Create new server
	s := server.NewServer(*addr, authz.NewService(c, *opaURL, *secretKey))
	defer func() {
		err := s.Shutdown()
		if err != nil {
			slog.Error("HTTP Server shutdown error", err)
		}
	}()

	// Start the server
	go func() {
		if err := s.Serve(); err != nil {
			slog.Error("HTTP Server error", err)
			os.Exit(1)
		}
	}()

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	// Block until we receive our signal.
	<-done
}
