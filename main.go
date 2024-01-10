package main

import (
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/peterbourgon/ff/v3"
	"github.com/peterbourgon/ff/v3/ffyaml"

	"github.com/shelmangroup/shelman-authz/authz"
	"github.com/shelmangroup/shelman-authz/server"
	"github.com/shelmangroup/shelman-authz/store"
	"github.com/shelmangroup/shelman-authz/telemetry"
)

func main() {
	fs := flag.NewFlagSet("shelman-authz", flag.ContinueOnError)
	addr := fs.String("listen-addr", ":8080", "address to listen on")
	otlpAddr := fs.String("otlp-addr", ":4317", "address to send OTLP traces to")
	providersConfig := fs.String("providers-config", "", "oidc config file")
	// logJson := fs.Bool("log-json", false, "log in JSON format")
	// logLevel := fs.String("log-level", "info", "log level (debug, info, warn, error)")

	err := ff.Parse(fs, os.Args[1:],
		ff.WithEnvVarPrefix("SHELMAN_AUTHZ"),
		ff.WithConfigFileFlag("config"),
		ff.WithConfigFileParser(ffyaml.Parser),
	)
	if err != nil {
		slog.Error("Configuration error", err)
		os.Exit(1)
	}

	slog.Info("🛠️ Hello Shelman Authz! 🛠️")

	// Setup tracing
	shutdown := telemetry.SetupTracing(*otlpAddr, "dev")
	defer shutdown()

	// read config file
	c, err := authz.ConfigFromXmlFile(*providersConfig)
	if err != nil {
		slog.Error("Provider Configuration error", err)
		os.Exit(1)
	}

	//init session store
	sessionStore := store.NewSessionStore(nil, 0)

	// Create new server
	s := server.NewServer(*addr, authz.NewService(c, sessionStore))
	defer s.Shutdown()

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
