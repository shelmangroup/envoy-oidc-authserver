package server

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/grpchealth"
	"connectrpc.com/grpcreflect"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/shelmangroup/shelman-authz/telemetry"
)

type Service interface {
	NewHandler() (string, http.Handler)
	Name() string
}

type Server struct {
	httpServer *http.Server
}

// NewServer creates a new server instance
func NewServer(httpAddr string, services ...Service) *Server {
	mux := http.NewServeMux()

	// Register service handlers
	svcNames := make([]string, 0, len(services))
	for _, s := range services {
		mux.Handle(s.NewHandler())
		svcNames = append(svcNames, s.Name())
	}

	// Health check
	checker := grpchealth.NewStaticChecker(svcNames...)
	mux.Handle(grpchealth.NewHandler(checker))

	// gRPC Reflection
	reflector := grpcreflect.NewStaticReflector(svcNames...)
	mux.Handle(grpcreflect.NewHandlerV1(reflector))
	mux.Handle(grpcreflect.NewHandlerV1Alpha(reflector))

	// Setup zpages tracing, nice for local development
	mux.HandleFunc(telemetry.ZPagesPath, telemetry.ZPagesHandlerFunc())

	httpServer := &http.Server{
		Addr:              httpAddr,
		Handler:           h2c.NewHandler(mux, &http2.Server{}),
		ReadHeaderTimeout: 5 * time.Second,
	}

	return &Server{
		httpServer: httpServer,
	}
}

func (s *Server) Serve() error {
	slog.Info("Start HTTP server")
	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer func() {
		cancel()
	}()

	slog.Info("Gracefully shutting down HTTP server")
	s.httpServer.Shutdown(ctx)
}
