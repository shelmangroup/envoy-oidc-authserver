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
		slog.Info("registering service", slog.String("name", s.Name()))
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

	// Create a new HTTP server
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
	slog.Info("Start HTTP server", slog.String("addr", s.httpServer.Addr))
	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer func() {
		cancel()
	}()

	slog.Info("Gracefully shutting down HTTP server")
	return s.httpServer.Shutdown(ctx)
}
