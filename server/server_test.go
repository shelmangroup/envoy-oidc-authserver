package server

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

type dummyService struct {
	Service
}

func (s *dummyService) NewHandler() (string, http.Handler) {
	return "dummy/8080", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
}

func (s *dummyService) Name() string {
	return "dummy"
}

// TestServer
func TestServer(t *testing.T) {
	// Should panic if no service is provided
	assert.Panics(t, func() { NewServer("127.0.0.1:8080", nil) })

	// register dummy service which implements Service interface
	s := NewServer("127.0.0.1:8080", &dummyService{})
	assert.NotNil(t, s)
	assert.NoError(t, s.Shutdown())
}
