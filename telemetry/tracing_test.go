package telemetry

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test SetupTracing
func TestSetupTracing(t *testing.T) {
	_, err := SetupTracing(context.Background())
	assert.Nil(t, err)
}
