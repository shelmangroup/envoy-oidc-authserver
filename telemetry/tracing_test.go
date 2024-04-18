package telemetry

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test SetupTracing
func TestSetupTracing(t *testing.T) {
	assert.NotNil(t, SetupTracing("localhost:4317", 1.0))
	assert.NotNil(t, SetupTracing("localhost:4317", 0.5))
}
