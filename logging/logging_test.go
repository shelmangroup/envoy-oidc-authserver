package logging

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLogLevelIllegal(t *testing.T) {
	_, err := NewLogger("no_such_level", false)
	require.Error(t, err)
}

func TestLogLevels(t *testing.T) {
	scenarios := []struct {
		level   string
		enabled slog.Level
	}{
		{level: "debug", enabled: slog.LevelDebug},
		{level: "info", enabled: slog.LevelInfo},
		{level: "warn", enabled: slog.LevelWarn},
		{level: "error", enabled: slog.LevelError},
	}
	for i, scenario := range scenarios {
		t.Run(scenario.level, func(t *testing.T) {
			logger, err := NewLogger(scenario.level, true)
			require.NoError(t, err)
			require.Equal(
				t,
				logger.Enabled(context.Background(), scenario.enabled),
				true,
			)
			if i > 0 {
				require.Equal(
					t,
					logger.Enabled(context.Background(), scenarios[i-1].enabled),
					false,
				)
			}
		})
	}
}
