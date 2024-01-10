package logging

import (
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/lmittmann/tint"
	"github.com/mattn/go-isatty"
)

func NewLogger(level string, json bool) (*slog.Logger, error) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "info":
		lvl = slog.LevelInfo
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		return nil, errors.New("invalid log level")
	}

	var handler slog.Handler

	if json {
		handler = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			Level: lvl,
		})
	} else {
		handler = tint.NewHandler(os.Stderr, &tint.Options{
			Level:      lvl,
			TimeFormat: time.TimeOnly,
			NoColor:    !isatty.IsTerminal(os.Stderr.Fd()),
		})
	}
	logger := slog.New(handler)
	return logger, nil
}
