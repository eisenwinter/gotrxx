/*
Package logging abstracts structured logging,
in which log records include a message,
a severity level, and various other attributes
expressed as key-value pairs.

for now it basically wraps slog
*/
package logging

import (
	"context"
	"log/slog"
)

// Logger abstracts away logging needs for easier refactors in the future
type Logger interface {
	Debug(msg string, args ...any)
	DebugContext(ctx context.Context, msg string, args ...any)
	Error(msg string, args ...any)
	ErrorContext(ctx context.Context, msg string, args ...any)
	Info(msg string, args ...any)
	InfoContext(ctx context.Context, msg string, args ...any)
	Warn(msg string, args ...any)
	WarnContext(ctx context.Context, msg string, args ...any)
	With(args ...any) Logger
	WithGroup(name string) Logger
	Log(ctx context.Context, level int, msg string, args ...any)
}

type wrapper struct {
	s *slog.Logger
}

// Debug implements Logger.
func (w *wrapper) Debug(msg string, args ...any) {
	w.s.Debug(msg, args...)
}

// DebugContext implements Logger.
func (w *wrapper) DebugContext(ctx context.Context, msg string, args ...any) {
	w.s.DebugContext(ctx, msg, args...)
}

// Error implements Logger.
func (w *wrapper) Error(msg string, args ...any) {
	w.s.Error(msg, args...)
}

// ErrorContext implements Logger.
func (w *wrapper) ErrorContext(ctx context.Context, msg string, args ...any) {
	w.s.ErrorContext(ctx, msg, args...)
}

// Info implements Logger.
func (w *wrapper) Info(msg string, args ...any) {
	w.s.Info(msg, args...)
}

// InfoContext implements Logger.
func (w *wrapper) InfoContext(ctx context.Context, msg string, args ...any) {
	w.s.InfoContext(ctx, msg, args...)
}

// Warn implements Logger.
func (w *wrapper) Warn(msg string, args ...any) {
	w.s.Warn(msg, args...)
}

// WarnContext implements Logger.
func (w *wrapper) WarnContext(ctx context.Context, msg string, args ...any) {
	w.s.WarnContext(ctx, msg, args...)
}

// With implements Logger.
func (w *wrapper) With(args ...any) Logger {
	return wrapSlog(w.s.With(args...))
}

// WithGroup implements Logger.
func (w *wrapper) WithGroup(name string) Logger {
	return wrapSlog(w.s.WithGroup(name))
}

func (w *wrapper) Log(ctx context.Context, level int, msg string, args ...any) {
	w.s.Log(ctx, slog.Level(level), msg, args...)
}

func wrapSlog(s *slog.Logger) Logger {
	return &wrapper{s}
}

func NewFromSlog(logger *slog.Logger) Logger {
	return wrapSlog(logger)
}

type noOpLog struct{}

// Debug implements Logger.
func (n *noOpLog) Debug(msg string, args ...any) {}

// DebugContext implements Logger.
func (n *noOpLog) DebugContext(ctx context.Context, msg string, args ...any) {}

// Error implements Logger.
func (n *noOpLog) Error(msg string, args ...any) {}

// ErrorContext implements Logger.
func (n *noOpLog) ErrorContext(ctx context.Context, msg string, args ...any) {}

// Info implements Logger.
func (n *noOpLog) Info(msg string, args ...any) {}

// InfoContext implements Logger.
func (n *noOpLog) InfoContext(ctx context.Context, msg string, args ...any) {}

// Log implements Logger.
func (n *noOpLog) Log(ctx context.Context, level int, msg string, args ...any) {}

// Warn implements Logger.
func (n *noOpLog) Warn(msg string, args ...any) {}

// WarnContext implements Logger.
func (n *noOpLog) WarnContext(ctx context.Context, msg string, args ...any) {}

// With implements Logger.
func (n *noOpLog) With(args ...any) Logger {
	return n
}

// WithGroup implements Logger.
func (n *noOpLog) WithGroup(name string) Logger {
	return n
}

func NewNoOpLogger() Logger {
	return &noOpLog{}
}
