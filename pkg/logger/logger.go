// Package logger provides structured logging for namd.
// Structured logging means every log entry is a set of key=value pairs,
// not just a plain string. This makes logs parseable by tools like
// grep, jq, Datadog, Grafana — critical for a public service.
//
// Example output:
//
//	2026-05-10T01:00:00Z level=INFO  component=server event=tunnel_registered name=gabriel ip=102.34.x.x
//	2026-05-10T01:00:01Z level=WARN  component=auth   event=auth_failed      name=gabriel ip=1.2.3.4 reason=invalid_token
//	2026-05-10T01:00:02Z level=ERROR component=server event=stream_error      name=gabriel err=connection_reset
package logger

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Level controls which log messages are emitted.
type Level int

const (
	DEBUG Level = iota // verbose — development only
	INFO               // normal operation
	WARN               // something unexpected but recoverable
	ERROR              // something failed
	AUDIT              // security-relevant events — always logged regardless of level
)

func (l Level) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO "
	case WARN:
		return "WARN "
	case ERROR:
		return "ERROR"
	case AUDIT:
		return "AUDIT"
	default:
		return "UNKNOWN"
	}
}

// Logger is a structured logger.
// It writes to an io.Writer (stdout by default, file in production).
// Fields are attached to give context to every log line.
type Logger struct {
	mu        sync.Mutex
	out       io.Writer
	minLevel  Level
	component string // which part of namd this logger is for
}

// New creates a logger for a specific component.
// component — "server", "auth", "tunnel", "webhook" etc.
func New(component string) *Logger {
	return &Logger{
		out:       os.Stdout,
		minLevel:  INFO,
		component: component,
	}
}

// NewWithLevel creates a logger with a specific minimum level.
func NewWithLevel(component string, level Level) *Logger {
	l := New(component)
	l.minLevel = level
	return l
}

// SetOutput changes where logs are written.
// In production: write to a file or syslog.
func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.out = w
}

// Fields is a map of key=value pairs attached to a log entry.
// Using a map keeps the API clean — callers build fields naturally.
type Fields map[string]interface{}

// Info logs at INFO level.
func (l *Logger) Info(event string, fields Fields) {
	l.log(INFO, event, fields)
}

// Warn logs at WARN level.
func (l *Logger) Warn(event string, fields Fields) {
	l.log(WARN, event, fields)
}

// Error logs at ERROR level.
func (l *Logger) Error(event string, fields Fields) {
	l.log(ERROR, event, fields)
}

// Debug logs at DEBUG level — only emitted if minLevel is DEBUG.
func (l *Logger) Debug(event string, fields Fields) {
	l.log(DEBUG, event, fields)
}

// Audit logs security-relevant events — ALWAYS emitted regardless of minLevel.
// Use for: auth failures, tunnel registrations, suspicious requests.
// Audit logs should never be suppressed — they are the security trail.
func (l *Logger) Audit(event string, fields Fields) {
	l.log(AUDIT, event, fields)
}

// log is the internal write function.
// It builds the log line and writes it atomically.
func (l *Logger) log(level Level, event string, fields Fields) {
	// AUDIT always logs. Others check minLevel.
	if level != AUDIT && level < l.minLevel {
		return
	}

	// Build the log line.
	// Format: timestamp level component event key=value key=value ...
	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")

	line := fmt.Sprintf("%s level=%s component=%-8s event=%s",
		now, level.String(), l.component, event,
	)

	// Append fields in sorted order for consistent output.
	// We do not sort here for performance — use a slice of known fields
	// if you need deterministic ordering in production.
	for k, v := range fields {
		line += fmt.Sprintf(" %s=%v", k, v)
	}

	line += "\n"

	// Lock before writing — multiple goroutines log simultaneously.
	// Without the lock, lines from different goroutines could interleave.
	l.mu.Lock()
	defer l.mu.Unlock()
	l.out.Write([]byte(line))
}

// ── Package-level default logger ──────────────────────────────────────────────
// For convenience — components that do not need a named logger can use these.

var defaultLogger = New("namd")

func Info(event string, fields Fields) {
	defaultLogger.Info(event, fields)
}

func Warn(event string, fields Fields) {
	defaultLogger.Warn(event, fields)
}

func Error(event string, fields Fields) {
	defaultLogger.Error(event, fields)
}

func Audit(event string, fields Fields) {
	defaultLogger.Audit(event, fields)
}

func Debug(event string, fields Fields) {
	defaultLogger.Debug(event, fields)
}
