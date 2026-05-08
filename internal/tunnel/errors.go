package tunnel

import "errors"

// These are the sentinel errors for the tunnel package.
//
// A sentinel error is a package-level error variable that callers
// can check against using errors.Is().
//
// Why not just return fmt.Errorf("tunnel not found") as a string?
// Because string matching is fragile. If we ever change the message,
// every caller that checks the string breaks silently.
// With sentinel errors, callers do:
//
//	errors.Is(err, tunnel.ErrNotFound)
//
// That never breaks regardless of message changes.
//
// errors.New creates a simple error with a fixed message.
// It is unexported from the errors package — we own these variables.
var (
	// ErrNotFound is returned when a tunnel name does not exist in the registry.
	ErrNotFound = errors.New("tunnel not found")

	// ErrAlreadyExists is returned when registering a name that is already taken.
	ErrAlreadyExists = errors.New("tunnel name already registered")

	// ErrConnectionClosed is returned when trying to use a tunnel whose
	// underlying TCP connection has been closed.
	ErrConnectionClosed = errors.New("tunnel connection is closed")
)
