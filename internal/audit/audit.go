// Package audit is the extension point for the local audit log (PLAN F20).
// Iteration 1 records nothing; later iterations can replace Log.
package audit

import "time"

// Event is one command execution. Passwords are never included.
type Event struct {
	Time     time.Time
	Env      string
	Group    string
	Host     string
	Command  string
	Rule     string
	ExitCode int
}

// Logger records execution events.
type Logger interface {
	Record(Event)
}

// Nop discards events.
type Nop struct{}

func (Nop) Record(Event) {}

// Log is the process-wide logger. It defaults to a no-op.
var Log Logger = Nop{}
