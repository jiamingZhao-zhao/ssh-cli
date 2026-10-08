// Package exitcode defines process statuses for ssh-cli.
// Remote command statuses are passed through unchanged. Tool failures use 250+.
package exitcode

import (
	"errors"
	"fmt"
)

const (
	OK      = 0
	Usage   = 250
	Connect = 251
	Auth    = 252
	Denied  = 253
	HostKey = 254
)

// Error is a tool failure that should be printed and mapped to Code.
type Error struct {
	Code int
	Msg  string
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Msg
}

// New builds a printable tool error with a stable exit code.
func New(code int, format string, args ...any) error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Silent is an exit status that has already been reported to the user.
type Silent int

func (s Silent) Error() string { return fmt.Sprintf("exit %d", int(s)) }

// From maps an error to a process status. Silent statuses are not handled here.
func From(err error) int {
	if err == nil {
		return OK
	}
	var e *Error
	if errors.As(err, &e) && e != nil {
		return e.Code
	}
	return Usage
}
