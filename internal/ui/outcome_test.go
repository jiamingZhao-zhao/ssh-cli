package ui

import (
	"context"
	"errors"
	"testing"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
)

func TestExecFailureStatus(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{context.DeadlineExceeded, "timeout"},
		{exitcode.New(exitcode.Auth, "authentication failed"), "auth"},
		{exitcode.New(exitcode.Connect, "connection failed"), "connect"},
		{exitcode.New(exitcode.HostKey, "host key changed"), "connect"},
		{exitcode.New(exitcode.Denied, "policy denied"), "denied"},
		{errors.New("stream interrupted"), "error"},
	} {
		if got := execFailureStatus(context.Background(), tc.err); got != tc.want {
			t.Errorf("%v: %s, want %s", tc.err, got, tc.want)
		}
	}
}
