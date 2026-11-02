package cli

import "context"

type connectionInfo struct {
	Mode        string `json:"mode"`
	Connected   bool   `json:"connected"`
	Reused      bool   `json:"reused"`
	ConnectMS   int64  `json:"connectMs"`
	ExecutionMS int64  `json:"executionMs"`
	Outcome     string `json:"outcome"`
}

// Copy only invocation settings; never copy the mutex or share writable result state.
func (a *App) queryCopy(ctx context.Context) *App {
	return &App{Dir: a.Dir, In: a.In, Out: a.Out, Err: a.Err, JSON: a.JSON, Yes: a.Yes, Insecure: a.Insecure, UseDaemon: a.UseDaemon, AutoDaemon: a.AutoDaemon, OperationContext: ctx, MaxLineBytes: a.MaxLineBytes, MaxOutputBytes: a.MaxOutputBytes}
}
