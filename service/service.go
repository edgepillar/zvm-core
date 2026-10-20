// Package service holds the few things every long-running ZVM process does the
// same way: stop on a signal, and wait for a dependency that is not up yet.
//
// Each of these started as an unexported helper in cmd/zvm, shared by the node,
// the relayer and the bridge because all three come up inside a compose file
// where the thing they dial may not be listening for another few seconds.
package service

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// SignalContext is cancelled on the first interrupt or SIGTERM. A second
// signal is not caught, so an operator who means it can still kill the process.
func SignalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// WaitFor retries fn every two seconds until it succeeds or ctx ends. It is for
// startup dependencies only — a node that cannot reach its L1 yet should wait,
// not exit, because exiting inside a restart loop hides which dependency is
// actually missing. Every tenth attempt is logged so a wait that is never going
// to end still says what it is waiting for.
func WaitFor[T any](ctx context.Context, what string, fn func() (T, error)) (T, error) {
	var zero T
	for attempt := 0; ; attempt++ {
		v, err := fn()
		if err == nil {
			return v, nil
		}
		if attempt%10 == 0 {
			slog.Warn("waiting for dependency", "what", what, "err", err)
		}
		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}
