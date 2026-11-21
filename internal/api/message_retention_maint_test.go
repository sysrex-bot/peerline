package api

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"
)

func TestMaintenanceManager_MessageRetentionOptional(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	off := &fakePurger{called: make(chan struct{}, 1)}
	m := NewMaintenanceManager(ctx, off, log, nil, 30*24*60*60, 6)
	defer m.Stop()
	select {
	case <-off.called:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for startup purge")
	}
	// Give the rest of the startup tick a moment to finish.
	time.Sleep(20 * time.Millisecond)
	if len(off.getMsgCalls()) != 0 {
		t.Fatalf("message purge should be skipped when unset, got %v", off.getMsgCalls())
	}

	on := &fakePurger{called: make(chan struct{}, 1), msgReturnCount: 3}
	m2 := NewMaintenanceManager(ctx, on, log, nil, 30*24*60*60, 6, WithMessageRetention(7*24*time.Hour))
	defer m2.Stop()
	select {
	case <-on.called:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for startup purge")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if calls := on.getMsgCalls(); len(calls) >= 1 {
			if calls[0] != int64(7*24*60*60) {
				t.Fatalf("message retention %d, want 7 days", calls[0])
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("expected message purge at startup when configured")
}
