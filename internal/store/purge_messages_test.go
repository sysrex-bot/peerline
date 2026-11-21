package store

import (
	"context"
	"testing"
	"time"

	"github.com/sysrex/peerline/internal/clock/clocktest"
)

func TestPurgeExpiredMessages(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(time.Unix(1_700_000_000, 0))
	s, err := OpenWithOptions(":memory:", OpenOptions{Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CreatePeer(ctx, "a", "alice", "ha", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePeer(ctx, "b", "bob", "hb", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertMessage(ctx, &Message{From: "a", To: "b", Type: "note", Body: "old"}); err != nil {
		t.Fatal(err)
	}
	clk.Advance(48 * time.Hour)
	if err := s.InsertMessage(ctx, &Message{From: "a", To: "b", Type: "note", Body: "new"}); err != nil {
		t.Fatal(err)
	}

	deleted, more, err := s.PurgeExpiredMessages(ctx, 0)
	if err != nil || deleted != 0 || more {
		t.Fatalf("zero retention should be a no-op: deleted=%d more=%v err=%v", deleted, more, err)
	}
	page, err := s.Inbox(ctx, "b", 0, 10)
	if err != nil || len(page) != 2 {
		t.Fatalf("expected both messages still present, got %d, err=%v", len(page), err)
	}

	deleted, more, err = s.PurgeExpiredMessages(ctx, 24*60*60)
	if err != nil || more {
		t.Fatalf("purge: deleted=%d more=%v err=%v", deleted, more, err)
	}
	if deleted != 1 {
		t.Fatalf("deleted %d, want 1", deleted)
	}
	page, err = s.Inbox(ctx, "b", 0, 10)
	if err != nil || len(page) != 1 || page[0].Body != "new" {
		t.Fatalf("expected only the new message, got %#v err=%v", page, err)
	}
}

func TestPurgeExpiredMessagesDefaultKeepsAll(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(time.Unix(1_700_000_000, 0))
	s, err := OpenWithOptions(":memory:", OpenOptions{Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CreatePeer(ctx, "a", "alice", "ha", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePeer(ctx, "b", "bob", "hb", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertMessage(ctx, &Message{From: "a", To: "b", Type: "note", Body: "keep"}); err != nil {
		t.Fatal(err)
	}
	clk.Advance(400 * 24 * time.Hour)
	deleted, more, err := s.PurgeExpiredMessages(ctx, 0)
	if err != nil || deleted != 0 || more {
		t.Fatalf("deleted=%d more=%v err=%v", deleted, more, err)
	}
	page, err := s.Inbox(ctx, "b", 0, 10)
	if err != nil || len(page) != 1 {
		t.Fatalf("got %d messages, err=%v", len(page), err)
	}
}
