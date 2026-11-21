package store

import (
	"context"
	"testing"
	"time"
)

func TestRegisterAndAcceptByPairingMarksCreatedViaInvite(t *testing.T) {
	ctx := context.Background()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CreatePeer(ctx, "alice", "Alice", "ha", "", ""); err != nil {
		t.Fatal(err)
	}
	via, err := s.CreatedViaInvite(ctx, "alice")
	if err != nil || via {
		t.Fatalf("operator-created peer should not be marked, via=%v err=%v", via, err)
	}
	if err := s.CreateInviteWithPairing(ctx, "code", "pair", "alice", []string{"messages"}, nil, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterAndAcceptByPairing(ctx, "pair", "bob", "Bob", "hb", "", "", nil, nil); err != nil {
		t.Fatal(err)
	}
	via, err = s.CreatedViaInvite(ctx, "bob")
	if err != nil || !via {
		t.Fatalf("pairing-created peer should be marked, via=%v err=%v", via, err)
	}
}
