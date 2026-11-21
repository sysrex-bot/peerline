package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sysrex/peerline/internal/clock/clocktest"
	"github.com/sysrex/peerline/internal/store"
)

func TestInviteMintedPeersCannotIssuePairingOrEmailInvites(t *testing.T) {
	const regToken = "test-reg-token"
	regHdr := map[string]string{"X-Peerline-Register-Token": regToken}
	clk := clocktest.New(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	st, err := store.OpenWithOptions(t.TempDir()+"/t.db", store.OpenOptions{Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := Config{Clock: clk, RegisterToken: regToken}
	prepareTestConfig(t, st, &cfg)
	apiSrv, err := New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(apiSrv.Stop)
	srv := httptest.NewServer(apiSrv.Handler())
	t.Cleanup(srv.Close)

	alice := registerAs(t, srv, "alice", regHdr)
	resp, body := alice.do("POST", "/v1/invites", map[string]any{
		"scopes":           []string{"messages"},
		"generate_pairing": true,
		"ttl_seconds":      3600,
	}, nil)
	want(t, resp, body, 201)
	var inv struct {
		PairingURL string `json:"pairing_url"`
	}
	if err := json.Unmarshal(body, &inv); err != nil {
		t.Fatal(err)
	}
	path := "/v1/pairing/" + strings.Split(inv.PairingURL, "/v1/pairing/")[1]

	anon := &client{t: t, srv: srv}
	resp, body = anon.do("POST", path, map[string]any{"name": "bob"}, nil)
	want(t, resp, body, 201)
	var bobCreds struct {
		PeerID string `json:"peer_id"`
		APIKey string `json:"api_key"`
	}
	if err := json.Unmarshal(body, &bobCreds); err != nil {
		t.Fatal(err)
	}
	bob := &client{t: t, srv: srv, key: bobCreds.APIKey}

	resp, body = bob.do("POST", "/v1/invites", map[string]any{
		"scopes":           []string{"messages"},
		"generate_pairing": true,
	}, nil)
	want(t, resp, body, 403)
	if !strings.Contains(string(body), "cannot send email invites or generate pairing links") {
		t.Fatalf("unexpected body: %s", body)
	}

	resp, body = bob.do("POST", "/v1/invites", map[string]any{
		"scopes":   []string{"messages"},
		"to_email": "carol@example.com",
	}, nil)
	want(t, resp, body, 403)

	// Ordinary code invites remain available, and operator-created peers can still mint pairing links.
	resp, body = bob.do("POST", "/v1/invites", map[string]any{
		"scopes": []string{"messages"},
	}, nil)
	want(t, resp, body, 201)

	resp, body = alice.do("POST", "/v1/invites", map[string]any{
		"scopes":           []string{"messages"},
		"generate_pairing": true,
	}, nil)
	want(t, resp, body, 201)
}
