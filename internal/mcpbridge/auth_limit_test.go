package mcpbridge

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sysrex/peerline/internal/msg"
)

func newIntrospectServer(t *testing.T, hits *atomic.Int32, handler func(w http.ResponseWriter, r *http.Request, body map[string]any)) *httptest.Server {
	t.Helper()
	validExp := time.Now().Add(time.Hour).Unix()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		id, secret, ok := r.BasicAuth()
		if !ok || id != "id" || secret != "secret" {
			t.Error("missing introspection credentials")
		}
		body := map[string]any{"active": true, "sub": "subject-a", "iss": "https://issuer.example", "aud": "https://mcp.example/mcp", "scope": "peerline:messages", "exp": validExp}
		if handler != nil {
			handler(w, r, body)
			return
		}
		json.NewEncoder(w).Encode(body)
	}))
}

func newTestAuthenticator(t *testing.T, introspectURL string) *OAuthAuthenticator {
	t.Helper()
	t.Setenv("TEST_OAUTH_ID", "id")
	t.Setenv("TEST_OAUTH_SECRET", "secret")
	account := Account{ID: "a", Subject: "subject-a", PeerID: "peer-a", RelayURL: "https://relay.example", APIKeyEnv: "KEY_A"}
	a, err := NewOAuthAuthenticator(OAuthConfig{ResourceURL: "https://mcp.example/mcp", IssuerURL: "https://issuer.example", IntrospectionURL: introspectURL, ClientIDEnv: "TEST_OAUTH_ID", ClientSecretEnv: "TEST_OAUTH_SECRET", Scopes: []string{"peerline:messages"}, Accounts: []Account{account}})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestIntrospectionResultCache(t *testing.T) {
	var hits atomic.Int32
	var mu sync.Mutex
	active := true
	srv := newIntrospectServer(t, &hits, func(w http.ResponseWriter, r *http.Request, body map[string]any) {
		mu.Lock()
		body["active"] = active
		mu.Unlock()
		json.NewEncoder(w).Encode(body)
	})
	defer srv.Close()
	a := newTestAuthenticator(t, srv.URL)
	a.client = srv.Client()
	now := time.Now()
	a.now = func() time.Time { return now }

	req := httptest.NewRequest("POST", "https://mcp.example/mcp", nil)
	req.Header.Set("Authorization", "Bearer access-token")
	if _, err := a.Authenticate(req); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Authenticate(req); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 {
		t.Fatalf("expected 1 introspection, got %d", hits.Load())
	}

	mu.Lock()
	active = false
	mu.Unlock()
	if _, err := a.Authenticate(req); err != nil {
		t.Fatal("cached positive result should still succeed inside TTL")
	}

	now = now.Add(defaultPositiveCacheTTL + time.Second)
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("revoked token accepted after cache expiry")
	}
	if hits.Load() != 2 {
		t.Fatalf("expected 2 introspections after TTL, got %d", hits.Load())
	}

	// Negative result is cached too.
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("expected cached denial")
	}
	if hits.Load() != 2 {
		t.Fatalf("negative cache should suppress a third call, got %d", hits.Load())
	}
}

func TestIntrospectionConcurrencyCap(t *testing.T) {
	var hits, inflight, maxInflight atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	srv := newIntrospectServer(t, &hits, func(w http.ResponseWriter, r *http.Request, body map[string]any) {
		n := inflight.Add(1)
		for {
			prev := maxInflight.Load()
			if n <= prev || maxInflight.CompareAndSwap(prev, n) {
				break
			}
		}
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		inflight.Add(-1)
		json.NewEncoder(w).Encode(body)
	})
	defer srv.Close()
	a := newTestAuthenticator(t, srv.URL)
	a.client = srv.Client()
	a.posTTL = 0
	a.negTTL = 0

	const extra = 4
	var wg sync.WaitGroup
	for i := 0; i < defaultIntrospectLimit+extra; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest("POST", "https://mcp.example/mcp", nil)
			req.Header.Set("Authorization", "Bearer access-token")
			if _, err := a.Authenticate(req); err != nil {
				t.Error(err)
			}
		}()
	}
	for i := 0; i < defaultIntrospectLimit; i++ {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for semaphore holders")
		}
	}
	if maxInflight.Load() != int32(defaultIntrospectLimit) {
		t.Fatalf("max inflight = %d, want %d", maxInflight.Load(), defaultIntrospectLimit)
	}
	close(release)
	wg.Wait()
}

func TestMCPAuthRateLimit(t *testing.T) {
	s, _ := rpcTestServer()
	s.AuthLim = msg.NewLimiter(30, 5)
	h := s.Handler()
	reqFor := func() *http.Request {
		req := httptest.NewRequest("POST", "https://mcp.example/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		req.RemoteAddr = "203.0.113.9:12345"
		req.Header.Set("Authorization", "Bearer a")
		req.Header.Set("Content-Type", "application/json")
		return req
	}
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, reqFor())
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d rate limited too early", i+1)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqFor())
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("got %d, want 429", w.Code)
	}
}

type unavailableAuth struct{}

func (unavailableAuth) Authenticate(*http.Request) (Account, error) {
	return Account{}, errAuthorizationUnavailable
}

func TestMCPAuthUnavailableIsServiceUnavailable(t *testing.T) {
	s := &Server{Auth: unavailableAuth{}, Relay: &rpcRelay{}, ResourceURL: "https://mcp.example/mcp", Challenge: `Bearer realm="test"`}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "https://mcp.example/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Authorization", "Bearer a")
	req.Header.Set("Content-Type", "application/json")
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503", w.Code)
	}
	if w.Header().Get("WWW-Authenticate") != "" {
		t.Fatal("unavailable should not look like a client auth challenge")
	}
}
