package mcpbridge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// OAuthConfig uses one trusted external authorization server and immutable
// operator-managed subject/account bindings. The server must support resource-bound
// authorization-code + S256 PKCE and ChatGPT registration/discovery. Introspection
// uses client_secret_basic with environment credentials. No tokens are issued here.
type OAuthConfig struct {
	ResourceURL          string    `json:"resource_url"`
	IssuerURL            string    `json:"issuer_url"`
	IntrospectionURL     string    `json:"introspection_url"`
	ClientIDEnv          string    `json:"client_id_env"`
	ClientSecretEnv      string    `json:"client_secret_env"`
	Scopes               []string  `json:"scopes"`
	Accounts             []Account `json:"-"`
	AllowPrivateNetworks bool      `json:"allow_private_networks"`
}

const (
	defaultPositiveCacheTTL = 15 * time.Second
	defaultNegativeCacheTTL = 5 * time.Second
	defaultIntrospectLimit  = 8
)

type introspectCacheEntry struct {
	until   time.Time
	err     error
	account Account
}

type OAuthAuthenticator struct {
	config   OAuthConfig
	accounts map[string]Account
	client   *http.Client
	now      func() time.Time
	posTTL   time.Duration
	negTTL   time.Duration
	sem      chan struct{}
	cacheMu  sync.Mutex
	cache    map[string]introspectCacheEntry
}

var errAuthentication = errors.New("authentication required")
var errAuthorizationUnavailable = errors.New("authorization verification temporarily unavailable")
var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func NewOAuthAuthenticator(c OAuthConfig) (*OAuthAuthenticator, error) {
	for _, raw := range []string{c.ResourceURL, c.IssuerURL, c.IntrospectionURL} {
		if _, err := validateHTTPSURL(raw); err != nil {
			return nil, errors.New("OAuth URLs must be absolute HTTPS URLs without credentials, queries or fragments")
		}
	}
	if !envName.MatchString(c.ClientIDEnv) || !envName.MatchString(c.ClientSecretEnv) || os.Getenv(c.ClientIDEnv) == "" || os.Getenv(c.ClientSecretEnv) == "" {
		return nil, errors.New("OAuth introspection credential environment variables are required")
	}
	if len(c.Scopes) == 0 {
		return nil, errors.New("at least one OAuth scope required")
	}
	for _, s := range c.Scopes {
		if s == "" || strings.ContainsAny(s, " \t\r\n\"\\") {
			return nil, errors.New("invalid OAuth scope")
		}
	}
	a := &OAuthAuthenticator{
		config:   c,
		accounts: map[string]Account{},
		client:   NewSafeHTTPClient(c.AllowPrivateNetworks),
		now:      time.Now,
		posTTL:   defaultPositiveCacheTTL,
		negTTL:   defaultNegativeCacheTTL,
		sem:      make(chan struct{}, defaultIntrospectLimit),
		cache:    map[string]introspectCacheEntry{},
	}
	ids, keys := map[string]bool{}, map[string]bool{}
	credentialValues := map[string]bool{}
	peerBindings := map[string]bool{}
	for _, account := range c.Accounts {
		if account.ID == "" || account.Subject == "" || account.PeerID == "" || !envName.MatchString(account.APIKeyEnv) {
			return nil, errors.New("account requires immutable ID, subject, peer ID and API key environment name")
		}
		if _, err := validateHTTPSURL(account.RelayURL); err != nil {
			return nil, errors.New("invalid account relay URL")
		}
		if _, ok := a.accounts[account.Subject]; ok || ids[account.ID] || keys[account.APIKeyEnv] {
			return nil, errors.New("account IDs, subjects and API key environment names must be unique")
		}
		key := os.Getenv(account.APIKeyEnv)
		binding := strings.TrimRight(account.RelayURL, "/") + "\x00" + account.PeerID
		if (key != "" && credentialValues[key]) || peerBindings[binding] {
			return nil, errors.New("accounts must have distinct relay credentials and peer bindings")
		}
		if key != "" {
			credentialValues[key] = true
		}
		peerBindings[binding] = true
		ids[account.ID] = true
		keys[account.APIKeyEnv] = true
		a.accounts[account.Subject] = cloneAccount(account)
	}
	a.config.Accounts = nil
	a.config.Scopes = append([]string(nil), c.Scopes...)
	return a, nil
}
func cloneAccount(a Account) Account {
	peers := make(map[string]string, len(a.Peers))
	for k, v := range a.Peers {
		peers[k] = v
	}
	a.Peers = peers
	return a
}
func (a *OAuthAuthenticator) Metadata() map[string]any {
	return map[string]any{"resource": a.config.ResourceURL, "authorization_servers": []string{a.config.IssuerURL}, "scopes_supported": append([]string(nil), a.config.Scopes...), "bearer_methods_supported": []string{"header"}}
}
func (a *OAuthAuthenticator) Challenge() string {
	u, _ := url.Parse(a.config.ResourceURL)
	u.Path = "/.well-known/oauth-protected-resource" + strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return `Bearer resource_metadata="` + u.String() + `", scope="` + strings.Join(a.config.Scopes, " ") + `"`
}
func tokenCacheKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (a *OAuthAuthenticator) currentTime() time.Time {
	if a.now != nil {
		return a.now()
	}
	return time.Now()
}

func (a *OAuthAuthenticator) cacheGet(key string) (introspectCacheEntry, bool) {
	now := a.currentTime()
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()
	ent, ok := a.cache[key]
	if !ok || !ent.until.After(now) {
		if ok {
			delete(a.cache, key)
		}
		return introspectCacheEntry{}, false
	}
	return ent, true
}

func (a *OAuthAuthenticator) cachePut(key string, ent introspectCacheEntry) {
	if ent.err == nil && a.posTTL <= 0 {
		return
	}
	if ent.err != nil && a.negTTL <= 0 {
		return
	}
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()
	if len(a.cache) >= 10000 {
		now := a.currentTime()
		for k, v := range a.cache {
			if !v.until.After(now) {
				delete(a.cache, k)
			}
		}
	}
	a.cache[key] = ent
}

func (a *OAuthAuthenticator) Authenticate(r *http.Request) (Account, error) {
	headers := r.Header.Values("Authorization")
	if len(headers) != 1 {
		return Account{}, errAuthentication
	}
	parts := strings.Fields(headers[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) > 16384 {
		return Account{}, errAuthentication
	}
	key := tokenCacheKey(parts[1])
	if ent, ok := a.cacheGet(key); ok {
		if ent.err != nil {
			return Account{}, ent.err
		}
		account := cloneAccount(ent.account)
		account.AccessToken = parts[1]
		return account, nil
	}

	select {
	case a.sem <- struct{}{}:
	case <-r.Context().Done():
		return Account{}, errAuthorizationUnavailable
	}
	defer func() { <-a.sem }()

	account, err := a.introspect(r.Context(), parts[1])
	now := a.currentTime()
	ent := introspectCacheEntry{err: err}
	if err == nil {
		stored := cloneAccount(account)
		stored.AccessToken = ""
		ent.account = stored
		until := now.Add(a.posTTL)
		if !account.AccessTokenExpiresAt.IsZero() && account.AccessTokenExpiresAt.Before(until) {
			until = account.AccessTokenExpiresAt
		}
		ent.until = until
	} else {
		ent.until = now.Add(a.negTTL)
	}
	a.cachePut(key, ent)
	return account, err
}

func (a *OAuthAuthenticator) introspect(ctx context.Context, accessToken string) (Account, error) {
	form := url.Values{"token": {accessToken}, "token_type_hint": {"access_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.config.IntrospectionURL, strings.NewReader(form.Encode()))
	if err != nil {
		return Account{}, errAuthentication
	}
	id, secret := os.Getenv(a.config.ClientIDEnv), os.Getenv(a.config.ClientSecretEnv)
	if id == "" || secret == "" {
		return Account{}, errAuthorizationUnavailable
	}
	req.SetBasicAuth(url.QueryEscape(id), url.QueryEscape(secret))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return Account{}, errAuthorizationUnavailable
	}
	defer resp.Body.Close()
	// HTTP failures describe the introspection service/client, not the user
	// token. Only a valid introspection response can establish revocation.
	if resp.StatusCode != http.StatusOK {
		return Account{}, errAuthorizationUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(data) > 65536 {
		return Account{}, errAuthorizationUnavailable
	}
	var token struct {
		Active    *bool           `json:"active"`
		Subject   string          `json:"sub"`
		Issuer    string          `json:"iss"`
		Audience  json.RawMessage `json:"aud"`
		Scope     string          `json:"scope"`
		Expires   int64           `json:"exp"`
		NotBefore int64           `json:"nbf"`
		TokenType string          `json:"token_type"`
	}
	if json.Unmarshal(data, &token) != nil {
		return Account{}, errAuthorizationUnavailable
	}
	if token.Active == nil {
		return Account{}, errAuthorizationUnavailable
	}
	now := a.currentTime()
	if !*token.Active || token.Issuer != a.config.IssuerURL || token.Expires <= now.Unix() || token.NotBefore > now.Unix() || !audienceContains(token.Audience, a.config.ResourceURL) || (token.TokenType != "" && !strings.EqualFold(token.TokenType, "Bearer")) {
		return Account{}, errAuthentication
	}
	scopes := map[string]bool{}
	for _, s := range strings.Fields(token.Scope) {
		scopes[s] = true
	}
	for _, s := range a.config.Scopes {
		if !scopes[s] {
			return Account{}, errAuthentication
		}
	}
	account, ok := a.accounts[token.Subject]
	if !ok {
		return Account{}, errAuthentication
	}
	account = cloneAccount(account)
	account.AccessToken = accessToken
	account.AccessTokenExpiresAt = time.Unix(token.Expires, 0).UTC()
	return account, nil
}
func audienceContains(raw json.RawMessage, want string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	var many []string
	if json.Unmarshal(raw, &many) != nil {
		return false
	}
	for _, s := range many {
		if s == want {
			return true
		}
	}
	return false
}

// CheckAccess revalidates an original subscription token on every background
// delivery. Revoked, expired or differently bound tokens fail closed; reconnecting
// does not silently transfer a subscription to a new principal or relay account.
// A non-nil error means verification is unavailable: fail closed and retry later.
// False with no error means definitive denial; the subscription must stop.
func (a *OAuthAuthenticator) CheckAccess(ctx context.Context, expected Account, token string) (bool, error) {
	if token == "" {
		return false, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.config.ResourceURL, nil)
	if err != nil {
		return false, nil
	}
	req.Header.Set("Authorization", "Bearer "+token)
	actual, err := a.Authenticate(req)
	if errors.Is(err, errAuthorizationUnavailable) {
		return false, errAuthorizationUnavailable
	}
	if err != nil {
		return false, nil
	}
	return actual.ID == expected.ID && actual.Subject == expected.Subject && actual.RelayURL == expected.RelayURL && actual.PeerID == expected.PeerID && actual.APIKeyEnv == expected.APIKeyEnv, nil
}
