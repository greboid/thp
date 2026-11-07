package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

func newTestUpstream(t *testing.T, seen *string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen != nil {
			*seen = r.Header.Get(tailscaleUserLoginHeader)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func newWhoisClient(t *testing.T, login, name, pic string) *local.Client {
	t.Helper()
	return newWhoisClientFor(t, &apitype.WhoIsResponse{
		Node: &tailcfg.Node{Name: "laptop.example.ts.net."},
		UserProfile: &tailcfg.UserProfile{
			LoginName:     login,
			DisplayName:   name,
			ProfilePicURL: pic,
		},
	})
}

func newWhoisClientFor(t *testing.T, resp *apitype.WhoIsResponse) *local.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/localapi/v0/whois" {
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(server.Close)
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	var dialer net.Dialer
	return &local.Client{Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", serverURL.Host)
	}}
}

func newTestHandler(t *testing.T, lc *local.Client, authHeaders bool, upstreamURL *url.URL) http.Handler {
	t.Helper()
	return identityMiddleware(lc, authHeaders, newReverseProxy(upstreamURL, time.Minute))
}

func TestForgedIdentityHeadersNeverForwarded(t *testing.T) {
	for _, authHeaders := range []bool{true, false} {
		t.Run(fmt.Sprintf("authheaders=%v", authHeaders), func(t *testing.T) {
			var upstreamLogin string
			upstream := newTestUpstream(t, &upstreamLogin)
			upstreamURL, err := url.Parse(upstream.URL)
			if err != nil {
				t.Fatal(err)
			}
			unavailable := &local.Client{Dial: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("identity unavailable")
			}}
			handler := newTestHandler(t, unavailable, authHeaders, upstreamURL)

			req := httptest.NewRequest(http.MethodGet, "http://proxy.example/", nil)
			req.Header.Set(tailscaleUserLoginHeader, "admin@example.com")
			req.Header.Set(tailscaleUserNameHeader, "Administrator")
			req.Header.Set(tailscaleUserProfileHeader, "https://example.com/admin.png")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d", rec.Code)
			}
			if upstreamLogin != "" {
				t.Fatalf("forged header reached upstream: %q", upstreamLogin)
			}
		})
	}
}

func TestResolvedIdentityForwarded(t *testing.T) {
	var upstreamLogin, upstreamName string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamLogin = r.Header.Get(tailscaleUserLoginHeader)
		upstreamName = r.Header.Get(tailscaleUserNameHeader)
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	lc := newWhoisClient(t, "alice@example.com", "Alice Example", "https://example.com/alice.png")
	handler := newTestHandler(t, lc, true, upstreamURL)

	req := httptest.NewRequest(http.MethodGet, "http://proxy.example/", nil)
	req.Header.Set(tailscaleUserLoginHeader, "attacker@example.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if upstreamLogin != "alice@example.com" || upstreamName != "Alice Example" {
		t.Fatalf("expected resolved identity upstream, got login=%q name=%q", upstreamLogin, upstreamName)
	}
}

func TestNewHTTPServerTimeouts(t *testing.T) {
	server := newHTTPServer(http.NotFoundHandler(), 0)
	if server.ReadHeaderTimeout <= 0 || server.ReadTimeout <= 0 || server.IdleTimeout <= 0 {
		t.Fatal("expected read header, read and idle timeouts to be set")
	}
	limited := newHTTPServer(http.NotFoundHandler(), 10*time.Second)
	if limited.WriteTimeout != 10*time.Second {
		t.Fatalf("expected write timeout to be honored, got %v", limited.WriteTimeout)
	}
}

func TestForgedIdentityHeaderVariantsStripped(t *testing.T) {
	var got http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(newTestHandler(t, nil, false, upstreamURL))
	t.Cleanup(proxy.Close)

	req, err := http.NewRequest(http.MethodGet, proxy.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Set raw keys so Go does not canonicalise them away.
	req.Header["Tailscale_User_Login"] = []string{"admin@example.com"}
	req.Header["TAILSCALE-USER-NAME"] = []string{"Administrator"}
	req.Header["tailscale_user-profile_pic"] = []string{"https://example.com/admin.png"}
	req.Header["Tailscale-User-Anything"] = []string{"x"}
	req.Header.Set("X-Unrelated", "kept")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	for name := range got {
		if isIdentityHeader(name) {
			t.Errorf("identity header variant reached upstream: %s", name)
		}
	}
	if got.Get("X-Unrelated") != "kept" {
		t.Error("unrelated header was stripped")
	}
}

func TestNoIdentityForTaggedOrIncompleteResponses(t *testing.T) {
	cases := map[string]*apitype.WhoIsResponse{
		"tagged": {
			Node:        &tailcfg.Node{Name: "server.example.ts.net.", Tags: []string{"tag:server"}},
			UserProfile: &tailcfg.UserProfile{LoginName: "tagged-devices"},
		},
		"nil profile": {Node: &tailcfg.Node{Name: "laptop.example.ts.net."}},
		"nil node":    {UserProfile: &tailcfg.UserProfile{LoginName: "alice@example.com"}},
	}
	for name, resp := range cases {
		t.Run(name, func(t *testing.T) {
			upstreamLogin := "unset"
			upstream := newTestUpstream(t, &upstreamLogin)
			upstreamURL, err := url.Parse(upstream.URL)
			if err != nil {
				t.Fatal(err)
			}
			handler := newTestHandler(t, newWhoisClientFor(t, resp), true, upstreamURL)

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://proxy.example/", nil))

			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d", rec.Code)
			}
			if upstreamLogin != "" {
				t.Fatalf("expected no identity upstream, got %q", upstreamLogin)
			}
		})
	}
}

func TestParseUpstream(t *testing.T) {
	valid := []string{"http://app:80", "https://example.com", "http://127.0.0.1:8080/base"}
	for _, raw := range valid {
		if _, err := parseUpstream(raw); err != nil {
			t.Errorf("parseUpstream(%q) unexpected error: %v", raw, err)
		}
	}
	invalid := []string{"", "localhost:8080", "app:80", "ftp://example.com", "http://", "http:///path", "://bad"}
	for _, raw := range invalid {
		if _, err := parseUpstream(raw); err == nil {
			t.Errorf("parseUpstream(%q) expected error", raw)
		}
	}
}

func TestRedirectTarget(t *testing.T) {
	tests := []struct {
		dns    string
		port   int
		secure bool
		want   string
	}{
		{"myapp.example.ts.net.", 443, true, "https://myapp.example.ts.net/"},
		{"myapp.example.ts.net.", 8443, true, "https://myapp.example.ts.net:8443/"},
		{"myapp.example.ts.net.", 80, false, "http://myapp.example.ts.net/"},
		{"myapp.example.ts.net.", 8080, false, "http://myapp.example.ts.net:8080/"},
	}
	for _, tt := range tests {
		if got := redirectTarget(tt.dns, tt.port, tt.secure); got != tt.want {
			t.Errorf("redirectTarget(%q, %d, %v) = %q, want %q", tt.dns, tt.port, tt.secure, got, tt.want)
		}
	}
}

func TestRedirectHandlerUnavailableUntilTargetKnown(t *testing.T) {
	handler := &redirectHandler{}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://myapp/", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 before target known, got %d", rec.Code)
	}

	target := "https://myapp.example.ts.net/"
	handler.target.Store(&target)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://myapp/", nil))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != target {
		t.Fatalf("expected redirect to %s, got %d %q", target, rec.Code, rec.Header().Get("Location"))
	}
}

func TestUpstreamResponseTimeout(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() {
		close(release)
		upstream.Close()
	})
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := newReverseProxy(upstreamURL, 100*time.Millisecond)

	rec := httptest.NewRecorder()
	start := time.Now()
	proxy.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://proxy.example/", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 from hung upstream, got %d", rec.Code)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("upstream timeout not applied")
	}
}
