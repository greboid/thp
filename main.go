package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/csmith/envflag/v2"
	"github.com/csmith/slogflags"
	"tailscale.com/client/local"
	"tailscale.com/tsnet"
)

var (
	tailscaleHost      = flag.String("tailscale-hostname", "tsp", "hostname for tailscale device")
	tailscalePort      = flag.Int("tailscale-port", 443, "port to listen on for incoming connections from tailscale")
	tailscaleConfigDir = flag.String("tailscale-config-dir", "config", "path to store tailscale configuration")
	tailscaleAuthKey   = flag.String("tailscale-auth-key", "", "tailscale auth key for connecting to the network. If blank, interactive auth will be required")
	upstream           = flag.String("upstream", "", "URL of the upstream service to proxy HTTP requests to (e.g., http://localhost:8080)")
	upstreamTimeout    = flag.Duration("upstream-timeout", 60*time.Second, "How long to wait for the upstream to start responding before failing the request (0 to wait forever)")
	useUpstreamHost    = flag.Bool("use-upstream-host", false, "Whether to send the upstream's host as the Host header instead of the host the client requested")
	useSSL             = flag.Bool("ssl", true, "Whether to enable tailscale SSL")
	funnel             = flag.Bool("funnel", false, "Whether to expose the service using funnel")
	authHeaders        = flag.Bool("authheaders", true, "Whether to add Tailscale auth headers")
	redirect           = flag.Bool("redirect", false, "Whether to redirect HTTP to HTTPS")
	redirectPort       = flag.Int("redirect-port", 80, "Port to listen on for http requests to redirect")
)

const (
	tailscaleUserLoginHeader   = "Tailscale-User-Login"
	tailscaleUserNameHeader    = "Tailscale-User-Name"
	tailscaleUserProfileHeader = "Tailscale-User-Profile-Pic"

	identityHeaderPrefix = "tailscale-user-"

	shutdownTimeout = 10 * time.Second
)

func parseUpstream(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("upstream cannot be blank")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing upstream URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("upstream URL %q must use http or https", raw)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("upstream URL %q has no host", raw)
	}
	return u, nil
}

func newReverseProxy(upstreamURL *url.URL, responseHeaderTimeout time.Duration, useUpstreamHost bool) *httputil.ReverseProxy {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = responseHeaderTimeout
	return &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(upstreamURL)
			if !useUpstreamHost {
				pr.Out.Host = pr.In.Host
			}
			pr.SetXForwarded()
		},
	}
}

func normaliseHeaderName(name string) string {
	return strings.ToLower(strings.ReplaceAll(name, "_", "-"))
}

func isIdentityHeader(name string) bool {
	return strings.HasPrefix(normaliseHeaderName(name), identityHeaderPrefix)
}

func identityMiddleware(lc *local.Client, authHeaders bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for name := range r.Header {
			if isIdentityHeader(name) {
				delete(r.Header, name)
			}
		}
		if !authHeaders {
			next.ServeHTTP(w, r)
			return
		}
		whois, err := lc.WhoIs(r.Context(), r.RemoteAddr)
		if err != nil {
			slog.Debug("Unable to resolve identity", "error", err)
			next.ServeHTTP(w, r)
			return
		}
		if whois.Node == nil || whois.UserProfile == nil {
			slog.Debug("Identity response incomplete, not adding auth headers", "remote", r.RemoteAddr)
			next.ServeHTTP(w, r)
			return
		}
		if whois.Node.IsTagged() {
			slog.Debug("Request from tagged device, not adding auth headers", "node", whois.Node.Name)
			next.ServeHTTP(w, r)
			return
		}
		r.Header.Set(tailscaleUserLoginHeader, whois.UserProfile.LoginName)
		r.Header.Set(tailscaleUserNameHeader, whois.UserProfile.DisplayName)
		r.Header.Set(tailscaleUserProfileHeader, whois.UserProfile.ProfilePicURL)
		slog.Debug("Authing", "user", whois.UserProfile.LoginName)
		next.ServeHTTP(w, r)
	})
}

func newHTTPServer(handler http.Handler, writeTimeout time.Duration) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       90 * time.Second,
	}
}

func redirectTarget(dnsName string, port int, secure bool) string {
	scheme, defaultPort := "https", 443
	if !secure {
		scheme, defaultPort = "http", 80
	}
	host := strings.TrimSuffix(dnsName, ".")
	if port != defaultPort {
		host = net.JoinHostPort(host, fmt.Sprint(port))
	}
	return fmt.Sprintf("%s://%s/", scheme, host)
}

type redirectHandler struct {
	target atomic.Pointer[string]
}

func (h *redirectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	target := h.target.Load()
	if target == nil {
		http.Error(w, "Service is starting, try again shortly", http.StatusServiceUnavailable)
		return
	}
	http.Redirect(w, r, *target, http.StatusFound)
}

func main() {
	envflag.Parse()
	slogflags.Logger(slogflags.WithSetDefault(true))

	if err := run(); err != nil {
		slog.Error("Fatal error", "error", err)
		os.Exit(1)
	}
}

func run() error {
	upstreamURL, err := parseUpstream(*upstream)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	slog.Debug("Starting tailscale", "hostname", *tailscaleHost)
	serv := tsnet.Server{
		Hostname: *tailscaleHost,
		Dir:      *tailscaleConfigDir,
		AuthKey:  *tailscaleAuthKey,
		UserLogf: slog.NewLogLogger(slog.Default().Handler(), slog.LevelInfo).Printf,
		Logf:     slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug).Printf,
	}
	defer func() {
		_ = serv.Close()
	}()

	lc, err := serv.LocalClient()
	if err != nil {
		return fmt.Errorf("getting the local client: %w", err)
	}

	var listener net.Listener
	addr := fmt.Sprintf(":%d", *tailscalePort)
	if *funnel {
		listener, err = serv.ListenFunnel("tcp", addr)
	} else if *useSSL {
		listener, err = serv.ListenTLS("tcp", addr)
	} else {
		listener, err = serv.Listen("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("listening on tailnet port %d: %w", *tailscalePort, err)
	}

	serveErrs := make(chan error, 2)
	serve := func(name string, server *http.Server, l net.Listener) {
		if err := server.Serve(l); !errors.Is(err, http.ErrServerClosed) {
			serveErrs <- fmt.Errorf("%s server: %w", name, err)
		}
	}

	proxyServer := newHTTPServer(identityMiddleware(lc, *authHeaders, newReverseProxy(upstreamURL, *upstreamTimeout, *useUpstreamHost)), 0)
	servers := []*http.Server{proxyServer}
	slog.Info("Listening for incoming connections", "hostname", *tailscaleHost, "port", *tailscalePort)
	go serve("proxy", proxyServer, listener)

	if *redirect {
		redirectListener, err := serv.Listen("tcp", fmt.Sprintf(":%d", *redirectPort))
		if err != nil {
			shutdown(servers)
			return fmt.Errorf("listening on redirect port %d: %w", *redirectPort, err)
		}

		handler := &redirectHandler{}
		redirectServer := newHTTPServer(handler, 10*time.Second)
		servers = append(servers, redirectServer)
		go serve("redirect", redirectServer, redirectListener)

		go func() {
			status, err := serv.Up(ctx)
			if err != nil {
				if ctx.Err() == nil {
					slog.Error("Error waiting for tailscale to come up, redirects unavailable", "error", err)
				}
				return
			}
			if status.Self == nil || status.Self.DNSName == "" {
				slog.Error("Tailscale has no DNS name, redirects unavailable")
				return
			}
			target := redirectTarget(status.Self.DNSName, *tailscalePort, *useSSL || *funnel)
			handler.target.Store(&target)
			slog.Info("Redirecting incoming http connections", "port", *redirectPort, "target", target)
		}()
	}

	select {
	case <-ctx.Done():
		slog.Info("Shutting down...")
		shutdown(servers)
		return nil
	case err := <-serveErrs:
		shutdown(servers)
		return err
	}
}

func shutdown(servers []*http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	for _, server := range servers {
		if err := server.Shutdown(ctx); err != nil {
			slog.Warn("Error shutting down server, closing connections", "error", err)
			_ = server.Close()
		}
	}
}
