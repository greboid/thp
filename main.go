package main

import (
	"context"
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
	"syscall"

	"github.com/csmith/envflag/v2"
	"github.com/csmith/slogflags"
	"tailscale.com/tsnet"
)

var (
	tailscaleHost      = flag.String("tailscale-hostname", "tsp", "hostname for tailscale device")
	tailscalePort      = flag.Int("tailscale-port", 443, "port to listen on for incoming connections from tailscale")
	tailscaleConfigDir = flag.String("tailscale-config-dir", "config", "path to store tailscale configuration")
	tailscaleAuthKey   = flag.String("tailscale-auth-key", "", "tailscale auth key for connecting to the network. If blank, interactive auth will be required")
	upstream           = flag.String("upstream", "", "URL of the upstream service to proxy HTTP requests to (e.g., http://localhost:8080)")
	useSSL             = flag.Bool("ssl", true, "Whether to enable tailscale SSL")
	funnel             = flag.Bool("funnel", false, "Whether to expose the service using funnel")
	authHeaders        = flag.Bool("authheaders", true, "Whether to add Tailscale auth headers")
	redirect           = flag.Bool("redirect", false, "Whether to redirect HTTP to HTTPS")
	redirectPort       = flag.Int("redirect-port", 80, "Port to listen on for http requests to redirect")
)

func main() {
	envflag.Parse()
	slogflags.Logger(slogflags.WithSetDefault(true))

	if *upstream == "" {
		slog.Error("Upstream host cannot be blank")
		os.Exit(1)
	}

	upstreamURL, err := url.Parse(*upstream)
	if err != nil {
		slog.Error("Error parsing upstream URL", "error", err)
		os.Exit(1)
	}

	slog.Debug("Starting tailscale %s %s", *tailscaleHost, *tailscaleAuthKey)
	serv := tsnet.Server{
		Hostname: *tailscaleHost,
		Dir:      *tailscaleConfigDir,
		AuthKey:  *tailscaleAuthKey,
		UserLogf: slog.NewLogLogger(slog.Default().Handler(), slog.LevelInfo).Printf,
		Logf:     slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug).Printf,
	}
	defer func(serv *tsnet.Server) {
		_ = serv.Close()
	}(&serv)

	lc, err := serv.LocalClient()
	if err != nil {
		slog.Error("Error getting the local client", "error", err)
		os.Exit(1)
	}

	var listener net.Listener
	if *funnel {
		listener, err = serv.ListenFunnel("tcp", fmt.Sprintf(":%d", *tailscalePort))
	} else if *useSSL {
		listener, err = serv.ListenTLS("tcp", fmt.Sprintf(":%d", *tailscalePort))
	} else {
		listener, err = serv.Listen("tcp", fmt.Sprintf(":%d", *tailscalePort))
	}
	if err != nil {
		slog.Error("Error listening on tailnet", "port", *tailscalePort, "error", err)
		os.Exit(1)
	}
	defer func(listener net.Listener) {
		_ = listener.Close()
	}(listener)

	reverseProxy := httputil.NewSingleHostReverseProxy(upstreamURL)

	if *authHeaders {
		d := reverseProxy.Director
		reverseProxy.Director = func(r *http.Request) {
			d(r)
			whois, err := lc.WhoIs(r.Context(), r.RemoteAddr)
			if err == nil {
				r.Header.Set("Tailscale-User-Login", whois.UserProfile.LoginName)
				r.Header.Set("Tailscale-User-Name", whois.UserProfile.DisplayName)
				r.Header.Set("Tailscale-User-Profile-Pic", whois.UserProfile.ProfilePicURL)
				slog.Debug("Authing", "user", whois.UserProfile.LoginName)
			}
		}
	}

	slog.Info("Listening for incoming connections", "hostname", *tailscaleHost, "port", *tailscalePort)

	if *redirect {
		redirectListener, err := serv.Listen("tcp", fmt.Sprintf(":%d", *redirectPort))
		if err != nil {
			slog.Error("Error listening on redirect", "port", *redirectPort, "error", err)
			os.Exit(1)
		}

		go func() {
			status, err := lc.StatusWithoutPeers(context.Background())
			if err != nil {
				slog.Error("Error getting tailscale status", "error", err)
				return
			}

			target := fmt.Sprintf("https://%s:%d/", strings.TrimSuffix(status.Self.DNSName, "."), *tailscalePort)
			slog.Info("Listening for incoming http connections", "hostname", *tailscaleHost, "port", *tailscalePort, "target", target)
			http.Serve(redirectListener, http.RedirectHandler(target, http.StatusFound))
		}()

		defer redirectListener.Close()
	}

	mux := http.NewServeMux()
	mux.Handle("/", reverseProxy)
	go func() {
		err := http.Serve(listener, mux)
		if err != nil {
			slog.Error("HTTP server error", "error", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("Shutting down...")
}
