package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"

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
	useSSL             = flag.Bool("ssl", true, "Whether to enable tailscale SSL")
	funnel             = flag.Bool("funnel", false, "Whether to expose the service using funnel")
)

type httpHandler struct {
	reverseProxy   *httputil.ReverseProxy
	lc             *local.Client
	addAuthHeaders bool
	logger         *slog.Logger
}

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

	slog.Info("Listening for incoming connections", "hostname", *tailscaleHost, "port", *tailscalePort)

	handler := &httpHandler{
		reverseProxy:   reverseProxy,
	}

	go func() {
		err := http.Serve(listener, handler)
		if err != nil {
			slog.Error("HTTP server error", "error", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("Shutting down...")
}

func (h *httpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	slog.Debug("HTTP request received", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
	h.reverseProxy.ServeHTTP(w, r)
}
