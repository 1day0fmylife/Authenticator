// Command authenticator-mfa runs the MFA verifier HTTP service (SRV-001 skeleton).
//
// Only health endpoints exist so far. Service authentication and TLS arrive
// in SRV-003; until then the server refuses non-loopback listen addresses
// unless -insecure-listen-any is given explicitly. Standard library only.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/1day0fmylife/Authenticator/server/internal/api"
)

type config struct {
	listen            string
	shutdownTimeout   time.Duration
	insecureListenAny bool
}

func parseFlags(args []string, stderr io.Writer) (config, error) {
	fs := flag.NewFlagSet("authenticator-mfa", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cfg config
	fs.StringVar(&cfg.listen, "listen", "127.0.0.1:8080", "listen address (host:port)")
	fs.DurationVar(&cfg.shutdownTimeout, "shutdown-timeout", 10*time.Second, "graceful shutdown timeout")
	fs.BoolVar(&cfg.insecureListenAny, "insecure-listen-any", false,
		"allow a non-loopback address before service authentication/TLS exist (SRV-003)")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	if fs.NArg() != 0 {
		return config{}, errors.New("unexpected positional arguments")
	}
	if cfg.shutdownTimeout <= 0 || cfg.shutdownTimeout > 5*time.Minute {
		return config{}, errors.New("shutdown-timeout must be in (0, 5m]")
	}
	return cfg, nil
}

// checkListen refuses non-loopback addresses unless explicitly allowed:
// without service auth/TLS the API must not be reachable from the network.
func checkListen(addr string, allowAny bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	if allowAny {
		return nil
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("refusing non-loopback listen address without -insecure-listen-any (no service auth/TLS yet)")
	}
	return nil
}

// run starts the server and blocks until ctx is cancelled, then shuts down
// gracefully. ready (if not nil) receives the bound address.
func run(ctx context.Context, args []string, stderr io.Writer, ready chan<- string) error {
	cfg, err := parseFlags(args, stderr)
	if err != nil {
		return err
	}
	if err := checkListen(cfg.listen, cfg.insecureListenAny); err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	if cfg.insecureListenAny {
		logger.Warn("listening without service authentication or TLS; do not expose to untrusted networks")
	}

	service := api.New(api.Config{Logger: logger})
	listener, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	server := api.NewHTTPServer(cfg.listen, service.Handler(), logger)

	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	logger.Info("authenticator-mfa started", "addr", listener.Addr().String())
	if ready != nil {
		ready <- listener.Addr().String()
	}

	select {
	case err := <-serveErr:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}

	service.SetDraining()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.shutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	logger.Info("authenticator-mfa stopped")
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stderr, nil); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "authenticator-mfa:", err)
		os.Exit(1)
	}
}
