package api

import (
	"io"
	"log"
	"log/slog"
	"net/http"
	"time"
)

// DefaultMaxBodyBytes bounds request bodies; MFA requests are small.
const DefaultMaxBodyBytes int64 = 64 << 10

// Server timeouts and limits (slow-loris and oversized-header protection).
const (
	ReadHeaderTimeout = 5 * time.Second
	ReadTimeout       = 10 * time.Second
	WriteTimeout      = 15 * time.Second
	IdleTimeout       = 60 * time.Second
	MaxHeaderBytes    = 16 << 10
)

// Config configures the HTTP service.
type Config struct {
	// Logger receives JSON access logs; nil discards them.
	Logger *slog.Logger
	// MaxBodyBytes bounds request bodies; 0 means DefaultMaxBodyBytes.
	MaxBodyBytes int64
	// Readiness probes evaluated by GET /health/ready.
	Readiness []ReadinessCheck
}

// Service is the verifier HTTP API.
type Service struct {
	router  *Router
	health  *health
	handler http.Handler
}

// New builds the service with health endpoints registered.
func New(cfg Config) *Service {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	maxBody := cfg.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = DefaultMaxBodyBytes
	}
	h := &health{checks: cfg.Readiness, logger: logger}
	router := NewRouter()
	router.HandleFunc(http.MethodGet, "/health/live", h.live)
	router.HandleFunc(http.MethodGet, "/health/ready", h.ready)
	return &Service{router: router, health: h, handler: wrap(router, logger, maxBody)}
}

// Router exposes route registration for later API slices (SRV-004+).
func (s *Service) Router() *Router { return s.router }

// Handler returns the fully wrapped handler.
func (s *Service) Handler() http.Handler { return s.handler }

// SetDraining makes /health/ready report not ready, before shutdown.
func (s *Service) SetDraining() { s.health.draining.Store(true) }

// NewHTTPServer returns an http.Server with conservative timeouts. Server
// errors (e.g. malformed requests) go to logger at warn level.
func NewHTTPServer(addr string, handler http.Handler, logger *slog.Logger) *http.Server {
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: ReadHeaderTimeout,
		ReadTimeout:       ReadTimeout,
		WriteTimeout:      WriteTimeout,
		IdleTimeout:       IdleTimeout,
		MaxHeaderBytes:    MaxHeaderBytes,
		ErrorLog:          log.New(slogWriter{logger}, "", 0),
	}
}

type slogWriter struct{ logger *slog.Logger }

func (w slogWriter) Write(p []byte) (int, error) {
	// net/http messages contain remote addresses but no request bodies.
	w.logger.Warn("http server", "message", string(p))
	return len(p), nil
}
