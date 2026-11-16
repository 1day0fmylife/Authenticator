package api

import (
	"context"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"
)

// ReadinessCheck is a dependency probe (e.g. PostgreSQL in SRV-002).
// Name must be a static identifier; it is returned to callers.
type ReadinessCheck struct {
	Name  string
	Check func(context.Context) error
}

// checkTimeout bounds each readiness probe.
const checkTimeout = 2 * time.Second

type health struct {
	checks   []ReadinessCheck
	draining atomic.Bool
	logger   *slog.Logger
}

func (h *health) live(w http.ResponseWriter, _ *http.Request) {
	WriteJSON(w, http.StatusOK, map[string]string{"status": "live"})
}

func (h *health) ready(w http.ResponseWriter, r *http.Request) {
	if h.draining.Load() {
		WriteProblem(w, r, http.StatusServiceUnavailable, CodeNotReady, "shutting down")
		return
	}
	names := make([]string, 0, len(h.checks))
	for _, check := range h.checks {
		ctx, cancel := context.WithTimeout(r.Context(), checkTimeout)
		err := check.Check(ctx)
		cancel()
		if err != nil {
			// The error text may contain connection details: log only
			// the check name, and return only a static detail.
			h.logger.Warn("readiness check failed", "check", check.Name, "request_id", RequestIDFrom(r.Context()))
			WriteProblem(w, r, http.StatusServiceUnavailable, CodeNotReady, "dependency not ready")
			return
		}
		names = append(names, check.Name)
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "ready", "checks": names})
}
