package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"time"
)

// RequestIDHeader carries the correlation ID in requests and responses.
const RequestIDHeader = "X-Request-ID"

// maxRequestIDLen bounds an accepted client-supplied request ID.
const maxRequestIDLen = 64

type requestInfo struct {
	id    string
	route string
}

type requestInfoKey struct{}

func infoFrom(ctx context.Context) *requestInfo {
	info, _ := ctx.Value(requestInfoKey{}).(*requestInfo)
	return info
}

// RequestIDFrom returns the request ID stored by the middleware, or "".
func RequestIDFrom(ctx context.Context) string {
	if info := infoFrom(ctx); info != nil {
		return info.id
	}
	return ""
}

func setRoute(ctx context.Context, route string) {
	if info := infoFrom(ctx); info != nil {
		info.route = route
	}
}

// validRequestID accepts only short IDs from a conservative alphabet, so a
// client cannot inject log lines, control characters or unbounded data.
func validRequestID(id string) bool {
	if id == "" || len(id) > maxRequestIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}

func newRequestID() string {
	var raw [16]byte
	// crypto/rand.Read never returns an error on supported platforms
	// (Go >= 1.24 crashes the program instead of returning weak data).
	_, _ = rand.Read(raw[:])
	return hex.EncodeToString(raw[:])
}

// statusRecorder captures the status and size for the access log.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (s *statusRecorder) WriteHeader(status int) {
	if s.status == 0 {
		s.status = status
	}
	s.ResponseWriter.WriteHeader(status)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += int64(n)
	return n, err
}

// logMethod keeps arbitrary client-chosen method tokens out of the logs.
func logMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return method
	default:
		return "OTHER"
	}
}

// wrap applies, outermost first: request ID, security headers, access log,
// panic recovery and the request body limit.
func wrap(next http.Handler, logger *slog.Logger, maxBodyBytes int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := r.Header.Get(RequestIDHeader)
		if !validRequestID(id) {
			id = newRequestID()
		}
		info := &requestInfo{id: id, route: "unmatched"}
		r = r.WithContext(context.WithValue(r.Context(), requestInfoKey{}, info))

		h := w.Header()
		h.Set(RequestIDHeader, id)
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Referrer-Policy", "no-referrer")

		rec := &statusRecorder{ResponseWriter: w}
		defer func() {
			if recovered := recover(); recovered != nil {
				if recovered == http.ErrAbortHandler {
					panic(recovered)
				}
				// The panic value may contain request data: never log or
				// return it. Only the route and request ID are recorded.
				logger.Error("handler panic", "route", info.route, "request_id", id)
				if rec.status == 0 {
					WriteProblem(rec, r, http.StatusInternalServerError, CodeInternal, "internal error")
				}
			}
			status := rec.status
			if status == 0 {
				status = http.StatusOK
			}
			// Route is the registered pattern, never the raw path or query,
			// so identifiers in URLs do not reach the logs.
			logger.Info("request",
				"method", logMethod(r.Method),
				"route", info.route,
				"status", status,
				"bytes", rec.bytes,
				"duration_ms", time.Since(start).Milliseconds(),
				"request_id", id,
			)
		}()

		if r.ContentLength > maxBodyBytes {
			WriteProblem(rec, r, http.StatusRequestEntityTooLarge, CodeBodyTooLarge, "request body too large")
			return
		}
		r.Body = http.MaxBytesReader(rec, r.Body, maxBodyBytes)
		next.ServeHTTP(rec, r)
	})
}
