package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestService(t *testing.T, cfg Config) (*Service, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	cfg.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	return New(cfg), &logs
}

func do(t *testing.T, h http.Handler, method, target string, body io.Reader, header map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, body)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeProblem(t *testing.T, rec *httptest.ResponseRecorder) Problem {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); ct != ProblemContentType {
		t.Fatalf("content-type = %q, want %q", ct, ProblemContentType)
	}
	var p Problem
	dec := json.NewDecoder(rec.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if p.Status != rec.Code || p.Code == "" || p.Type != "urn:authenticator:problem:"+p.Code {
		t.Fatalf("malformed problem %+v for status %d", p, rec.Code)
	}
	if p.RequestID == "" || p.RequestID != rec.Header().Get(RequestIDHeader) {
		t.Fatalf("problem request_id %q does not match header", p.RequestID)
	}
	return p
}

func TestLiveAndReady(t *testing.T) {
	s, _ := newTestService(t, Config{})
	live := do(t, s.Handler(), http.MethodGet, "/health/live", nil, nil)
	if live.Code != http.StatusOK || !strings.Contains(live.Body.String(), `"status":"live"`) {
		t.Fatalf("live: %d %s", live.Code, live.Body)
	}
	ready := do(t, s.Handler(), http.MethodGet, "/health/ready", nil, nil)
	if ready.Code != http.StatusOK || !strings.Contains(ready.Body.String(), `"status":"ready"`) {
		t.Fatalf("ready: %d %s", ready.Code, ready.Body)
	}
	head := do(t, s.Handler(), http.MethodHead, "/health/live", nil, nil)
	if head.Code != http.StatusOK {
		t.Fatalf("HEAD live: %d", head.Code)
	}
}

func TestReadinessFailureHidesErrorDetails(t *testing.T) {
	const secretish = "postgres://user:hunter2@db.internal/mfa"
	s, logs := newTestService(t, Config{Readiness: []ReadinessCheck{
		{Name: "ok", Check: func(context.Context) error { return nil }},
		{Name: "postgres", Check: func(context.Context) error { return errors.New("dial " + secretish) }},
	}})
	rec := do(t, s.Handler(), http.MethodGet, "/health/ready", nil, nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	p := decodeProblem(t, rec)
	if p.Code != CodeNotReady {
		t.Fatalf("code %q", p.Code)
	}
	for _, out := range []string{body, logs.String()} {
		if strings.Contains(out, "hunter2") || strings.Contains(out, "db.internal") {
			t.Fatalf("readiness error leaked: %s", out)
		}
	}
	if !strings.Contains(logs.String(), `"check":"postgres"`) {
		t.Fatalf("failed check name not logged: %s", logs.String())
	}
}

func TestReadinessReportsDraining(t *testing.T) {
	s, _ := newTestService(t, Config{})
	s.SetDraining()
	rec := do(t, s.Handler(), http.MethodGet, "/health/ready", nil, nil)
	if rec.Code != http.StatusServiceUnavailable || decodeProblem(t, rec).Code != CodeNotReady {
		t.Fatalf("draining ready: %d", rec.Code)
	}
	if live := do(t, s.Handler(), http.MethodGet, "/health/live", nil, nil); live.Code != http.StatusOK {
		t.Fatalf("live while draining: %d", live.Code)
	}
}

func TestReadinessCheckHasDeadline(t *testing.T) {
	var sawDeadline bool
	s, _ := newTestService(t, Config{Readiness: []ReadinessCheck{{Name: "db", Check: func(ctx context.Context) error {
		_, sawDeadline = ctx.Deadline()
		return nil
	}}}})
	do(t, s.Handler(), http.MethodGet, "/health/ready", nil, nil)
	if !sawDeadline {
		t.Fatal("readiness check context has no deadline")
	}
}

func TestNotFoundAndMethodNotAllowedAreProblems(t *testing.T) {
	s, _ := newTestService(t, Config{})
	nf := do(t, s.Handler(), http.MethodGet, "/v1/mfa/challenges", nil, nil)
	if nf.Code != http.StatusNotFound || decodeProblem(t, nf).Code != CodeNotFound {
		t.Fatalf("404: %d", nf.Code)
	}
	na := do(t, s.Handler(), http.MethodPost, "/health/live", strings.NewReader("{}"), nil)
	if na.Code != http.StatusMethodNotAllowed || decodeProblem(t, na).Code != CodeMethodNotAllowed {
		t.Fatalf("405: %d", na.Code)
	}
	if allow := na.Header().Get("Allow"); allow != "GET" {
		t.Fatalf("Allow = %q", allow)
	}
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	s, _ := newTestService(t, Config{})
	for _, target := range []string{"/health/live", "/nope"} {
		rec := do(t, s.Handler(), http.MethodGet, target, nil, nil)
		for header, want := range map[string]string{
			"Cache-Control":           "no-store",
			"X-Content-Type-Options":  "nosniff",
			"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
			"Referrer-Policy":         "no-referrer",
		} {
			if got := rec.Header().Get(header); got != want {
				t.Fatalf("%s %s = %q, want %q", target, header, got, want)
			}
		}
	}
}

func TestRequestIDValidation(t *testing.T) {
	s, _ := newTestService(t, Config{})
	good := do(t, s.Handler(), http.MethodGet, "/health/live", nil, map[string]string{RequestIDHeader: "abc-123_X.y"})
	if got := good.Header().Get(RequestIDHeader); got != "abc-123_X.y" {
		t.Fatalf("valid id not kept: %q", got)
	}
	for _, bad := range []string{
		"",
		strings.Repeat("a", maxRequestIDLen+1),
		"inject\nfake log line",
		"with space",
		"quote\"",
		"юникод",
	} {
		rec := do(t, s.Handler(), http.MethodGet, "/health/live", nil, map[string]string{RequestIDHeader: bad})
		got := rec.Header().Get(RequestIDHeader)
		if got == bad || len(got) != 32 || !validRequestID(got) {
			t.Fatalf("bad id %q replaced by %q", bad, got)
		}
	}
	a := do(t, s.Handler(), http.MethodGet, "/health/live", nil, nil).Header().Get(RequestIDHeader)
	b := do(t, s.Handler(), http.MethodGet, "/health/live", nil, nil).Header().Get(RequestIDHeader)
	if a == b {
		t.Fatal("generated request IDs repeat")
	}
}

func TestPanicIsContainedAndNotLeaked(t *testing.T) {
	s, logs := newTestService(t, Config{})
	s.Router().HandleFunc(http.MethodGet, "/test/panic", func(http.ResponseWriter, *http.Request) {
		panic("seed=JBSWY3DPEHPK3PXP otp=123456")
	})
	rec := do(t, s.Handler(), http.MethodGet, "/test/panic", nil, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	if decodeProblem(t, rec).Code != CodeInternal {
		t.Fatal("wrong code")
	}
	for _, out := range []string{body, logs.String()} {
		if strings.Contains(out, "JBSWY3DPEHPK3PXP") || strings.Contains(out, "123456") {
			t.Fatalf("panic value leaked: %s", out)
		}
	}
}

func TestBodyLimit(t *testing.T) {
	s, _ := newTestService(t, Config{MaxBodyBytes: 16})
	var readErr error
	s.Router().HandleFunc(http.MethodPost, "/test/echo", func(w http.ResponseWriter, r *http.Request) {
		_, readErr = io.ReadAll(r.Body)
		var tooLarge *http.MaxBytesError
		if errors.As(readErr, &tooLarge) {
			WriteProblem(w, r, http.StatusRequestEntityTooLarge, CodeBodyTooLarge, "request body too large")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	declared := do(t, s.Handler(), http.MethodPost, "/test/echo", strings.NewReader(strings.Repeat("x", 17)), nil)
	if declared.Code != http.StatusRequestEntityTooLarge || decodeProblem(t, declared).Code != CodeBodyTooLarge {
		t.Fatalf("declared oversize: %d", declared.Code)
	}

	// Unknown length (chunked): enforced while reading.
	req := httptest.NewRequest(http.MethodPost, "/test/echo", io.NopCloser(strings.NewReader(strings.Repeat("x", 100))))
	req.ContentLength = -1
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge || readErr == nil {
		t.Fatalf("streamed oversize: %d err=%v", rec.Code, readErr)
	}

	ok := do(t, s.Handler(), http.MethodPost, "/test/echo", strings.NewReader("small"), nil)
	if ok.Code != http.StatusNoContent {
		t.Fatalf("small body: %d", ok.Code)
	}
}

func TestAccessLogIsPrivacyPreserving(t *testing.T) {
	s, logs := newTestService(t, Config{})
	do(t, s.Handler(), "PROPFIND", "/v1/mfa/subjects/alice@example.test/factors?otp=123456", nil,
		map[string]string{"Authorization": "Bearer top-secret-token"})
	do(t, s.Handler(), http.MethodGet, "/health/live?debug=secret-query", nil, nil)

	out := logs.String()
	for _, leaked := range []string{"alice@example.test", "123456", "top-secret-token", "secret-query", "PROPFIND", "/v1/mfa/subjects"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("access log leaked %q: %s", leaked, out)
		}
	}
	var entries []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("log line is not JSON: %q", line)
		}
		entries = append(entries, entry)
	}
	if len(entries) != 2 {
		t.Fatalf("want 2 access log lines, got %d", len(entries))
	}
	if entries[0]["route"] != "unmatched" || entries[0]["method"] != "OTHER" || entries[0]["status"] != float64(404) {
		t.Fatalf("unexpected entry: %v", entries[0])
	}
	if entries[1]["route"] != "/health/live" || entries[1]["status"] != float64(200) {
		t.Fatalf("unexpected entry: %v", entries[1])
	}
}

func TestDuplicateRoutePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("duplicate route did not panic")
		}
	}()
	r := NewRouter()
	r.HandleFunc(http.MethodGet, "/x", func(http.ResponseWriter, *http.Request) {})
	r.HandleFunc(http.MethodGet, "/x", func(http.ResponseWriter, *http.Request) {})
}

func TestHTTPServerLimits(t *testing.T) {
	srv := NewHTTPServer("127.0.0.1:0", http.NotFoundHandler(), nil)
	if srv.ReadHeaderTimeout == 0 || srv.ReadTimeout == 0 || srv.WriteTimeout == 0 || srv.IdleTimeout == 0 {
		t.Fatal("server timeouts must all be set")
	}
	if srv.MaxHeaderBytes != MaxHeaderBytes {
		t.Fatalf("MaxHeaderBytes = %d", srv.MaxHeaderBytes)
	}
}
