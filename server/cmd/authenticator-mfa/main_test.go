package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a goroutine-safe log sink for the race detector.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestCheckListen(t *testing.T) {
	for _, tc := range []struct {
		addr     string
		allowAny bool
		ok       bool
	}{
		{"127.0.0.1:8080", false, true},
		{"[::1]:8080", false, true},
		{"localhost:8080", false, true},
		{"0.0.0.0:8080", false, false},
		{":8080", false, false},
		{"10.0.0.5:8080", false, false},
		{"example.test:8080", false, false},
		{"0.0.0.0:8080", true, true},
		{"no-port", true, false},
	} {
		if err := checkListen(tc.addr, tc.allowAny); (err == nil) != tc.ok {
			t.Errorf("checkListen(%q, %v) = %v, want ok=%v", tc.addr, tc.allowAny, err, tc.ok)
		}
	}
}

func TestParseFlagsRejectsBadInput(t *testing.T) {
	for _, args := range [][]string{
		{"-shutdown-timeout", "0s"},
		{"-shutdown-timeout", "1h"},
		{"positional"},
		{"-unknown"},
	} {
		if _, err := parseFlags(args, io.Discard); err == nil {
			t.Errorf("parseFlags(%v) accepted bad input", args)
		}
	}
	cfg, err := parseFlags(nil, io.Discard)
	if err != nil || cfg.listen != "127.0.0.1:8080" || cfg.insecureListenAny {
		t.Fatalf("defaults: %+v %v", cfg, err)
	}
}

func TestRunRefusesNonLoopbackByDefault(t *testing.T) {
	err := run(context.Background(), []string{"-listen", "0.0.0.0:0"}, io.Discard, nil)
	if err == nil || !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("run accepted 0.0.0.0 without opt-in: %v", err)
	}
}

func TestRunServesHealthAndShutsDownGracefully(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logs := &syncBuffer{}
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"-listen", "127.0.0.1:0", "-shutdown-timeout", "5s"}, logs, ready) }()

	var addr string
	select {
	case addr = <-ready:
	case err := <-done:
		t.Fatalf("run exited early: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not start")
	}

	client := &http.Client{Timeout: 5 * time.Second}
	for path, want := range map[string]int{"/health/live": 200, "/health/ready": 200, "/v1/unknown": 404} {
		resp, err := client.Get("http://" + addr + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("GET %s = %d, want %d", path, resp.StatusCode, want)
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("graceful shutdown timed out")
	}
	out := logs.String()
	if !strings.Contains(out, "authenticator-mfa started") || !strings.Contains(out, "authenticator-mfa stopped") {
		t.Fatalf("lifecycle not logged: %s", out)
	}
	if _, err := client.Get("http://" + addr + "/health/live"); err == nil {
		t.Fatal("server still accepting after shutdown")
	}
}
