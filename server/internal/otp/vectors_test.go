package otp_test

import (
	"encoding/base32"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/1day0fmylife/Authenticator/server/internal/otp"
)

type vectorSecret struct {
	ASCII  string `json:"ascii"`
	Base32 string `json:"base32"`
}

type hotpVector struct {
	ID         string `json:"id"`
	Secret     string `json:"secret"`
	Algorithm  string `json:"algorithm"`
	Digits     int    `json:"digits"`
	Counter    uint64 `json:"counter"`
	Code       string `json:"code"`
	Provenance string `json:"provenance"`
}

type totpVector struct {
	ID         string `json:"id"`
	Secret     string `json:"secret"`
	Algorithm  string `json:"algorithm"`
	Digits     int    `json:"digits"`
	UnixTime   int64  `json:"unix_time"`
	Period     int    `json:"period"`
	Code       string `json:"code"`
	Provenance string `json:"provenance"`
}

type vectorFile[V any] struct {
	Schema          int                     `json:"schema"`
	Kind            string                  `json:"kind"`
	Description     string                  `json:"description"`
	SourceDocuments []string                `json:"source_documents"`
	Secrets         map[string]vectorSecret `json:"secrets"`
	Vectors         []V                     `json:"vectors"`
}

func vectorsPath(t *testing.T, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "tests", "vectors", name)
}

func loadVectors[V any](t *testing.T, name, kind string) vectorFile[V] {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath(t, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var doc vectorFile[V]
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	if doc.Schema != 1 {
		t.Fatalf("%s: unsupported schema %d", name, doc.Schema)
	}
	if doc.Kind != kind {
		t.Fatalf("%s: kind %q, want %q", name, doc.Kind, kind)
	}
	if len(doc.Secrets) == 0 || len(doc.Vectors) == 0 {
		t.Fatalf("%s: empty secrets or vectors", name)
	}
	return doc
}

func secretBytes(t *testing.T, doc map[string]vectorSecret, id string) []byte {
	t.Helper()
	s, ok := doc[id]
	if !ok {
		t.Fatalf("vector references unknown secret %q", id)
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(s.Base32, "="))
	if err != nil {
		t.Fatalf("secret %q: invalid base32: %v", id, err)
	}
	if string(decoded) != s.ASCII {
		t.Fatalf("secret %q: base32 does not match ascii", id)
	}
	return []byte(s.ASCII)
}

func TestHOTPVectors(t *testing.T) {
	doc := loadVectors[hotpVector](t, "rfc4226-hotp.json", "hotp")
	seen := map[string]bool{}

	published := map[uint64]string{
		0: "755224", 1: "287082", 2: "359152", 3: "969429", 4: "338314",
		5: "254676", 6: "287922", 7: "162583", 8: "399871", 9: "520489",
	}
	foundPublished := 0

	for _, v := range doc.Vectors {
		if seen[v.ID] {
			t.Fatalf("duplicate vector id %q", v.ID)
		}
		seen[v.ID] = true
		if v.Provenance == "" {
			t.Fatalf("vector %q: missing provenance", v.ID)
		}
		if v.Digits != 6 && v.Digits != 8 {
			t.Fatalf("vector %q: digits %d", v.ID, v.Digits)
		}

		secret := secretBytes(t, doc.Secrets, v.Secret)
		got, err := otp.GenerateHOTP(secret, v.Counter, v.Digits, otp.Algorithm(v.Algorithm))
		if err != nil {
			t.Fatalf("vector %q: %v", v.ID, err)
		}
		if got != v.Code {
			t.Fatalf("vector %q: got %s, want %s", v.ID, got, v.Code)
		}

		if v.Digits == 6 && strings.HasPrefix(v.Provenance, "RFC 4226") {
			if want, ok := published[v.Counter]; ok {
				if v.Code != want {
					t.Fatalf("vector %q: published RFC 4226 value changed: %s != %s", v.ID, v.Code, want)
				}
				foundPublished++
			}
		}
	}
	if foundPublished != len(published) {
		t.Fatalf("published RFC 4226 coverage: %d of %d", foundPublished, len(published))
	}
}

func TestTOTPVectors(t *testing.T) {
	doc := loadVectors[totpVector](t, "rfc6238-totp.json", "totp")
	seen := map[string]bool{}

	// Published RFC 6238 Appendix B values, independent of the JSON file.
	published := map[string]map[int64]string{
		"SHA1": {
			59: "94287082", 1111111109: "07081804", 1111111111: "14050471",
			1234567890: "89005924", 2000000000: "69279037", 20000000000: "65353130",
		},
		"SHA256": {
			59: "46119246", 1111111109: "68084774", 1111111111: "67062674",
			1234567890: "91819424", 2000000000: "90698825", 20000000000: "77737706",
		},
		"SHA512": {
			59: "90693936", 1111111109: "25091201", 1111111111: "99943326",
			1234567890: "93441116", 2000000000: "38618901", 20000000000: "47863826",
		},
	}
	foundPublished := 0
	wantPublished := 0
	for _, byTime := range published {
		wantPublished += len(byTime)
	}

	for _, v := range doc.Vectors {
		if seen[v.ID] {
			t.Fatalf("duplicate vector id %q", v.ID)
		}
		seen[v.ID] = true
		if v.Provenance == "" {
			t.Fatalf("vector %q: missing provenance", v.ID)
		}
		if v.Digits != 6 && v.Digits != 8 {
			t.Fatalf("vector %q: digits %d", v.ID, v.Digits)
		}
		if v.Period <= 0 || v.UnixTime < 0 {
			t.Fatalf("vector %q: invalid time/period", v.ID)
		}

		secret := secretBytes(t, doc.Secrets, v.Secret)
		got, err := otp.GenerateTOTP(secret, v.UnixTime, v.Period, v.Digits, otp.Algorithm(v.Algorithm))
		if err != nil {
			t.Fatalf("vector %q: %v", v.ID, err)
		}
		if got != v.Code {
			t.Fatalf("vector %q: got %s, want %s", v.ID, got, v.Code)
		}

		if v.Digits == 8 && v.Period == 30 && strings.HasPrefix(v.Provenance, "RFC 6238") {
			want, ok := published[v.Algorithm][v.UnixTime]
			if !ok {
				t.Fatalf("vector %q: unexpected published combination", v.ID)
			}
			if v.Code != want {
				t.Fatalf("vector %q: published RFC 6238 value changed: %s != %s", v.ID, v.Code, want)
			}
			foundPublished++
		}
	}
	if foundPublished != wantPublished {
		t.Fatalf("published RFC 6238 coverage: %d of %d", foundPublished, wantPublished)
	}
}
