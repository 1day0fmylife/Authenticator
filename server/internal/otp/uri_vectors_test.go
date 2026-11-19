package otp_test

import (
	"bytes"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/1day0fmylife/Authenticator/server/internal/otp"
)

type uriValidVector struct {
	Name         string  `json:"name"`
	URI          string  `json:"uri"`
	Canonical    string  `json:"canonical"`
	Type         string  `json:"type"`
	SecretBase32 string  `json:"secret_base32"`
	SecretHex    string  `json:"secret_hex"`
	Issuer       string  `json:"issuer"`
	Account      string  `json:"account"`
	Algorithm    string  `json:"algorithm"`
	Digits       int     `json:"digits"`
	Period       *int    `json:"period"`
	Counter      *uint64 `json:"counter"`
}

type uriInvalidVector struct {
	Name   string `json:"name"`
	URI    string `json:"uri"`
	Reason string `json:"reason"`
}

type uriVectorFile struct {
	Schema      int                `json:"schema"`
	Description string             `json:"description"`
	Valid       []uriValidVector   `json:"valid"`
	Invalid     []uriInvalidVector `json:"invalid"`
}

func loadURIVectors(t *testing.T) uriVectorFile {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath(t, "otpauth.json"))
	if err != nil {
		t.Fatalf("read otpauth.json: %v", err)
	}
	var doc uriVectorFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse otpauth.json: %v", err)
	}
	if doc.Schema != 1 {
		t.Fatalf("otpauth.json: unsupported schema %d", doc.Schema)
	}
	if len(doc.Valid) < 20 || len(doc.Invalid) < 40 {
		t.Fatalf("otpauth.json: %d valid, %d invalid vectors", len(doc.Valid), len(doc.Invalid))
	}
	return doc
}

// stdlibSecret independently decodes secret_base32 with the standard library
// so the vectors are not validated only by the code under test.
func stdlibSecret(t *testing.T, v uriValidVector) []byte {
	t.Helper()
	got, err := base32.StdEncoding.WithPadding(base32.NoPadding).
		DecodeString(strings.TrimRight(v.SecretBase32, "="))
	if err != nil {
		t.Fatalf("vector %q: stdlib base32: %v", v.Name, err)
	}
	want, err := hex.DecodeString(v.SecretHex)
	if err != nil {
		t.Fatalf("vector %q: secret_hex: %v", v.Name, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("vector %q: secret_base32 and secret_hex disagree", v.Name)
	}
	return want
}

func TestURIVectorsValid(t *testing.T) {
	doc := loadURIVectors(t)
	seen := map[string]bool{}

	for _, v := range doc.Valid {
		if seen[v.Name] {
			t.Fatalf("duplicate vector name %q", v.Name)
		}
		seen[v.Name] = true
		if v.Canonical == "" {
			t.Fatalf("vector %q: missing canonical form", v.Name)
		}

		secret := stdlibSecret(t, v)
		parsed, err := otp.ParseURI(v.URI)
		if err != nil {
			t.Fatalf("vector %q: %v", v.Name, err)
		}

		if got, want := string(parsed.Type()), v.Type; got != want {
			t.Fatalf("vector %q: type %q, want %q", v.Name, got, want)
		}
		if !bytes.Equal(parsed.Secret(), secret) {
			t.Fatalf("vector %q: secret mismatch", v.Name)
		}
		if got, want := parsed.Issuer(), v.Issuer; got != want {
			t.Fatalf("vector %q: issuer %q, want %q", v.Name, got, want)
		}
		if got, want := parsed.Account(), v.Account; got != want {
			t.Fatalf("vector %q: account %q, want %q", v.Name, got, want)
		}
		if got, want := string(parsed.Algorithm()), v.Algorithm; got != want {
			t.Fatalf("vector %q: algorithm %q, want %q", v.Name, got, want)
		}
		if got, want := parsed.Digits(), v.Digits; got != want {
			t.Fatalf("vector %q: digits %d, want %d", v.Name, got, want)
		}

		switch v.Type {
		case "totp":
			if v.Period == nil || v.Counter != nil {
				t.Fatalf("vector %q: totp needs period and no counter", v.Name)
			}
			if got := parsed.Period(); got != *v.Period {
				t.Fatalf("vector %q: period %d, want %d", v.Name, got, *v.Period)
			}
			if got := parsed.Counter(); got != 0 {
				t.Fatalf("vector %q: period-based entry has counter %d", v.Name, got)
			}
		case "hotp":
			if v.Counter == nil || v.Period != nil {
				t.Fatalf("vector %q: hotp needs counter and no period", v.Name)
			}
			if got := parsed.Counter(); got != *v.Counter {
				t.Fatalf("vector %q: counter %d, want %d", v.Name, got, *v.Counter)
			}
			if got := parsed.Period(); got != 0 {
				t.Fatalf("vector %q: counter-based entry has period %d", v.Name, got)
			}
		default:
			t.Fatalf("vector %q: unknown type %q", v.Name, v.Type)
		}

		formatted, err := parsed.Format()
		if err != nil {
			t.Fatalf("vector %q: format: %v", v.Name, err)
		}
		if formatted != v.Canonical {
			t.Fatalf("vector %q: canonical\n got %s\nwant %s", v.Name, formatted, v.Canonical)
		}

		reparsed, err := otp.ParseURI(formatted)
		if err != nil {
			t.Fatalf("vector %q: canonical form rejected: %v", v.Name, err)
		}
		if !parsed.Equal(reparsed) {
			t.Fatalf("vector %q: canonical round trip changed the entry", v.Name)
		}
	}
}

func TestURIVectorsInvalid(t *testing.T) {
	doc := loadURIVectors(t)

	for _, v := range doc.Invalid {
		if v.Reason == "" {
			t.Fatalf("vector %q: missing reason", v.Name)
		}
		parsed, err := otp.ParseURI(v.URI)
		if err == nil {
			t.Fatalf("vector %q: accepted %q", v.Name, v.URI)
		}
		if parsed != nil {
			t.Fatalf("vector %q: value returned with an error", v.Name)
		}
		if strings.Contains(err.Error(), "JBSWY3DPEHPK3PXP") ||
			strings.Contains(err.Error(), "alice") {
			t.Fatalf("vector %q: error echoes input: %v", v.Name, err)
		}
		if !isURISentinel(err) {
			t.Fatalf("vector %q: uncategorized error: %v", v.Name, err)
		}
	}
}
