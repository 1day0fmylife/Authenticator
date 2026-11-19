package otp_test

// Native Go fuzzing for the strict otpauth:// parser and the HOTP/TOTP core.
//
// The seeds are the shared public vectors in tests/vectors/otpauth.json, so a
// failure here is a divergence from the same corpus the Rust implementation
// uses. The fuzz targets assert only invariants that must hold for any input:
//
//   - parse never panics and never returns an unexpected error value;
//   - a rejected URI is reported with one of the documented static errors,
//     never with a message that echoes the input (which may contain a secret);
//   - an accepted URI formats to a canonical ASCII URI that reparses to an
//     equal value and formats back to the same bytes;
//   - generated HOTP/TOTP codes validate at the same counter/time, and
//     arbitrary user-supplied codes are rejected without panicking.
//
// Failure artifacts are written by the Go fuzzer under testdata/fuzz/. They can
// contain secrets copied from the corpus, so that directory is git-ignored:
// reproduce locally, then add a redacted regression vector to the shared JSON
// instead of committing the artifact.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/1day0fmylife/Authenticator/server/internal/otp"
)

func fuzzVectorsPath(f *testing.F) string {
	f.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		f.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "tests", "vectors", "otpauth.json")
}

func seedURICorpus(f *testing.F) {
	f.Helper()
	raw, err := os.ReadFile(fuzzVectorsPath(f))
	if err != nil {
		f.Fatalf("read otpauth.json: %v", err)
	}
	var doc struct {
		Schema int `json:"schema"`
		Valid  []struct {
			URI       string `json:"uri"`
			Canonical string `json:"canonical"`
		} `json:"valid"`
		Invalid []struct {
			URI string `json:"uri"`
		} `json:"invalid"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		f.Fatalf("parse otpauth.json: %v", err)
	}
	if doc.Schema != 1 || len(doc.Valid) < 20 || len(doc.Invalid) < 40 {
		f.Fatalf("unexpected otpauth.json shape: schema=%d valid=%d invalid=%d",
			doc.Schema, len(doc.Valid), len(doc.Invalid))
	}
	for _, vector := range doc.Valid {
		f.Add(vector.URI)
		f.Add(vector.Canonical)
	}
	for _, vector := range doc.Invalid {
		f.Add(vector.URI)
	}

	for _, extra := range []string{
		"",
		"?",
		"otpauth://",
		"otpauth://totp/",
		"otpauth://totp/x?secret=",
		"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP",
		"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0",
		"otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=18446744073709551615",
		"otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=18446744073709551616",
		"otpauth://totp/a:b?secret=JBSWY3DPEHPK3PXP&issuer=a",
		"otpauth://totp/a%00b?secret=JBSWY3DPEHPK3PXP",
		"otpauth://totp/%ff?secret=JBSWY3DPEHPK3PXP",
		"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&secret=JBSWY3DPEHPK3PXP",
		"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP#fragment",
		"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP%",
		"OTPAUTH://TOTP/X?SECRET=JBSWY3DPEHPK3PXP",
		"otpauth://totp/Пример:почта@example.com?secret=JBSWY3DPEHPK3PXP",
		strings.Repeat("A", otp.MaxURIBytes),
		strings.Repeat("A", otp.MaxURIBytes+1),
	} {
		f.Add(extra)
	}
}

// uriErrorSentinels is the complete set of errors the URI surface documents.
// A fuzz finding that reports anything else is a contract regression.
func uriErrorSentinels() map[error]struct{} {
	return map[error]struct{}{
		otp.ErrEmptyURI:             {},
		otp.ErrURITooLong:           {},
		otp.ErrInvalidScheme:        {},
		otp.ErrInvalidURIType:       {},
		otp.ErrInvalidLabel:         {},
		otp.ErrInvalidEscape:        {},
		otp.ErrInvalidURICharacter:  {},
		otp.ErrControlCharacter:     {},
		otp.ErrInvalidUTF8:          {},
		otp.ErrInvalidIssuer:        {},
		otp.ErrInvalidAccount:       {},
		otp.ErrMissingSecret:        {},
		otp.ErrMissingCounter:       {},
		otp.ErrDuplicateParameter:   {},
		otp.ErrUnsupportedParameter: {},
		otp.ErrInvalidParameter:     {},
		otp.ErrInvalidCounter:       {},
		otp.ErrContradictoryIssuer:  {},
		otp.ErrUnexpectedParameter:  {},
		otp.ErrInvalidSecret:        {},
		otp.ErrInvalidAlgorithm:     {},
		otp.ErrInvalidDigits:        {},
		otp.ErrInvalidPeriod:        {},
	}
}

// assertStaticURIError verifies that err is one of the documented values and
// that its text is the fixed message. The raw input is deliberately not
// printed: it may contain key material.
func assertStaticURIError(t *testing.T, err error) {
	t.Helper()
	sentinels := uriErrorSentinels()
	if _, ok := sentinels[err]; !ok {
		t.Fatalf("parser returned unexpected error type %T", err)
	}
	for known := range sentinels {
		if err.Error() == known.Error() {
			return
		}
	}
	t.Fatalf("error text is not a documented static message (%d bytes)", len(err.Error()))
}

func assertCanonicalURI(t *testing.T, canonical string) {
	t.Helper()
	if len(canonical) > otp.MaxURIBytes {
		t.Fatalf("canonical URI is %d bytes, limit is %d", len(canonical), otp.MaxURIBytes)
	}
	if !strings.HasPrefix(canonical, "otpauth://") {
		t.Fatalf("canonical URI does not start with otpauth://")
	}
	for i := 0; i < len(canonical); i++ {
		if canonical[i] < 0x21 || canonical[i] > 0x7e {
			t.Fatalf("canonical URI contains non-printable byte 0x%02x at %d", canonical[i], i)
		}
	}
}

func assertRedacted(t *testing.T, uri *otp.URI) {
	t.Helper()
	for _, format := range []string{"%v", "%+v", "%#v"} {
		rendered := fmt.Sprintf(format, uri)
		if !strings.Contains(rendered, "<redacted>") {
			t.Fatalf("format %s did not redact the secret", format)
		}
	}
	rendered := fmt.Sprintf("%v", *uri)
	if !strings.Contains(rendered, "<redacted>") {
		t.Fatal("value formatting did not redact the secret")
	}
}

func FuzzParseURI(f *testing.F) {
	seedURICorpus(f)

	f.Fuzz(func(t *testing.T, raw string) {
		uri, err := otp.ParseURI(raw)
		if len(raw) > otp.MaxURIBytes {
			if err != otp.ErrURITooLong {
				t.Fatalf("%d-byte input was not rejected as too long", len(raw))
			}
			return
		}
		if raw == "" {
			if err != otp.ErrEmptyURI {
				t.Fatal("empty input was not rejected as empty")
			}
			return
		}
		if err != nil {
			assertStaticURIError(t, err)
			return
		}

		if len(uri.Secret()) == 0 || len(uri.Secret()) > otp.MaxSecretBytes {
			t.Fatalf("accepted URI has secret length %d", len(uri.Secret()))
		}

		canonical, err := uri.Format()
		if err != nil {
			t.Fatalf("Format rejected a URI that ParseURI accepted: %v", err)
		}
		assertCanonicalURI(t, canonical)
		assertRedacted(t, uri)

		reparsed, err := otp.ParseURI(canonical)
		if err != nil {
			t.Fatalf("canonical URI (%d bytes) did not reparse: %v", len(canonical), err)
		}
		if !uri.Equal(reparsed) {
			t.Fatal("canonical round-trip changed the parsed value")
		}
		second, err := reparsed.Format()
		if err != nil {
			t.Fatalf("canonical URI did not reformat: %v", err)
		}
		if second != canonical {
			t.Fatalf("canonical form is not stable: %d then %d bytes", len(canonical), len(second))
		}
	})
}

func fuzzAlgorithm(id uint8) (otp.Algorithm, bool) {
	switch id {
	case 0:
		return otp.SHA1, true
	case 1:
		return otp.SHA256, true
	case 2:
		return otp.SHA512, true
	default:
		return "", false
	}
}

func assertStaticOTPError(t *testing.T, err error) {
	t.Helper()
	known := map[error]struct{}{
		otp.ErrInvalidSecret:    {},
		otp.ErrInvalidDigits:    {},
		otp.ErrInvalidPeriod:    {},
		otp.ErrInvalidCode:      {},
		otp.ErrInvalidAlgorithm: {},
		otp.ErrInvalidTime:      {},
		otp.ErrCounterOverflow:  {},
	}
	if _, ok := known[err]; !ok {
		t.Fatalf("OTP core returned unexpected error type %T", err)
	}
}

// FuzzOTP exercises the HOTP/TOTP core with bounded inputs: valid generated
// codes must verify, and arbitrary user-supplied codes must be handled without
// panics or unexpected errors.
func FuzzOTP(f *testing.F) {
	for _, secret := range []string{
		"12345678901234567890",
		"JBSWY3DPEHPK3PXP",
		"",
		strings.Repeat("k", otp.MaxSecretBytes),
	} {
		f.Add([]byte(secret), uint64(0), int64(0), 6, uint8(0), "755224")
		f.Add([]byte(secret), uint64(1<<63), int64(1_700_000_000), 8, uint8(1), "00000000")
	}

	f.Fuzz(func(t *testing.T, secret []byte, counter uint64, unixTime int64, digits int, algID uint8, code string) {
		// Keep HMAC inputs bounded: the parser core must reject oversize
		// secrets, but the fuzzer should not spend time allocating them.
		if len(secret) > otp.MaxSecretBytes+1 {
			secret = secret[:otp.MaxSecretBytes+1]
		}
		if len(code) > 32 {
			code = code[:32]
		}
		alg, ok := fuzzAlgorithm(algID)
		if !ok {
			return
		}

		hotp, err := otp.GenerateHOTP(secret, counter, digits, alg)
		if err != nil {
			assertStaticOTPError(t, err)
		} else {
			if len(hotp) != digits {
				t.Fatalf("HOTP code length %d for digits %d", len(hotp), digits)
			}
			matchedCounter, matched, err := otp.ValidateHOTP(secret, hotp, counter, digits, alg, 0)
			if err != nil {
				t.Fatalf("ValidateHOTP rejected a generated code: %v", err)
			}
			if !matched || matchedCounter != counter {
				t.Fatalf("generated HOTP code did not validate at its counter")
			}
			if _, _, err := otp.ValidateHOTP(secret, code, counter, digits, alg, 0); err != nil {
				assertStaticOTPError(t, err)
			}
		}

		totp, err := otp.GenerateTOTP(secret, unixTime, otp.DefaultPeriod, digits, alg)
		if err != nil {
			assertStaticOTPError(t, err)
			return
		}
		if len(totp) != digits {
			t.Fatalf("TOTP code length %d for digits %d", len(totp), digits)
		}
		matched, err := otp.ValidateTOTP(secret, totp, unixTime, otp.DefaultPeriod, digits, alg, 0)
		if err != nil {
			t.Fatalf("ValidateTOTP rejected a generated code: %v", err)
		}
		if !matched {
			t.Fatal("generated TOTP code did not validate at its time step")
		}
	})
}
