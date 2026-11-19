package main

// Structural verification of tests/vectors/otpauth.json.
//
// This command deliberately does not parse otpauth URIs: the strict parser is
// the code under test, and a third implementation would add another thing to
// get wrong. Instead it verifies the invariants the shared file must satisfy on
// its own terms:
//
//   - the secret decodes with the standard library Base32 to `secret_hex` and
//     is already in the canonical uppercase, unpadded encoding;
//   - `canonical` carries the secret first, omits every default parameter and
//     keeps the fixed parameter order used by both implementations;
//   - each vector describes exactly one OTP family (period xor counter) and
//     stays inside the documented limits;
//   - names are unique, reasons are present and no invalid vector repeats a
//     canonical form.

import (
	"bytes"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

type otpauthValidVector struct {
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

type otpauthInvalidVector struct {
	Name   string `json:"name"`
	URI    string `json:"uri"`
	Reason string `json:"reason"`
}

type otpauthDoc struct {
	Schema      int                    `json:"schema"`
	Kind        string                 `json:"kind"`
	Description string                 `json:"description"`
	Valid       []otpauthValidVector   `json:"valid"`
	Invalid     []otpauthInvalidVector `json:"invalid"`
}

var base32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

func verifyOTPAuth(dir string) error {
	var doc otpauthDoc
	if err := loadJSON(filepath.Join(dir, "otpauth.json"), &doc); err != nil {
		return err
	}
	if doc.Schema != 1 || doc.Kind != "otpauth" {
		return fmt.Errorf("otpauth.json: schema/kind mismatch")
	}
	if len(doc.Valid) < 20 || len(doc.Invalid) < 40 {
		return fmt.Errorf("otpauth.json: %d valid and %d invalid vectors", len(doc.Valid), len(doc.Invalid))
	}

	seen := map[string]bool{}
	canonicals := map[string]bool{}
	for _, v := range doc.Valid {
		if err := checkOTPAuthValid(v, seen); err != nil {
			return err
		}
		// Several inputs may normalize to the same canonical form (for
		// example a reordered query); that is the point of those vectors.
		canonicals[v.Canonical] = true
	}

	for _, v := range doc.Invalid {
		if v.Name == "" || seen[v.Name] {
			return fmt.Errorf("otpauth.json: empty or duplicate vector name %q", v.Name)
		}
		seen[v.Name] = true
		if v.Reason == "" {
			return fmt.Errorf("otpauth.json: vector %q has no reason", v.Name)
		}
		if canonicals[v.URI] {
			return fmt.Errorf("otpauth.json: invalid vector %q uses an accepted canonical form", v.Name)
		}
	}

	fmt.Printf("OTPAUTH: %d valid and %d invalid vectors verified\n", len(doc.Valid), len(doc.Invalid))
	return nil
}

func checkOTPAuthValid(v otpauthValidVector, seen map[string]bool) error {
	if v.Name == "" || seen[v.Name] {
		return fmt.Errorf("otpauth.json: empty or duplicate vector name %q", v.Name)
	}
	seen[v.Name] = true

	switch v.Type {
	case "totp", "hotp":
	default:
		return fmt.Errorf("vector %q: unknown type %q", v.Name, v.Type)
	}
	if v.Digits != 6 && v.Digits != 8 {
		return fmt.Errorf("vector %q: unsupported digits %d", v.Name, v.Digits)
	}
	switch v.Algorithm {
	case "SHA1", "SHA256", "SHA512":
	default:
		return fmt.Errorf("vector %q: unsupported algorithm %q", v.Name, v.Algorithm)
	}

	secretHex, err := hex.DecodeString(v.SecretHex)
	if err != nil || len(secretHex) == 0 {
		return fmt.Errorf("vector %q: invalid secret_hex", v.Name)
	}
	decoded, err := base32NoPadding.DecodeString(v.SecretBase32)
	if err != nil {
		return fmt.Errorf("vector %q: secret_base32: %w", v.Name, err)
	}
	if !bytes.Equal(decoded, secretHex) {
		return fmt.Errorf("vector %q: secret_base32 and secret_hex disagree", v.Name)
	}
	if base32NoPadding.EncodeToString(secretHex) != v.SecretBase32 {
		return fmt.Errorf("vector %q: secret_base32 is not canonical uppercase", v.Name)
	}

	if v.Issuer == "" {
		if strings.HasPrefix(v.Canonical, "otpauth://"+v.Type+"/:") {
			return fmt.Errorf("vector %q: empty issuer rendered as a prefix", v.Name)
		}
	}

	prefix := "otpauth://" + v.Type + "/"
	if !strings.HasPrefix(v.Canonical, prefix) {
		return fmt.Errorf("vector %q: canonical form has the wrong prefix", v.Name)
	}
	for i := 0; i < len(v.Canonical); i++ {
		if b := v.Canonical[i]; b <= 0x20 || b >= 0x7f {
			return fmt.Errorf("vector %q: canonical form must be percent-encoded ASCII", v.Name)
		}
	}

	path, query, ok := strings.Cut(v.Canonical[len(prefix):], "?")
	if !ok || path == "" {
		return fmt.Errorf("vector %q: canonical form has no label or query", v.Name)
	}
	secretToken, params, _ := strings.Cut(query, "&")
	if !strings.HasPrefix(secretToken, "secret=") {
		return fmt.Errorf("vector %q: canonical secret is not the first parameter", v.Name)
	}
	if got := strings.TrimPrefix(secretToken, "secret="); got != v.SecretBase32 {
		return fmt.Errorf("vector %q: canonical secret %q does not match", v.Name, got)
	}

	var keys []string
	values := map[string]string{}
	if params != "" {
		for _, item := range strings.Split(params, "&") {
			key, value, ok := strings.Cut(item, "=")
			if !ok || key == "" || value == "" {
				return fmt.Errorf("vector %q: malformed canonical parameter %q", v.Name, item)
			}
			if _, dup := values[key]; dup {
				return fmt.Errorf("vector %q: duplicate canonical parameter %q", v.Name, key)
			}
			keys = append(keys, key)
			values[key] = value
		}
	}

	var want []string
	if v.Issuer != "" {
		want = append(want, "issuer")
	}
	if v.Algorithm != "SHA1" {
		want = append(want, "algorithm")
	}
	if v.Digits != 6 {
		want = append(want, "digits")
	}
	switch v.Type {
	case "totp":
		if v.Period == nil || v.Counter != nil {
			return fmt.Errorf("vector %q: totp needs period and no counter", v.Name)
		}
		if *v.Period < 1 || *v.Period > 86400 {
			return fmt.Errorf("vector %q: period %d out of range", v.Name, *v.Period)
		}
		if *v.Period != 30 {
			want = append(want, "period")
		}
	case "hotp":
		if v.Counter == nil || v.Period != nil {
			return fmt.Errorf("vector %q: hotp needs counter and no period", v.Name)
		}
		want = append(want, "counter")
	}

	if strings.Join(keys, ",") != strings.Join(want, ",") {
		return fmt.Errorf("vector %q: canonical parameters %v, want %v", v.Name, keys, want)
	}

	if v.Issuer != "" && values["issuer"] == "" {
		return fmt.Errorf("vector %q: canonical issuer is empty", v.Name)
	}
	if v.Algorithm != "SHA1" && values["algorithm"] != v.Algorithm {
		return fmt.Errorf("vector %q: canonical algorithm %q", v.Name, values["algorithm"])
	}
	if v.Digits != 6 && values["digits"] != strconv.Itoa(v.Digits) {
		return fmt.Errorf("vector %q: canonical digits %q", v.Name, values["digits"])
	}
	if v.Type == "totp" && *v.Period != 30 && values["period"] != strconv.Itoa(*v.Period) {
		return fmt.Errorf("vector %q: canonical period %q", v.Name, values["period"])
	}
	if v.Type == "hotp" && values["counter"] != strconv.FormatUint(*v.Counter, 10) {
		return fmt.Errorf("vector %q: canonical counter %q", v.Name, values["counter"])
	}
	return nil
}
