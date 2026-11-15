// Command verify-vectors independently recomputes the shared OTP vectors.
//
// It intentionally does not import internal/otp: it is a second, standalone
// implementation used to catch mistakes in the production package or in the
// JSON files. Standard library only.
package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type secret struct {
	ASCII  string `json:"ascii"`
	Base32 string `json:"base32"`
	Note   string `json:"note"`
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

type hotpDoc struct {
	Schema          int               `json:"schema"`
	Kind            string            `json:"kind"`
	Description     string            `json:"description"`
	SourceDocuments []string          `json:"source_documents"`
	Secrets         map[string]secret `json:"secrets"`
	Vectors         []hotpVector      `json:"vectors"`
}

type totpDoc struct {
	Schema          int               `json:"schema"`
	Kind            string            `json:"kind"`
	Description     string            `json:"description"`
	SourceDocuments []string          `json:"source_documents"`
	Secrets         map[string]secret `json:"secrets"`
	Vectors         []totpVector      `json:"vectors"`
}

func hashFor(alg string) (func() hash.Hash, error) {
	switch alg {
	case "SHA1":
		return sha1.New, nil
	case "SHA256":
		return sha256.New, nil
	case "SHA512":
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm %q", alg)
	}
}

func hotp(secret []byte, counter uint64, digits int, alg string) (string, error) {
	if len(secret) == 0 {
		return "", fmt.Errorf("empty secret")
	}
	if digits != 6 && digits != 8 {
		return "", fmt.Errorf("unsupported digits %d", digits)
	}
	newHash, err := hashFor(alg)
	if err != nil {
		return "", err
	}

	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(newHash, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)

	offset := int(sum[len(sum)-1] & 0x0f)
	value := uint32(sum[offset]&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])

	pow := uint32(1)
	for i := 0; i < digits; i++ {
		pow *= 10
	}
	code := strconv.FormatUint(uint64(value%pow), 10)
	for len(code) < digits {
		code = "0" + code
	}
	return code, nil
}

func totp(secret []byte, unixTime int64, period, digits int, alg string) (string, error) {
	if period <= 0 {
		return "", fmt.Errorf("invalid period %d", period)
	}
	if unixTime < 0 {
		return "", fmt.Errorf("negative unix time")
	}
	return hotp(secret, uint64(unixTime/int64(period)), digits, alg)
}

func decodeSecret(id string, s secret) ([]byte, error) {
	trimmed := strings.TrimRight(s.Base32, "=")
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("secret %s: base32: %w", id, err)
	}
	if string(decoded) != s.ASCII {
		return nil, fmt.Errorf("secret %s: base32 does not match ascii", id)
	}
	if len(decoded) == 0 {
		return nil, fmt.Errorf("secret %s: empty", id)
	}
	return decoded, nil
}

func loadJSON(path string, dst any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return nil
}

func verifyHOTP(dir string) error {
	var doc hotpDoc
	if err := loadJSON(filepath.Join(dir, "rfc4226-hotp.json"), &doc); err != nil {
		return err
	}
	if doc.Schema != 1 || doc.Kind != "hotp" {
		return fmt.Errorf("rfc4226-hotp.json: schema/kind mismatch")
	}
	if len(doc.Secrets) == 0 || len(doc.Vectors) == 0 {
		return fmt.Errorf("rfc4226-hotp.json: empty secrets or vectors")
	}

	published := map[uint64]string{
		0: "755224", 1: "287082", 2: "359152", 3: "969429", 4: "338314",
		5: "254676", 6: "287922", 7: "162583", 8: "399871", 9: "520489",
	}
	foundPublished := 0
	seen := map[string]bool{}
	derived := 0

	for _, v := range doc.Vectors {
		if seen[v.ID] {
			return fmt.Errorf("duplicate vector id %q", v.ID)
		}
		seen[v.ID] = true
		if v.Provenance == "" {
			return fmt.Errorf("vector %q: missing provenance", v.ID)
		}
		if len(v.Code) != v.Digits {
			return fmt.Errorf("vector %q: code length does not match digits", v.ID)
		}
		s, ok := doc.Secrets[v.Secret]
		if !ok {
			return fmt.Errorf("vector %q: unknown secret %q", v.ID, v.Secret)
		}
		secretBytes, err := decodeSecret(v.Secret, s)
		if err != nil {
			return err
		}
		got, err := hotp(secretBytes, v.Counter, v.Digits, v.Algorithm)
		if err != nil {
			return fmt.Errorf("vector %q: %w", v.ID, err)
		}
		if got != v.Code {
			return fmt.Errorf("vector %q: got %s, want %s", v.ID, got, v.Code)
		}

		if v.Digits == 6 && strings.HasPrefix(v.Provenance, "RFC 4226") {
			want, ok := published[v.Counter]
			if !ok {
				return fmt.Errorf("vector %q: unexpected published counter %d", v.ID, v.Counter)
			}
			if v.Code != want {
				return fmt.Errorf("vector %q: published value changed", v.ID)
			}
			foundPublished++
		}
		if strings.HasPrefix(v.Provenance, "derived:") {
			derived++
		}
	}
	if foundPublished != len(published) {
		return fmt.Errorf("published RFC 4226 coverage: %d of %d", foundPublished, len(published))
	}
	fmt.Printf("HOTP: %d vectors verified (%d published, %d derived)\n", len(doc.Vectors), foundPublished, derived)
	return nil
}

func verifyTOTP(dir string) error {
	var doc totpDoc
	if err := loadJSON(filepath.Join(dir, "rfc6238-totp.json"), &doc); err != nil {
		return err
	}
	if doc.Schema != 1 || doc.Kind != "totp" {
		return fmt.Errorf("rfc6238-totp.json: schema/kind mismatch")
	}
	if len(doc.Secrets) == 0 || len(doc.Vectors) == 0 {
		return fmt.Errorf("rfc6238-totp.json: empty secrets or vectors")
	}

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
	wantPublished := 0
	for _, byTime := range published {
		wantPublished += len(byTime)
	}
	foundPublished := 0
	seen := map[string]bool{}
	derived := 0

	for _, v := range doc.Vectors {
		if seen[v.ID] {
			return fmt.Errorf("duplicate vector id %q", v.ID)
		}
		seen[v.ID] = true
		if v.Provenance == "" {
			return fmt.Errorf("vector %q: missing provenance", v.ID)
		}
		if len(v.Code) != v.Digits {
			return fmt.Errorf("vector %q: code length does not match digits", v.ID)
		}
		if v.Period <= 0 || v.Period > 86400 {
			return fmt.Errorf("vector %q: invalid period %d", v.ID, v.Period)
		}
		if v.UnixTime < 0 {
			return fmt.Errorf("vector %q: negative unix time", v.ID)
		}
		s, ok := doc.Secrets[v.Secret]
		if !ok {
			return fmt.Errorf("vector %q: unknown secret %q", v.ID, v.Secret)
		}
		secretBytes, err := decodeSecret(v.Secret, s)
		if err != nil {
			return err
		}
		got, err := totp(secretBytes, v.UnixTime, v.Period, v.Digits, v.Algorithm)
		if err != nil {
			return fmt.Errorf("vector %q: %w", v.ID, err)
		}
		if got != v.Code {
			return fmt.Errorf("vector %q: got %s, want %s", v.ID, got, v.Code)
		}

		if v.Digits == 8 && v.Period == 30 && strings.HasPrefix(v.Provenance, "RFC 6238") {
			byTime, ok := published[v.Algorithm]
			if !ok {
				return fmt.Errorf("vector %q: unexpected published algorithm", v.ID)
			}
			want, ok := byTime[v.UnixTime]
			if !ok {
				return fmt.Errorf("vector %q: unexpected published time", v.ID)
			}
			if v.Code != want {
				return fmt.Errorf("vector %q: published value changed", v.ID)
			}
			foundPublished++
		}
		if strings.HasPrefix(v.Provenance, "derived:") {
			derived++
		}
	}
	if foundPublished != wantPublished {
		return fmt.Errorf("published RFC 6238 coverage: %d of %d", foundPublished, wantPublished)
	}
	fmt.Printf("TOTP: %d vectors verified (%d published, %d derived)\n", len(doc.Vectors), foundPublished, derived)
	return nil
}

func main() {
	dir := flag.String("dir", "../tests/vectors", "directory containing rfc4226-hotp.json and rfc6238-totp.json")
	flag.Parse()

	if err := verifyHOTP(*dir); err != nil {
		fmt.Fprintln(os.Stderr, "verify-vectors:", err)
		os.Exit(1)
	}
	if err := verifyTOTP(*dir); err != nil {
		fmt.Fprintln(os.Stderr, "verify-vectors:", err)
		os.Exit(1)
	}
	fmt.Println("OK: shared OTP vectors are consistent")
}
