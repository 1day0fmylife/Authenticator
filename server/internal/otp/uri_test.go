package otp_test

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/1day0fmylife/Authenticator/server/internal/otp"
)

const uriTestSecret = "JBSWY3DPEHPK3PXP"

var uriSentinels = []error{
	otp.ErrEmptyURI,
	otp.ErrURITooLong,
	otp.ErrInvalidScheme,
	otp.ErrInvalidURIType,
	otp.ErrInvalidLabel,
	otp.ErrInvalidEscape,
	otp.ErrInvalidURICharacter,
	otp.ErrControlCharacter,
	otp.ErrInvalidUTF8,
	otp.ErrInvalidSecret,
	otp.ErrInvalidIssuer,
	otp.ErrInvalidAccount,
	otp.ErrMissingSecret,
	otp.ErrMissingCounter,
	otp.ErrDuplicateParameter,
	otp.ErrUnsupportedParameter,
	otp.ErrInvalidParameter,
	otp.ErrInvalidAlgorithm,
	otp.ErrInvalidDigits,
	otp.ErrInvalidPeriod,
	otp.ErrInvalidCounter,
	otp.ErrContradictoryIssuer,
	otp.ErrUnexpectedParameter,
}

func isURISentinel(err error) bool {
	for _, sentinel := range uriSentinels {
		if errors.Is(err, sentinel) {
			return true
		}
	}
	return false
}

func TestParseURIMinimalTOTP(t *testing.T) {
	uri, err := otp.ParseURI("otpauth://totp/alice?secret=" + uriTestSecret)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := uri.Type(); got != otp.TypeTOTP {
		t.Fatalf("type %q", got)
	}
	if got := uri.Algorithm(); got != otp.SHA1 {
		t.Fatalf("algorithm %q", got)
	}
	if got := uri.Digits(); got != 6 {
		t.Fatalf("digits %d", got)
	}
	if got := uri.Period(); got != otp.DefaultPeriod {
		t.Fatalf("period %d", got)
	}
	if got := uri.Counter(); got != 0 {
		t.Fatalf("counter %d", got)
	}
	if got := string(uri.Secret()); got != "Hello!\xde\xad\xbe\xef" {
		t.Fatalf("secret %x", got)
	}
	if got := uri.Issuer(); got != "" {
		t.Fatalf("issuer %q", got)
	}
	if got := uri.Account(); got != "alice" {
		t.Fatalf("account %q", got)
	}
}

// TestParseURIErrorClassification pins one sentinel per failure mode so a
// refactor cannot silently widen or narrow the accepted grammar.
func TestParseURIErrorClassification(t *testing.T) {
	secret := "secret=" + uriTestSecret
	cases := []struct {
		name string
		uri  string
		want error
	}{
		{"empty", "", otp.ErrEmptyURI},
		{"wrong-scheme", "https://totp/a?" + secret, otp.ErrInvalidScheme},
		{"missing-slashes", "otpauth:/totp/a?" + secret, otp.ErrInvalidScheme},
		{"unknown-type", "otpauth://motp/a?" + secret, otp.ErrInvalidURIType},
		{"missing-slash", "otpauth://totp?" + secret, otp.ErrInvalidURIType},
		{"empty-label", "otpauth://totp/?" + secret, otp.ErrInvalidLabel},
		{"extra-segment", "otpauth://totp/a/b?" + secret, otp.ErrInvalidLabel},
		{"fragment", "otpauth://totp/a?" + secret + "#x", otp.ErrInvalidURICharacter},
		{"raw-space", "otpauth://totp/a b?" + secret, otp.ErrInvalidURICharacter},
		{"raw-non-ascii", "otpauth://totp/алиса?" + secret, otp.ErrInvalidURICharacter},
		{"unknown-parameter", "otpauth://totp/a?" + secret + "&image=x", otp.ErrUnsupportedParameter},
		{"duplicate-parameter", "otpauth://totp/a?" + secret + "&secret=MZXW6", otp.ErrDuplicateParameter},
		{"duplicate-different-case", "otpauth://totp/a?" + secret + "&SECRET=MZXW6", otp.ErrDuplicateParameter},
		{"invalid-digits", "otpauth://totp/a?" + secret + "&digits=7", otp.ErrInvalidDigits},
		{"invalid-algorithm", "otpauth://totp/a?" + secret + "&algorithm=MD5", otp.ErrInvalidAlgorithm},
		{"algorithm-unicode-fold", "otpauth://totp/a?" + secret + "&algorithm=%C5%BFHA1", otp.ErrInvalidAlgorithm},
		{"period-zero", "otpauth://totp/a?" + secret + "&period=0", otp.ErrInvalidPeriod},
		{"period-overflow", "otpauth://totp/a?" + secret + "&period=18446744073709551616", otp.ErrInvalidPeriod},
		{"missing-counter", "otpauth://hotp/a?" + secret, otp.ErrMissingCounter},
		{"counter-on-totp", "otpauth://totp/a?" + secret + "&counter=1", otp.ErrUnexpectedParameter},
		{"period-on-hotp", "otpauth://hotp/a?" + secret + "&counter=1&period=30", otp.ErrUnexpectedParameter},
		{"issuer-conflict", "otpauth://totp/A:a?" + secret + "&issuer=B", otp.ErrContradictoryIssuer},
		{"escaped-null", "otpauth://totp/a?" + secret + "%00", otp.ErrControlCharacter},
		{"invalid-utf8", "otpauth://totp/a%ff?" + secret, otp.ErrInvalidUTF8},
		{"truncated-escape", "otpauth://totp/a?" + secret + "%", otp.ErrInvalidEscape},
		{"empty-issuer-parameter", "otpauth://totp/a?" + secret + "&issuer=", otp.ErrInvalidIssuer},
		{"empty-label-issuer", "otpauth://totp/:a?" + secret, otp.ErrInvalidLabel},
		{"double-colon", "otpauth://totp/A:b:c?" + secret, otp.ErrInvalidLabel},
		{"empty-account", "otpauth://totp/A:?" + secret, otp.ErrInvalidLabel},
		{"trailing-ampersand", "otpauth://totp/a?" + secret + "&", otp.ErrInvalidParameter},
		{"item-without-equals", "otpauth://totp/a?secret", otp.ErrInvalidParameter},
		{"empty-key", "otpauth://totp/a?=x&" + secret, otp.ErrInvalidParameter},
		{"empty-query", "otpauth://totp/a?", otp.ErrInvalidParameter},
		{"missing-secret", "otpauth://totp/a", otp.ErrMissingSecret},
		{"empty-secret", "otpauth://totp/a?secret=", otp.ErrInvalidSecret},
		{"not-base32", "otpauth://totp/a?secret=JBSWY3DPEHPK3PX1", otp.ErrInvalidSecret},
	}

	for _, tc := range cases {
		uri, err := otp.ParseURI(tc.uri)
		if err == nil {
			t.Fatalf("%s: accepted %q", tc.name, tc.uri)
		}
		if uri != nil {
			t.Fatalf("%s: non-nil value with error", tc.name)
		}
		if !errors.Is(err, tc.want) {
			t.Fatalf("%s: got %v, want %v", tc.name, err, tc.want)
		}
		if strings.Contains(err.Error(), uriTestSecret) || strings.Contains(err.Error(), "alice") {
			t.Fatalf("%s: error echoes input: %v", tc.name, err)
		}
	}
}

func TestParseURITooLong(t *testing.T) {
	_, err := otp.ParseURI("otpauth://totp/alice?secret=" + strings.Repeat("A", otp.MaxURIBytes))
	if !errors.Is(err, otp.ErrURITooLong) {
		t.Fatalf("got %v, want ErrURITooLong", err)
	}
}

func TestURIFormattingIsRedacted(t *testing.T) {
	uri, err := otp.ParseURI("otpauth://totp/Example:alice?" + "secret=" + uriTestSecret + "&issuer=Example")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, rendered := range []string{
		fmt.Sprintf("%v", uri),
		fmt.Sprintf("%s", uri),
		fmt.Sprintf("%#v", uri),
		fmt.Sprintf("%+v", uri),
		fmt.Sprintf("%v", *uri),
		fmt.Sprintf("%#v", *uri),
		uri.String(),
		uri.GoString(),
	} {
		if strings.Contains(rendered, uriTestSecret) {
			t.Fatalf("formatting leaks the secret: %s", rendered)
		}
		if strings.Contains(rendered, "alice") || strings.Contains(rendered, "Example") {
			t.Fatalf("formatting leaks labels: %s", rendered)
		}
	}
}

func TestURISecretIsCopiedAndClearable(t *testing.T) {
	uri, err := otp.ParseURI("otpauth://totp/alice?secret=" + uriTestSecret)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	got := uri.Secret()
	got[0] = 0
	if want := "Hello!\xde\xad\xbe\xef"; string(uri.Secret()) != want {
		t.Fatalf("Secret() returned a live reference: %x", uri.Secret())
	}

	uri.Clear()
	if !bytes.Equal(uri.Secret(), make([]byte, len("Hello!\xde\xad\xbe\xef"))) {
		t.Fatalf("Clear() left secret bytes: %x", uri.Secret())
	}
	// Clear() overwrites the bytes but leaves a structurally valid entry: the
	// rendered URI must no longer carry the original secret.
	formatted, err := uri.Format()
	if err != nil {
		t.Fatalf("format after Clear: %v", err)
	}
	if strings.Contains(formatted, uriTestSecret) {
		t.Fatalf("format after Clear still renders the secret: %s", formatted)
	}
}

func TestNewTOTPRejectsInvalidValues(t *testing.T) {
	secret := []byte("Hello!\xde\xad\xbe\xef")
	label := strings.Repeat("a", otp.MaxLabelBytes)

	if _, err := otp.NewTOTP(secret, label, label, otp.SHA512, 8, otp.MaxPeriod); err != nil {
		t.Fatalf("boundary values rejected: %v", err)
	}

	cases := []struct {
		name    string
		secret  []byte
		issuer  string
		account string
		alg     otp.Algorithm
		digits  int
		period  int
		want    error
	}{
		{"empty-secret", nil, "", "a", otp.SHA1, 6, 30, otp.ErrInvalidSecret},
		{"long-secret", make([]byte, otp.MaxSecretBytes+1), "", "a", otp.SHA1, 6, 30, otp.ErrInvalidSecret},
		{"empty-account", secret, "", "", otp.SHA1, 6, 30, otp.ErrInvalidAccount},
		{"long-account", secret, "", label + "a", otp.SHA1, 6, 30, otp.ErrInvalidAccount},
		{"long-issuer", secret, label + "a", "a", otp.SHA1, 6, 30, otp.ErrInvalidIssuer},
		{"control-account", secret, "", "a\nb", otp.SHA1, 6, 30, otp.ErrInvalidAccount},
		{"control-issuer", secret, "a\tb", "a", otp.SHA1, 6, 30, otp.ErrInvalidIssuer},
		{"bad-digits", secret, "", "a", otp.SHA1, 7, 30, otp.ErrInvalidDigits},
		{"bad-algorithm", secret, "", "a", otp.Algorithm("MD5"), 6, 30, otp.ErrInvalidAlgorithm},
		{"period-zero", secret, "", "a", otp.SHA1, 6, 0, otp.ErrInvalidPeriod},
		{"period-too-large", secret, "", "a", otp.SHA1, 6, otp.MaxPeriod + 1, otp.ErrInvalidPeriod},
	}

	for _, tc := range cases {
		if _, err := otp.NewTOTP(tc.secret, tc.issuer, tc.account, tc.alg, tc.digits, tc.period); !errors.Is(err, tc.want) {
			t.Fatalf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestNewHOTPAcceptsMaximumCounter(t *testing.T) {
	uri, err := otp.NewHOTP([]byte("Hello!\xde\xad\xbe\xef"), "", "a", otp.SHA1, 6, ^uint64(0))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	formatted, err := uri.Format()
	if err != nil {
		t.Fatalf("format: %v", err)
	}
	if !strings.HasSuffix(formatted, "&counter=18446744073709551615") {
		t.Fatalf("unexpected canonical form: %s", formatted)
	}
}

func TestURIEqualComparesSecrets(t *testing.T) {
	a, err := otp.ParseURI("otpauth://totp/alice?secret=" + uriTestSecret)
	if err != nil {
		t.Fatalf("parse a: %v", err)
	}
	b, err := otp.ParseURI("otpauth://totp/alice?secret=MZXW6")
	if err != nil {
		t.Fatalf("parse b: %v", err)
	}
	if a.Equal(b) || b.Equal(a) {
		t.Fatal("entries with different secrets compare equal")
	}
	if !a.Equal(a) {
		t.Fatal("entry does not equal itself")
	}
	var nilURI *otp.URI
	if nilURI.Equal(nil) != true || nilURI.Equal(a) {
		t.Fatal("nil comparison is wrong")
	}
}

func TestParseURIBase32Strictness(t *testing.T) {
	cases := []struct {
		secret string
		ok     bool
	}{
		{"MZXW6", true},
		{"mzxw6", true},
		{"MZXW6===", true},
		{"MZXW6==", false},
		{"MZXW6====", false},
		{"MZXW6===AA", false},
		{"MZXW7", false},
		{"A", false},
		{"", false},
		{"========", false},
	}
	for _, tc := range cases {
		_, err := otp.ParseURI("otpauth://totp/a?secret=" + tc.secret)
		if tc.ok && err != nil {
			t.Fatalf("secret %q: unexpected error %v", tc.secret, err)
		}
		if !tc.ok && !errors.Is(err, otp.ErrInvalidSecret) {
			t.Fatalf("secret %q: got %v, want ErrInvalidSecret", tc.secret, err)
		}
	}
}

func TestPercentDecodingIsNotFormDecoding(t *testing.T) {
	uri, err := otp.ParseURI("otpauth://totp/ACME+Co:alice+tag?secret=" + uriTestSecret + "&issuer=ACME+Co")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := uri.Issuer(); got != "ACME+Co" {
		t.Fatalf("issuer %q", got)
	}
	if got := uri.Account(); got != "alice+tag" {
		t.Fatalf("account %q", got)
	}
	formatted, err := uri.Format()
	if err != nil {
		t.Fatalf("format: %v", err)
	}
	if !strings.HasPrefix(formatted, "otpauth://totp/ACME%2BCo:alice%2Btag?") {
		t.Fatalf("unexpected canonical form: %s", formatted)
	}
}
