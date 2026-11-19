package otp

// Strict `otpauth://` Key URI parser and generator.
//
// The grammar is the Key Uri Format used by Google Authenticator and
// compatible products, restricted to the subset supported by this project:
// totp and hotp, SHA-1/256/512, 6 or 8 digits and a bounded period/counter.
//
// Deliberate v1 restrictions (mirrored by the Rust parser in
// desktop/crates/otp-core/src/uri.rs and covered by tests/vectors/otpauth.json):
//
//   - raw input must be printable ASCII and at most MaxURIBytes; issuer,
//     account and label text outside ASCII must be percent-encoded;
//   - percent-decoding only, never form-decoding: a literal "+" stays "+";
//   - unknown or duplicate query parameters are rejected instead of ignored;
//   - digits must be exactly 6 or 8, period exactly 1..86400, the HOTP counter
//     must fit uint64; defaults are SHA-1, 6 digits and period 30;
//   - an issuer parameter and a label issuer prefix must agree exactly;
//   - for HOTP counter is required and period is forbidden, for TOTP the
//     opposite applies.
//
// Errors never carry the secret, account, issuer or the rejected input.

import (
	"crypto/subtle"
	"errors"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Key URI limits and defaults.
const (
	// MaxURIBytes bounds the raw URI length in bytes.
	MaxURIBytes = 4096
	// MaxLabelBytes bounds the decoded issuer and account length in bytes.
	MaxLabelBytes = 256
	// DefaultPeriod is the TOTP period assumed when `period` is absent.
	DefaultPeriod = 30
)

const uriScheme = "otpauth://"

// URIType is the OTP family encoded in a Key URI.
type URIType string

const (
	// TypeTOTP is the time-based OTP family.
	TypeTOTP URIType = "totp"
	// TypeHOTP is the counter-based OTP family.
	TypeHOTP URIType = "hotp"
)

// String implements fmt.Stringer. It never exposes key material.
func (t URIType) String() string { return string(t) }

// Key URI parsing and generation errors. Each message is static.
var (
	ErrEmptyURI             = errors.New("otp: empty URI")
	ErrURITooLong           = errors.New("otp: URI is too long")
	ErrInvalidScheme        = errors.New("otp: URI scheme must be otpauth://")
	ErrInvalidURIType       = errors.New("otp: URI type must be totp or hotp")
	ErrInvalidLabel         = errors.New("otp: invalid URI label")
	ErrInvalidEscape        = errors.New("otp: invalid percent escape")
	ErrInvalidURICharacter  = errors.New("otp: invalid character in URI")
	ErrControlCharacter     = errors.New("otp: control character in URI")
	ErrInvalidUTF8          = errors.New("otp: URI label is not valid UTF-8")
	ErrInvalidIssuer        = errors.New("otp: invalid issuer")
	ErrInvalidAccount       = errors.New("otp: invalid account")
	ErrMissingSecret        = errors.New("otp: URI is missing secret")
	ErrMissingCounter       = errors.New("otp: HOTP URI is missing counter")
	ErrDuplicateParameter   = errors.New("otp: duplicate URI parameter")
	ErrUnsupportedParameter = errors.New("otp: unsupported URI parameter")
	ErrInvalidParameter     = errors.New("otp: malformed URI parameter")
	ErrInvalidCounter       = errors.New("otp: invalid HOTP counter")
	ErrContradictoryIssuer  = errors.New("otp: issuer prefix and parameter disagree")
	ErrUnexpectedParameter  = errors.New("otp: URI parameter is not valid for this type")
)

// URI is a parsed and validated Key URI entry.
//
// The struct keeps its fields private so that a value cannot be constructed in
// an invalid state and so that formatting never prints the secret. Use
// NewTOTP, NewHOTP or ParseURI.
type URI struct {
	otpType   URIType
	algorithm Algorithm
	digits    int
	period    int
	counter   uint64
	secret    []byte
	issuer    string
	account   string
}

// NewTOTP builds a validated TOTP entry and renders it once to check that
// every field is representable. The secret slice is copied.
func NewTOTP(secret []byte, issuer, account string, alg Algorithm, digits, period int) (*URI, error) {
	u := &URI{
		otpType:   TypeTOTP,
		algorithm: alg,
		digits:    digits,
		period:    period,
		secret:    append([]byte(nil), secret...),
		issuer:    issuer,
		account:   account,
	}
	if _, err := u.Format(); err != nil {
		return nil, err
	}
	return u, nil
}

// NewHOTP builds a validated HOTP entry and renders it once to check that
// every field is representable. The secret slice is copied.
func NewHOTP(secret []byte, issuer, account string, alg Algorithm, digits int, counter uint64) (*URI, error) {
	u := &URI{
		otpType:   TypeHOTP,
		algorithm: alg,
		digits:    digits,
		counter:   counter,
		secret:    append([]byte(nil), secret...),
		issuer:    issuer,
		account:   account,
	}
	if _, err := u.Format(); err != nil {
		return nil, err
	}
	return u, nil
}

// Type returns the OTP family.
func (u *URI) Type() URIType { return u.otpType }

// Algorithm returns the HMAC algorithm.
func (u *URI) Algorithm() Algorithm { return u.algorithm }

// Digits returns the code length, 6 or 8.
func (u *URI) Digits() int { return u.digits }

// Period returns the TOTP period in seconds, or 0 for HOTP.
func (u *URI) Period() int { return u.period }

// Counter returns the HOTP counter, or 0 for TOTP.
func (u *URI) Counter() uint64 { return u.counter }

// Secret returns a copy of the raw secret bytes so that the caller cannot
// mutate the parsed value.
func (u *URI) Secret() []byte {
	out := make([]byte, len(u.secret))
	copy(out, u.secret)
	return out
}

// Issuer returns the issuer label, which may be empty.
func (u *URI) Issuer() string { return u.issuer }

// Account returns the account label, which is never empty.
func (u *URI) Account() string { return u.account }

// Clear overwrites the in-memory secret. This is best effort: it cannot erase
// copies the caller made, or bytes moved by the garbage collector.
func (u *URI) Clear() {
	for i := range u.secret {
		u.secret[i] = 0
	}
}

// Equal reports whether two entries are identical, comparing secrets in
// constant time.
func (u *URI) Equal(other *URI) bool {
	if u == nil || other == nil {
		return u == other
	}
	if u.otpType != other.otpType ||
		u.algorithm != other.algorithm ||
		u.digits != other.digits ||
		u.period != other.period ||
		u.counter != other.counter ||
		u.issuer != other.issuer ||
		u.account != other.account ||
		len(u.secret) != len(other.secret) {
		return false
	}
	return subtle.ConstantTimeCompare(u.secret, other.secret) == 1
}

// String implements fmt.Stringer without exposing key material. The receiver is
// a value so that formatting a dereferenced copy is redacted too.
func (u URI) String() string {
	return "otp.URI{" + string(u.otpType) + ", " + string(u.algorithm) + ", " +
		strconv.Itoa(u.digits) + " digits, <redacted>}"
}

// GoString implements fmt.GoStringer without exposing key material.
func (u URI) GoString() string { return u.String() }

// Format renders the canonical URI: defaults (SHA1, 6 digits, period 30) are
// omitted, the secret is uppercase Base32 without padding and every byte
// outside the unreserved set is percent-encoded.
func (u *URI) Format() (string, error) {
	if err := u.validate(); err != nil {
		return "", err
	}

	out := make([]byte, 0, 128)
	out = append(out, uriScheme...)
	out = append(out, string(u.otpType)...)
	out = append(out, '/')
	if u.issuer != "" {
		out = appendPercentEncoded(out, u.issuer)
		out = append(out, ':')
	}
	out = appendPercentEncoded(out, u.account)
	out = append(out, "?secret="...)
	out = appendBase32(out, u.secret)

	if u.issuer != "" {
		out = append(out, "&issuer="...)
		out = appendPercentEncoded(out, u.issuer)
	}
	if u.algorithm != SHA1 {
		out = append(out, "&algorithm="...)
		out = append(out, string(u.algorithm)...)
	}
	if u.digits != 6 {
		out = append(out, "&digits="...)
		out = append(out, byte('0'+u.digits))
	}
	switch u.otpType {
	case TypeTOTP:
		if u.period != DefaultPeriod {
			out = append(out, "&period="...)
			out = strconv.AppendInt(out, int64(u.period), 10)
		}
	case TypeHOTP:
		out = append(out, "&counter="...)
		out = strconv.AppendUint(out, u.counter, 10)
	}

	if len(out) > MaxURIBytes {
		return "", ErrURITooLong
	}
	return string(out), nil
}

// ParseURI parses and validates a strict otpauth:// URI.
func ParseURI(raw string) (*URI, error) {
	if len(raw) == 0 {
		return nil, ErrEmptyURI
	}
	if len(raw) > MaxURIBytes {
		return nil, ErrURITooLong
	}
	for i := 0; i < len(raw); i++ {
		switch b := raw[i]; {
		case b == '#':
			return nil, ErrInvalidURICharacter
		case b >= 0x80 || b == ' ':
			return nil, ErrInvalidURICharacter
		case b < 0x20 || b == 0x7f:
			return nil, ErrControlCharacter
		}
	}
	if len(raw) < len(uriScheme) || !asciiEqualFold(raw[:len(uriScheme)], uriScheme) {
		return nil, ErrInvalidScheme
	}
	rest := raw[len(uriScheme):]

	typePart, afterType, ok := strings.Cut(rest, "/")
	if !ok {
		return nil, ErrInvalidURIType
	}
	if afterType == "" {
		return nil, ErrInvalidLabel
	}
	otpType, err := parseURIType(typePart)
	if err != nil {
		return nil, err
	}

	labelRaw, queryRaw, hasQuery := strings.Cut(afterType, "?")
	if labelRaw == "" || strings.ContainsRune(labelRaw, '/') {
		return nil, ErrInvalidLabel
	}
	labelIssuer, account, err := parseLabel(labelRaw)
	if err != nil {
		return nil, err
	}

	var (
		seen        [6]bool
		secret      []byte
		hasSecret   bool
		issuerParam string
		hasIssuer   bool
		algorithm   = SHA1
		digits      = 6
		period      int
		hasPeriod   bool
		counter     uint64
		hasCounter  bool
	)

	if hasQuery {
		if queryRaw == "" {
			return nil, ErrInvalidParameter
		}
		for _, item := range strings.Split(queryRaw, "&") {
			if item == "" {
				return nil, ErrInvalidParameter
			}
			keyRaw, valueRaw, ok := strings.Cut(item, "=")
			if !ok || keyRaw == "" {
				return nil, ErrInvalidParameter
			}
			index, ok := parameterIndex(keyRaw)
			if !ok {
				return nil, ErrUnsupportedParameter
			}
			if seen[index] {
				return nil, ErrDuplicateParameter
			}
			seen[index] = true

			value, err := percentDecode([]byte(valueRaw))
			if err != nil {
				return nil, err
			}

			switch index {
			case 0: // secret
				decoded, err := decodeBase32(value)
				if err != nil {
					return nil, err
				}
				if len(decoded) == 0 || len(decoded) > MaxSecretBytes {
					return nil, ErrInvalidSecret
				}
				secret = decoded
				hasSecret = true
			case 1: // issuer
				decoded, err := decodeText(value, ErrInvalidIssuer)
				if err != nil {
					return nil, err
				}
				if decoded == "" || len(decoded) > MaxLabelBytes {
					return nil, ErrInvalidIssuer
				}
				issuerParam = decoded
				hasIssuer = true
			case 2: // algorithm
				parsed, err := parseURIAlgorithm(value)
				if err != nil {
					return nil, err
				}
				algorithm = parsed
			case 3: // digits
				parsed, err := parseURIDigits(value)
				if err != nil {
					return nil, err
				}
				digits = parsed
			case 4: // period
				if otpType == TypeHOTP {
					return nil, ErrUnexpectedParameter
				}
				parsed, err := parseDecimal(value, ErrInvalidPeriod)
				if err != nil || parsed < uint64(MinPeriod) || parsed > uint64(MaxPeriod) {
					return nil, ErrInvalidPeriod
				}
				period = int(parsed)
				hasPeriod = true
			case 5: // counter
				if otpType == TypeTOTP {
					return nil, ErrUnexpectedParameter
				}
				parsed, err := parseDecimal(value, ErrInvalidCounter)
				if err != nil {
					return nil, err
				}
				counter = parsed
				hasCounter = true
			}
		}
	}

	if !hasSecret {
		return nil, ErrMissingSecret
	}

	issuer := labelIssuer
	switch {
	case labelIssuer != "" && hasIssuer && labelIssuer != issuerParam:
		return nil, ErrContradictoryIssuer
	case labelIssuer == "" && hasIssuer:
		issuer = issuerParam
	}

	u := &URI{
		otpType:   otpType,
		algorithm: algorithm,
		digits:    digits,
		secret:    secret,
		issuer:    issuer,
		account:   account,
	}
	switch otpType {
	case TypeTOTP:
		if hasPeriod {
			u.period = period
		} else {
			u.period = DefaultPeriod
		}
	case TypeHOTP:
		if !hasCounter {
			return nil, ErrMissingCounter
		}
		u.counter = counter
	}

	if err := u.validate(); err != nil {
		return nil, err
	}
	return u, nil
}

func (u *URI) validate() error {
	if u.otpType != TypeTOTP && u.otpType != TypeHOTP {
		return ErrInvalidURIType
	}
	if len(u.secret) < MinSecretBytes || len(u.secret) > MaxSecretBytes {
		return ErrInvalidSecret
	}
	if _, err := u.algorithm.newHash(); err != nil {
		return err
	}
	if err := validateDigits(u.digits); err != nil {
		return err
	}
	if len(u.issuer) > MaxLabelBytes || hasControlRune(u.issuer) {
		return ErrInvalidIssuer
	}
	if u.account == "" || len(u.account) > MaxLabelBytes || hasControlRune(u.account) {
		return ErrInvalidAccount
	}

	switch u.otpType {
	case TypeTOTP:
		if err := validatePeriod(u.period); err != nil {
			return err
		}
		if u.counter != 0 {
			return ErrInvalidPeriod
		}
	case TypeHOTP:
		if u.period != 0 {
			return ErrInvalidPeriod
		}
	}
	return nil
}

func parseURIType(value string) (URIType, error) {
	switch {
	case asciiEqualFold(value, string(TypeTOTP)):
		return TypeTOTP, nil
	case asciiEqualFold(value, string(TypeHOTP)):
		return TypeHOTP, nil
	default:
		return "", ErrInvalidURIType
	}
}

// asciiEqualFold compares ASCII case-insensitively. strings.EqualFold is not
// used because it applies Unicode folding, so a percent-encoded non-ASCII
// value such as %C5%BFHA1 would be accepted here but rejected by the Rust
// parser.
func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func parameterIndex(key string) (int, bool) {
	switch {
	case asciiEqualFold(key, "secret"):
		return 0, true
	case asciiEqualFold(key, "issuer"):
		return 1, true
	case asciiEqualFold(key, "algorithm"):
		return 2, true
	case asciiEqualFold(key, "digits"):
		return 3, true
	case asciiEqualFold(key, "period"):
		return 4, true
	case asciiEqualFold(key, "counter"):
		return 5, true
	default:
		return 0, false
	}
}

// parseLabel splits "Issuer:Account" and decodes both parts. Only the first
// raw colon is a separator; a second raw colon is a malformed label.
func parseLabel(raw string) (issuer, account string, err error) {
	issuerRaw, accountRaw, hasIssuer := strings.Cut(raw, ":")
	if !hasIssuer {
		// strings.Cut returns an empty remainder when there is no separator.
		accountRaw = raw
	} else if issuerRaw == "" || accountRaw == "" || strings.ContainsRune(accountRaw, ':') {
		return "", "", ErrInvalidLabel
	}

	if hasIssuer {
		decoded, err := percentDecode([]byte(issuerRaw))
		if err != nil {
			return "", "", err
		}
		issuer, err = decodeText(decoded, ErrInvalidUTF8)
		if err != nil {
			return "", "", err
		}
		if issuer == "" || len(issuer) > MaxLabelBytes {
			return "", "", ErrInvalidIssuer
		}
	}

	decoded, err := percentDecode([]byte(accountRaw))
	if err != nil {
		return "", "", err
	}
	account, err = decodeText(decoded, ErrInvalidUTF8)
	if err != nil {
		return "", "", err
	}
	if account == "" || len(account) > MaxLabelBytes {
		return "", "", ErrInvalidAccount
	}
	return issuer, account, nil
}

func decodeText(raw []byte, utf8Error error) (string, error) {
	if !utf8.Valid(raw) {
		return "", utf8Error
	}
	text := string(raw)
	if hasControlRune(text) {
		return "", ErrControlCharacter
	}
	return text, nil
}

func hasControlRune(text string) bool {
	return strings.IndexFunc(text, unicode.IsControl) >= 0
}

func percentDecode(input []byte) ([]byte, error) {
	out := make([]byte, 0, len(input))
	for i := 0; i < len(input); {
		b := input[i]
		if b == '%' {
			if i+2 >= len(input) {
				return nil, ErrInvalidEscape
			}
			high, ok := hexValue(input[i+1])
			if !ok {
				return nil, ErrInvalidEscape
			}
			low, ok := hexValue(input[i+2])
			if !ok {
				return nil, ErrInvalidEscape
			}
			decoded := high<<4 | low
			if decoded < 0x20 || decoded == 0x7f {
				return nil, ErrControlCharacter
			}
			out = append(out, decoded)
			i += 3
			continue
		}
		if b < 0x20 || b == 0x7f {
			return nil, ErrControlCharacter
		}
		if b >= 0x80 {
			return nil, ErrInvalidURICharacter
		}
		out = append(out, b)
		i++
	}
	return out, nil
}

func hexValue(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	default:
		return 0, false
	}
}

func parseURIAlgorithm(value []byte) (Algorithm, error) {
	text := string(value)
	switch {
	case asciiEqualFold(text, string(SHA1)):
		return SHA1, nil
	case asciiEqualFold(text, string(SHA256)):
		return SHA256, nil
	case asciiEqualFold(text, string(SHA512)):
		return SHA512, nil
	default:
		return "", ErrInvalidAlgorithm
	}
}

func parseURIDigits(value []byte) (int, error) {
	switch string(value) {
	case "6":
		return 6, nil
	case "8":
		return 8, nil
	default:
		return 0, ErrInvalidDigits
	}
}

// parseDecimal accepts only a canonical unsigned decimal: no sign, no leading
// zero and no overflow.
func parseDecimal(value []byte, errValue error) (uint64, error) {
	if len(value) == 0 || (len(value) > 1 && value[0] == '0') {
		return 0, errValue
	}
	var parsed uint64
	for _, b := range value {
		if b < '0' || b > '9' {
			return 0, errValue
		}
		digit := uint64(b - '0')
		if parsed > (^uint64(0)-digit)/10 {
			return 0, errValue
		}
		parsed = parsed*10 + digit
	}
	return parsed, nil
}

// decodeBase32 decodes RFC 4648 Base32, accepting lowercase input and either
// no padding or the exactly canonical amount of padding. Non-zero trailing
// bits are rejected so that one secret has exactly one accepted encoding.
func decodeBase32(input []byte) ([]byte, error) {
	dataLen := len(input)
	padding := 0
	for dataLen > 0 && input[dataLen-1] == '=' {
		dataLen--
		padding++
	}
	if dataLen == 0 {
		return nil, ErrInvalidSecret
	}
	data := input[:dataLen]
	remainder := len(data) % 8

	if padding == 0 {
		switch remainder {
		case 0, 2, 4, 5, 7:
		default:
			return nil, ErrInvalidSecret
		}
	} else {
		if padding > 6 || len(input)%8 != 0 {
			return nil, ErrInvalidSecret
		}
		var expected int
		switch remainder {
		case 0:
			expected = 0
		case 2:
			expected = 6
		case 4:
			expected = 4
		case 5:
			expected = 3
		case 7:
			expected = 1
		default:
			return nil, ErrInvalidSecret
		}
		if padding != expected {
			return nil, ErrInvalidSecret
		}
	}

	out := make([]byte, 0, len(data)*5/8)
	var buffer uint32
	var bits uint
	for _, b := range data {
		var value uint32
		switch {
		case b >= 'A' && b <= 'Z':
			value = uint32(b - 'A')
		case b >= 'a' && b <= 'z':
			value = uint32(b - 'a')
		case b >= '2' && b <= '7':
			value = uint32(b-'2') + 26
		default:
			return nil, ErrInvalidSecret
		}
		buffer = buffer<<5 | value
		bits += 5
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(buffer>>bits))
			buffer &= (1 << bits) - 1
		}
	}
	if bits > 0 && buffer != 0 {
		return nil, ErrInvalidSecret
	}
	return out, nil
}

func appendBase32(dst, src []byte) []byte {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	var buffer uint32
	var bits uint
	for _, b := range src {
		buffer = buffer<<8 | uint32(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			dst = append(dst, alphabet[(buffer>>bits)&31])
		}
		buffer &= (1 << bits) - 1
	}
	if bits > 0 {
		dst = append(dst, alphabet[(buffer<<(5-bits))&31])
	}
	return dst
}

func appendPercentEncoded(dst []byte, value string) []byte {
	const hex = "0123456789ABCDEF"
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' ||
			b == '-' || b == '.' || b == '_' || b == '~' {
			dst = append(dst, b)
			continue
		}
		dst = append(dst, '%', hex[b>>4], hex[b&0x0f])
	}
	return dst
}
