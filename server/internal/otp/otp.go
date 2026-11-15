// Package otp implements HOTP (RFC 4226) and TOTP (RFC 6238).
//
// The package is intentionally free of GUI, storage and network code. It does
// not log secrets, does not keep global state and does not implement replay
// protection: accepting a time-step exactly once is the verifier's
// responsibility (see SRV-005).
package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"
	"strconv"
)

// Algorithm is a supported HMAC hash algorithm.
type Algorithm string

const (
	SHA1   Algorithm = "SHA1"
	SHA256 Algorithm = "SHA256"
	SHA512 Algorithm = "SHA512"
)

// Limits. Inputs outside these bounds are rejected instead of being coerced.
const (
	MinSecretBytes = 1
	MaxSecretBytes = 1024

	MinPeriod = 1
	MaxPeriod = 86400

	// MaxSkewSteps bounds the TOTP acceptance window to +/- 2 steps.
	// Widening it increases the brute-force surface; larger windows need an
	// explicit policy decision and tests.
	MaxSkewSteps = 2

	// MaxHOTPLookAhead bounds counter look-ahead for HOTP validation.
	MaxHOTPLookAhead = 10
)

var (
	ErrInvalidSecret    = errors.New("otp: invalid secret length")
	ErrInvalidDigits    = errors.New("otp: digits must be 6 or 8")
	ErrInvalidAlgorithm = errors.New("otp: unsupported algorithm")
	ErrInvalidPeriod    = errors.New("otp: invalid period")
	ErrInvalidTime      = errors.New("otp: invalid unix time")
	ErrInvalidCode      = errors.New("otp: invalid code format")
	ErrInvalidSkew      = errors.New("otp: invalid skew window")
	ErrCounterOverflow  = errors.New("otp: counter overflow")
)

var pow10 = [9]uint32{1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000}

func (a Algorithm) newHash() (func() hash.Hash, error) {
	switch a {
	case SHA1:
		return sha1.New, nil
	case SHA256:
		return sha256.New, nil
	case SHA512:
		return sha512.New, nil
	default:
		return nil, ErrInvalidAlgorithm
	}
}

func validateSecret(secret []byte) error {
	if len(secret) < MinSecretBytes || len(secret) > MaxSecretBytes {
		return ErrInvalidSecret
	}
	return nil
}

func validateDigits(digits int) error {
	if digits != 6 && digits != 8 {
		return ErrInvalidDigits
	}
	return nil
}

func validatePeriod(period int) error {
	if period < MinPeriod || period > MaxPeriod {
		return ErrInvalidPeriod
	}
	return nil
}

func validateCodeFormat(code string, digits int) error {
	if len(code) != digits {
		return ErrInvalidCode
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return ErrInvalidCode
		}
	}
	return nil
}

// hotpValue returns the truncated numeric HOTP value for a counter.
func hotpValue(secret []byte, counter uint64, digits int, alg Algorithm) (uint32, error) {
	if err := validateSecret(secret); err != nil {
		return 0, err
	}
	if err := validateDigits(digits); err != nil {
		return 0, err
	}
	newHash, err := alg.newHash()
	if err != nil {
		return 0, err
	}

	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)

	mac := hmac.New(newHash, secret)
	_, _ = mac.Write(msg[:]) // hash.Hash never returns an error
	sum := mac.Sum(nil)

	// RFC 4226 §5.3 dynamic truncation. All supported hashes are longer than
	// offset+3, and the offset is at most 15.
	offset := int(sum[len(sum)-1] & 0x0f)
	value := uint32(sum[offset]&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])

	return value % pow10[digits], nil
}

func formatCode(value uint32, digits int) string {
	s := strconv.FormatUint(uint64(value), 10)
	for len(s) < digits {
		s = "0" + s
	}
	return s
}

// GenerateHOTP returns the HOTP code for secret and counter.
func GenerateHOTP(secret []byte, counter uint64, digits int, alg Algorithm) (string, error) {
	value, err := hotpValue(secret, counter, digits, alg)
	if err != nil {
		return "", err
	}
	return formatCode(value, digits), nil
}

// TimeStep converts a Unix timestamp to a TOTP time-step.
func TimeStep(unixTime int64, period int) (uint64, error) {
	if unixTime < 0 {
		return 0, ErrInvalidTime
	}
	if err := validatePeriod(period); err != nil {
		return 0, err
	}
	return uint64(unixTime / int64(period)), nil
}

// GenerateTOTPAtStep returns the TOTP code for an explicit time-step.
func GenerateTOTPAtStep(secret []byte, step uint64, digits int, alg Algorithm) (string, error) {
	return GenerateHOTP(secret, step, digits, alg)
}

// GenerateTOTP returns the TOTP code for a Unix timestamp and period.
func GenerateTOTP(secret []byte, unixTime int64, period, digits int, alg Algorithm) (string, error) {
	step, err := TimeStep(unixTime, period)
	if err != nil {
		return "", err
	}
	return GenerateTOTPAtStep(secret, step, digits, alg)
}

// ConstantTimeEqualCode compares two OTP codes in constant time for equal
// lengths. Length is not treated as secret.
func ConstantTimeEqualCode(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ValidateTOTP reports whether code matches the time-step derived from
// unixTime, allowing +/- skewSteps steps for clock drift. The caller must still
// prevent replay of an accepted time-step.
func ValidateTOTP(secret []byte, code string, unixTime int64, period, digits int, alg Algorithm, skewSteps int) (bool, error) {
	if skewSteps < 0 || skewSteps > MaxSkewSteps {
		return false, ErrInvalidSkew
	}
	if err := validateDigits(digits); err != nil {
		return false, err
	}
	if err := validateCodeFormat(code, digits); err != nil {
		return false, err
	}
	base, err := TimeStep(unixTime, period)
	if err != nil {
		return false, err
	}

	matched := false
	for delta := -skewSteps; delta <= skewSteps; delta++ {
		var candidate uint64
		if delta < 0 {
			back := uint64(-delta)
			if base < back {
				continue
			}
			candidate = base - back
		} else {
			// base is derived from a non-negative int64 and a positive
			// period, so adding a bounded delta cannot overflow uint64.
			candidate = base + uint64(delta)
		}

		expected, err := GenerateTOTPAtStep(secret, candidate, digits, alg)
		if err != nil {
			return false, err
		}
		// Compare every candidate instead of returning early, so the number
		// of comparisons does not depend on which step matched.
		if ConstantTimeEqualCode(code, expected) {
			matched = true
		}
	}
	return matched, nil
}

// ValidateHOTP reports whether code matches counter..counter+lookAhead. It
// returns the matched counter. Replay protection and atomic persistence of the
// accepted counter belong to the caller.
func ValidateHOTP(secret []byte, code string, counter uint64, digits int, alg Algorithm, lookAhead int) (uint64, bool, error) {
	if lookAhead < 0 || lookAhead > MaxHOTPLookAhead {
		return 0, false, ErrInvalidSkew
	}
	if err := validateDigits(digits); err != nil {
		return 0, false, err
	}
	if err := validateCodeFormat(code, digits); err != nil {
		return 0, false, err
	}
	if counter > ^uint64(0)-uint64(lookAhead) {
		return 0, false, ErrCounterOverflow
	}

	var matchedCounter uint64
	matched := false
	for offset := 0; offset <= lookAhead; offset++ {
		candidate := counter + uint64(offset)
		expected, err := GenerateHOTP(secret, candidate, digits, alg)
		if err != nil {
			return 0, false, err
		}
		if ConstantTimeEqualCode(code, expected) && !matched {
			matched = true
			matchedCounter = candidate
		}
	}
	return matchedCounter, matched, nil
}

// String implements fmt.Stringer without exposing key material.
func (a Algorithm) String() string { return string(a) }
