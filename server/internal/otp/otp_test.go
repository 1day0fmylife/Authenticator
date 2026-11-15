package otp_test

import (
	"math"
	"strings"
	"testing"

	"github.com/1day0fmylife/Authenticator/server/internal/otp"
)

func testSecret() []byte { return []byte("12345678901234567890") }

func TestTOTPStepBoundaries(t *testing.T) {
	secret := testSecret()
	// RFC 6238 value for t=59 (step 1), 6 digits.
	const codeAtStep1 = "287082"
	codePeriod60, err := otp.GenerateTOTP(secret, 60, 60, 6, otp.SHA1)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		code   string
		unix   int64
		period int
		skew   int
		want   bool
	}{
		{"exact", codeAtStep1, 59, 30, 0, true},
		{"start-of-step", codeAtStep1, 30, 30, 0, true},
		{"end-of-step", codeAtStep1, 59, 30, 0, true},
		{"next-step-no-skew", codeAtStep1, 60, 30, 0, false},
		{"next-step-skew1", codeAtStep1, 60, 30, 1, true},
		{"previous-step-skew1", codeAtStep1, 29, 30, 1, true},
		{"previous-step-no-skew", codeAtStep1, 29, 30, 0, false},
		{"two-steps-ahead-skew1", codeAtStep1, 90, 30, 1, false},
		{"two-steps-ahead-skew2", codeAtStep1, 90, 30, 2, true},
		{"three-steps-ahead-skew2", codeAtStep1, 120, 30, 2, false},
		{"period-60-step", codePeriod60, 60, 60, 0, true},
		{"period-60-wrong-step", codePeriod60, 59, 60, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := otp.ValidateTOTP(secret, tc.code, tc.unix, tc.period, 6, otp.SHA1, tc.skew)
			if err != nil {
				t.Fatalf("ValidateTOTP: %v", err)
			}
			if got != tc.want {
				t.Fatalf("ValidateTOTP = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTOTPRejectsInvalidInput(t *testing.T) {
	secret := testSecret()
	valid := "287082"

	cases := []struct {
		name   string
		secret []byte
		code   string
		unix   int64
		period int
		digits int
		alg    otp.Algorithm
		skew   int
		want   error
	}{
		{"empty-secret", nil, valid, 59, 30, 6, otp.SHA1, 0, otp.ErrInvalidSecret},
		{"short-code", secret, "28708", 59, 30, 6, otp.SHA1, 0, otp.ErrInvalidCode},
		{"non-digit-code", secret, "28708a", 59, 30, 6, otp.SHA1, 0, otp.ErrInvalidCode},
		{"negative-time", secret, valid, -1, 30, 6, otp.SHA1, 0, otp.ErrInvalidTime},
		{"zero-period", secret, valid, 59, 0, 6, otp.SHA1, 0, otp.ErrInvalidPeriod},
		{"huge-period", secret, valid, 59, otp.MaxPeriod + 1, 6, otp.SHA1, 0, otp.ErrInvalidPeriod},
		{"negative-skew", secret, valid, 59, 30, 6, otp.SHA1, -1, otp.ErrInvalidSkew},
		{"skew-too-wide", secret, valid, 59, 30, 6, otp.SHA1, otp.MaxSkewSteps + 1, otp.ErrInvalidSkew},
		{"bad-digits", secret, valid, 59, 30, 7, otp.SHA1, 0, otp.ErrInvalidDigits},
		{"bad-algorithm", secret, valid, 59, 30, 6, "MD5", 0, otp.ErrInvalidAlgorithm},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := otp.ValidateTOTP(tc.secret, tc.code, tc.unix, tc.period, tc.digits, tc.alg, tc.skew)
			if err != tc.want {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if err != nil && strings.Contains(err.Error(), string(testSecret())) {
				t.Fatal("error message leaks the secret")
			}
		})
	}
}

func TestHOTPLookAhead(t *testing.T) {
	secret := testSecret()
	code, err := otp.GenerateHOTP(secret, 5, 6, otp.SHA1)
	if err != nil {
		t.Fatal(err)
	}

	counter, ok, err := otp.ValidateHOTP(secret, code, 0, 6, otp.SHA1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || counter != 5 {
		t.Fatalf("ValidateHOTP = (%d, %v), want (5, true)", counter, ok)
	}

	if _, ok, err := otp.ValidateHOTP(secret, "000000", 0, 6, otp.SHA1, 10); err != nil || ok {
		t.Fatalf("wrong code accepted: ok=%v err=%v", ok, err)
	}
}

func TestHOTPCounterOverflow(t *testing.T) {
	secret := testSecret()
	if _, err := otp.GenerateHOTP(secret, math.MaxUint64, 6, otp.SHA1); err != nil {
		t.Fatalf("MaxUint64 counter must be supported: %v", err)
	}
	if _, _, err := otp.ValidateHOTP(secret, "000000", math.MaxUint64, 6, otp.SHA1, 1); err != otp.ErrCounterOverflow {
		t.Fatalf("overflow err = %v, want %v", err, otp.ErrCounterOverflow)
	}
	if _, _, err := otp.ValidateHOTP(secret, "000000", math.MaxUint64, 6, otp.SHA1, otp.MaxHOTPLookAhead+1); err != otp.ErrInvalidSkew {
		t.Fatalf("look-ahead bound err = %v, want %v", err, otp.ErrInvalidSkew)
	}
}

func TestSecretLimits(t *testing.T) {
	if _, err := otp.GenerateHOTP(nil, 0, 6, otp.SHA1); err != otp.ErrInvalidSecret {
		t.Fatalf("nil secret err = %v", err)
	}
	if _, err := otp.GenerateHOTP(make([]byte, otp.MaxSecretBytes), 0, 6, otp.SHA1); err != nil {
		t.Fatalf("max secret rejected: %v", err)
	}
	if _, err := otp.GenerateHOTP(make([]byte, otp.MaxSecretBytes+1), 0, 6, otp.SHA1); err != otp.ErrInvalidSecret {
		t.Fatalf("oversized secret err = %v", err)
	}
}

func TestConstantTimeEqualCode(t *testing.T) {
	if !otp.ConstantTimeEqualCode("123456", "123456") {
		t.Fatal("equal codes reported different")
	}
	if otp.ConstantTimeEqualCode("123456", "123457") {
		t.Fatal("different codes reported equal")
	}
	if otp.ConstantTimeEqualCode("123456", "1234567") {
		t.Fatal("different lengths reported equal")
	}
}

func TestTimeStep(t *testing.T) {
	cases := []struct {
		unix   int64
		period int
		want   uint64
	}{
		{0, 30, 0},
		{29, 30, 0},
		{30, 30, 1},
		{59, 30, 1},
		{60, 30, 2},
		{math.MaxInt64, 30, uint64(math.MaxInt64 / 30)},
		{0, 60, 0},
		{3600, 60, 60},
	}
	for _, tc := range cases {
		got, err := otp.TimeStep(tc.unix, tc.period)
		if err != nil {
			t.Fatalf("TimeStep(%d, %d): %v", tc.unix, tc.period, err)
		}
		if got != tc.want {
			t.Fatalf("TimeStep(%d, %d) = %d, want %d", tc.unix, tc.period, got, tc.want)
		}
	}
}
