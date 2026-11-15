//! Deterministic property/invariant tests without external proptest crates.
//!
//! A fixed-seed xorshift generator samples secrets, counters, timestamps,
//! algorithms and digit counts. Failures are reproducible from the seed.

use otp_core::{
    generate_hotp, generate_totp, generate_totp_at_step, validate_hotp, validate_totp, Algorithm,
    Digits, MAX_PERIOD_SECONDS, MAX_SKEW_STEPS,
};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            0
        } else {
            self.next() % bound
        }
    }

    fn secret(&mut self) -> Vec<u8> {
        let length = 1 + self.below(64) as usize;
        (0..length).map(|_| self.next() as u8).collect()
    }

    fn algorithm(&mut self) -> Algorithm {
        match self.below(3) {
            0 => Algorithm::Sha1,
            1 => Algorithm::Sha256,
            _ => Algorithm::Sha512,
        }
    }

    fn digits(&mut self) -> Digits {
        if self.below(2) == 0 {
            Digits::Six
        } else {
            Digits::Eight
        }
    }
}

fn flipped(code: &str) -> String {
    let mut bytes = code.as_bytes().to_vec();
    let last = bytes.len() - 1;
    bytes[last] = if bytes[last] == b'9' {
        b'0'
    } else {
        bytes[last] + 1
    };
    String::from_utf8(bytes).expect("ascii digits")
}

#[test]
fn property_hotp_is_deterministic_and_well_formed() {
    let mut rng = Rng(0x5eed_1234_abcd_9876);

    for iteration in 0..500 {
        let secret = rng.secret();
        let algorithm = rng.algorithm();
        let digits = rng.digits();
        let counter = rng.next();

        let code = generate_hotp(&secret, counter, digits, algorithm)
            .unwrap_or_else(|error| panic!("iteration {iteration}: {error}"));

        assert_eq!(code.len(), digits.as_usize(), "iteration {iteration}");
        assert!(
            code.bytes().all(|byte| byte.is_ascii_digit()),
            "iteration {iteration}"
        );
        assert_eq!(
            code,
            generate_hotp(&secret, counter, digits, algorithm).expect("stable"),
            "iteration {iteration}"
        );
        assert_eq!(
            validate_hotp(&secret, &code, counter, digits, algorithm, 0).expect("validate"),
            Some(counter),
            "iteration {iteration}"
        );

        let wrong = flipped(&code);
        if wrong != code {
            assert!(
                validate_hotp(&secret, &wrong, counter, digits, algorithm, 0)
                    .expect("validate wrong")
                    .is_none(),
                "iteration {iteration}"
            );
        }
    }
}

#[test]
fn property_totp_matches_hotp_at_the_same_step() {
    let mut rng = Rng(0x0ddc_0ffe_e15e_beef);

    for iteration in 0..300 {
        let secret = rng.secret();
        let algorithm = rng.algorithm();
        let digits = rng.digits();
        let counter = rng.below(1_000_000_000);
        let periods = [1_u32, 30, 60, 3600, MAX_PERIOD_SECONDS];
        let period = periods[rng.below(periods.len() as u64) as usize];
        let offset = rng.below(u64::from(period));
        let unix_time = i64::try_from(counter * u64::from(period) + offset).expect("bounded");

        let hotp = generate_hotp(&secret, counter, digits, algorithm).expect("hotp");
        let totp = generate_totp(&secret, unix_time, period, digits, algorithm).expect("totp");
        assert_eq!(hotp, totp, "iteration {iteration}");

        assert!(
            validate_totp(&secret, &totp, unix_time, period, digits, algorithm, 0)
                .expect("validate"),
            "iteration {iteration}"
        );

        // A code from `skew` steps away is accepted when the window allows it.
        let far_time = i64::try_from(counter * u64::from(period) + offset + u64::from(period))
            .expect("bounded");
        let far_code =
            generate_totp_at_step(&secret, counter + 1, digits, algorithm).expect("step code");
        assert!(
            validate_totp(
                &secret,
                &far_code,
                far_time,
                period,
                digits,
                algorithm,
                MAX_SKEW_STEPS
            )
            .expect("validate far"),
            "iteration {iteration}"
        );
    }
}

#[test]
fn property_generated_codes_round_trip_across_algorithms() {
    let mut rng = Rng(0x1234_5678_9abc_def0);
    let algorithms = [Algorithm::Sha1, Algorithm::Sha256, Algorithm::Sha512];
    let digit_sets = [Digits::Six, Digits::Eight];

    for algorithm in algorithms {
        for digits in digit_sets {
            for _ in 0..50 {
                let secret = rng.secret();
                let counter = rng.next();
                let code = generate_hotp(&secret, counter, digits, algorithm).expect("hotp");
                assert_eq!(code.len(), digits.as_usize());
                assert_eq!(
                    generate_hotp(&secret, counter, digits, algorithm).expect("hotp again"),
                    code
                );
            }
        }
    }
}
