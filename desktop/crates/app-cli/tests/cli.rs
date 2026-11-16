//! End-to-end tests of the real `authenticator-cli` binary (VAULT-006):
//! headless vault checks without a GUI, distinct exit codes and no secret
//! output. Fixtures and passwords are synthetic test values.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

const FIXTURE_PASSWORD: &str = "correct horse battery staple";
const PW1: &str = "cli first passphrase";
const PW2: &str = "cli export passphrase";
const PW3: &str = "cli restored passphrase";
const FAST_KDF: [&str; 2] = ["--kdf", "19456,2,1"];

/// Values that must never appear in CLI output: fixture secret in raw,
/// hex and base32 form, and every password.
const FORBIDDEN: [&str; 7] = [
    "12345678901234567890",
    "3132333435363738393031323334353637383930",
    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
    FIXTURE_PASSWORD,
    PW1,
    PW2,
    PW3,
];

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .subsec_nanos();
        let path = std::env::temp_dir().join(format!(
            "authenticator-cli-test-{}-{}-{nanos}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("mkdir");
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/vault/v1")
        .join(name)
}

struct Output {
    code: i32,
    stdout: String,
    stderr: String,
}

fn cli(args: &[&dyn AsRef<std::ffi::OsStr>], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_authenticator-cli"))
        .args(args.iter().map(|arg| arg.as_ref()))
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cli");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    let output = child.wait_with_output().expect("wait");
    let result = Output {
        code: output.status.code().expect("exit code"),
        stdout: String::from_utf8(output.stdout).expect("utf8 stdout"),
        stderr: String::from_utf8(output.stderr).expect("utf8 stderr"),
    };
    for needle in FORBIDDEN {
        assert!(
            !result.stdout.contains(needle) && !result.stderr.contains(needle),
            "cli output leaked a secret or password"
        );
    }
    result
}

fn lines(passwords: &[&str]) -> String {
    passwords.iter().map(|p| format!("{p}\n")).collect()
}

fn assert_ok(output: &Output) {
    assert_eq!(output.code, 0, "stderr: {}", output.stderr);
}

#[test]
fn help_and_unknown_command() {
    assert_ok(&cli(&[&"help"], ""));
    assert_eq!(cli(&[&"frobnicate"], "").code, 2);
    assert_eq!(cli(&[], "").code, 2);
}

#[test]
fn create_info_verify_list_without_gui() {
    let dir = TempDir::new();
    let vault = dir.path("cli.avault");
    let create = cli(
        &[
            &"create",
            &vault,
            &"--password-stdin",
            &FAST_KDF[0],
            &FAST_KDF[1],
        ],
        &lines(&[PW1]),
    );
    assert_ok(&create);

    let info = cli(&[&"info", &vault], "");
    assert_ok(&info);
    assert!(info.stdout.contains("kdf: argon2id-v19 m=19456KiB t=2 p=1"));
    assert!(info.stdout.contains("authenticated: no"));
    let sha_line = info
        .stdout
        .lines()
        .find(|line| line.starts_with("sha256: "))
        .expect("sha line");
    assert_eq!(sha_line.len(), "sha256: ".len() + 64);

    let verify = cli(&[&"verify", &vault, &"--password-stdin"], &lines(&[PW1]));
    assert_ok(&verify);
    assert_eq!(verify.stdout.trim(), "ok: authenticated, 0 records");

    let list = cli(&[&"list", &vault, &"--password-stdin"], &lines(&[PW1]));
    assert_ok(&list);
    assert_eq!(list.stdout.trim(), "records: 0");

    // create never overwrites.
    let again = cli(
        &[
            &"create",
            &vault,
            &"--password-stdin",
            &FAST_KDF[0],
            &FAST_KDF[1],
        ],
        &lines(&[PW1]),
    );
    assert_eq!(again.code, 20);
}

#[test]
fn list_hides_labels_by_default_and_never_prints_secrets() {
    let dir = TempDir::new();
    let vault = dir.path("totp.avault");
    fs::copy(fixture("totp-sha1.avault"), &vault).expect("copy fixture");

    let list = cli(
        &[&"list", &vault, &"--password-stdin"],
        &lines(&[FIXTURE_PASSWORD]),
    );
    assert_ok(&list);
    assert!(list
        .stdout
        .contains("0\ttotp\tSHA1\t6\tperiod=30\tissuer_bytes=7"));
    assert!(!list.stdout.contains("alice@example.test"));
    assert!(!list.stdout.contains("Example"));

    let labelled = cli(
        &[&"list", &vault, &"--password-stdin", &"--show-labels"],
        &lines(&[FIXTURE_PASSWORD]),
    );
    assert_ok(&labelled);
    assert!(labelled.stdout.contains("account=\"alice@example.test\""));

    let hotp = dir.path("hotp.avault");
    fs::copy(fixture("hotp.avault"), &hotp).expect("copy fixture");
    let list = cli(
        &[&"list", &hotp, &"--password-stdin"],
        &lines(&[FIXTURE_PASSWORD]),
    );
    assert!(list.stdout.contains("hotp\tSHA1\t6\tcounter=42"));
}

#[test]
fn every_fixture_verifies_headless() {
    for (name, count) in [
        ("empty.avault", 0),
        ("totp-sha1.avault", 1),
        ("totp-sha256.avault", 1),
        ("totp-sha512.avault", 1),
        ("hotp.avault", 1),
        ("mixed-boundaries.avault", 3),
    ] {
        let verify = cli(
            &[&"verify", &fixture(name), &"--password-stdin"],
            &lines(&[FIXTURE_PASSWORD]),
        );
        assert_ok(&verify);
        assert_eq!(
            verify.stdout.trim(),
            format!("ok: authenticated, {count} records"),
            "{name}"
        );
    }
}

#[test]
fn error_classes_have_distinct_exit_codes() {
    let dir = TempDir::new();
    let vault = dir.path("v.avault");
    fs::copy(fixture("totp-sha1.avault"), &vault).expect("copy");
    let bytes = fs::read(&vault).expect("read");

    let verify = |path: &Path, password: &str| {
        cli(
            &[&"verify", &path, &"--password-stdin"],
            &lines(&[password]),
        )
    };
    assert_eq!(
        verify(&dir.path("missing.avault"), FIXTURE_PASSWORD).code,
        10
    );
    assert_eq!(verify(&dir.0, FIXTURE_PASSWORD).code, 11, "directory");

    let wrong = verify(&vault, "not the fixture password");
    assert_eq!(wrong.code, 15);
    assert!(wrong.stderr.contains("authentication failed"));

    let corrupt = dir.path("corrupt.avault");
    fs::write(&corrupt, &bytes[..bytes.len() - 1]).expect("write");
    assert_eq!(verify(&corrupt, FIXTURE_PASSWORD).code, 13);
    assert_eq!(cli(&[&"info", &corrupt], "").code, 13);

    let future = dir.path("future.avault");
    let mut changed = bytes.clone();
    changed[4..6].copy_from_slice(&2_u16.to_be_bytes());
    fs::write(&future, &changed).expect("write");
    assert_eq!(verify(&future, FIXTURE_PASSWORD).code, 14);

    let huge = dir.path("huge.avault");
    fs::File::create(&huge)
        .expect("create")
        .set_len(vault::MAX_FILE_BYTES as u64 + 1)
        .expect("sparse");
    assert_eq!(cli(&[&"info", &huge], "").code, 16);

    // Busy: a session in this process holds the lock; list needs it.
    let session = vault::VaultFile::open(&vault, FIXTURE_PASSWORD.as_bytes()).expect("open");
    let busy = cli(
        &[&"list", &vault, &"--password-stdin"],
        &lines(&[FIXTURE_PASSWORD]),
    );
    assert_eq!(busy.code, 12);
    drop(session);

    // Missing password input and missing flag are usage errors.
    assert_eq!(cli(&[&"verify", &vault, &"--password-stdin"], "").code, 2);
    assert_eq!(cli(&[&"verify", &vault], "").code, 2);
}

#[test]
fn passwords_are_bytes_without_trimming() {
    let dir = TempDir::new();
    let vault = dir.path("space.avault");
    let spaced = "trailing space pw ";
    assert_ok(&cli(
        &[
            &"create",
            &vault,
            &"--password-stdin",
            &FAST_KDF[0],
            &FAST_KDF[1],
        ],
        &lines(&[spaced]),
    ));
    let trimmed = cli(
        &[&"verify", &vault, &"--password-stdin"],
        &lines(&["trailing space pw"]),
    );
    assert_eq!(trimmed.code, 15, "a trimmed password must not match");
    assert_ok(&cli(
        &[&"verify", &vault, &"--password-stdin"],
        &format!("{spaced}\r\n"),
    ));
}

#[test]
fn backup_workflow_export_copy_restore_import() {
    let dir = TempDir::new();
    let source = dir.path("source.avault");
    fs::copy(fixture("mixed-boundaries.avault"), &source).expect("copy fixture");
    let original = fs::read(&source).expect("read");

    // export re-encrypts under a new password.
    let export = dir.path("export.avault");
    let out = cli(
        &[
            &"export",
            &source,
            &export,
            &"--password-stdin",
            &FAST_KDF[0],
            &FAST_KDF[1],
        ],
        &lines(&[FIXTURE_PASSWORD, PW2]),
    );
    assert_ok(&out);
    assert!(out.stdout.contains("exported 3 records"));
    let verify_export = |password: &str| {
        cli(
            &[&"verify", &export, &"--password-stdin"],
            &lines(&[password]),
        )
        .code
    };
    assert_eq!(verify_export(PW2), 0);
    assert_eq!(verify_export(FIXTURE_PASSWORD), 15);

    // copy is byte-identical and never overwrites.
    let copy = dir.path("copy.avault");
    assert_ok(&cli(
        &[&"copy", &source, &copy, &"--password-stdin"],
        &lines(&[FIXTURE_PASSWORD]),
    ));
    assert_eq!(fs::read(&copy).expect("copy"), original);
    assert_eq!(
        cli(
            &[&"copy", &source, &copy, &"--password-stdin"],
            &lines(&[FIXTURE_PASSWORD])
        )
        .code,
        20
    );

    // restore into a missing target needs explicit --replace-damaged.
    let target = dir.path("restored.avault");
    let restore = |extra: &[&dyn AsRef<std::ffi::OsStr>]| {
        let mut args: Vec<&dyn AsRef<std::ffi::OsStr>> = vec![
            &"restore",
            &target,
            &export,
            &"--password-stdin",
            &FAST_KDF[0],
            &FAST_KDF[1],
        ];
        args.extend_from_slice(extra);
        cli(&args, &lines(&[PW2, PW3]))
    };
    assert_eq!(restore(&[]).code, 10);
    assert!(!target.exists(), "no implicit vault creation");
    let restored = restore(&[&"--replace-damaged"]);
    assert_ok(&restored);
    assert!(restored.stdout.contains("restored 3 records"));
    assert_ok(&cli(
        &[&"verify", &target, &"--password-stdin"],
        &lines(&[PW3]),
    ));

    // import replaces all records of an existing vault.
    let other = dir.path("other.avault");
    assert_ok(&cli(
        &[
            &"create",
            &other,
            &"--password-stdin",
            &FAST_KDF[0],
            &FAST_KDF[1],
        ],
        &lines(&[PW1]),
    ));
    let import = cli(
        &[&"import", &other, &source, &"--password-stdin"],
        &lines(&[PW1, FIXTURE_PASSWORD]),
    );
    assert_ok(&import);
    assert!(import.stdout.contains("3 imported records"));
    assert_eq!(
        cli(&[&"verify", &other, &"--password-stdin"], &lines(&[PW1]))
            .stdout
            .trim(),
        "ok: authenticated, 3 records"
    );

    // The source fixture copy is never modified.
    assert_eq!(fs::read(&source).expect("read"), original);
}
