//! Headless offline CLI for the Authenticator vault (VAULT-006).
//!
//! Purpose: integration tests and diagnostics without the GUI. It has no
//! network code, no logging and no telemetry, and forbids `unsafe`.
//!
//! Secret handling:
//!
//! - passwords are read **only** from stdin and only with an explicit
//!   `--password-stdin`; one password per line, only the trailing `\n` or
//!   `\r\n` is removed (no trimming or Unicode normalization, ADR-003);
//!   passwords are never accepted from argv or environment variables;
//! - if stdin is a terminal the CLI refuses, because it cannot disable echo
//!   without extra dependencies; pipe the password instead;
//! - OTP secrets and codes are never printed; issuer/account labels only
//!   with `--show-labels`; argument values are never echoed in errors.

#![forbid(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::io::{BufRead, Read, Write};
use std::path::PathBuf;

use vault::{
    inspect_file, verify_file, KdfParams, OtpType, RestoreMode, VaultError, VaultFile,
    MAX_PASSWORD_BYTES,
};
use zeroize::Zeroizing;

/// Exit code for success.
pub const EXIT_OK: u8 = 0;
/// Exit code for an unclassified failure (e.g. writing to stdout failed).
pub const EXIT_FAILURE: u8 = 1;
/// Exit code for invalid command-line usage.
pub const EXIT_USAGE: u8 = 2;

/// Stable exit code per vault error class, so scripts can tell them apart.
pub fn exit_code(error: &VaultError) -> u8 {
    match error {
        VaultError::NotFound => 10,
        VaultError::Unavailable(_) => 11,
        VaultError::Busy => 12,
        VaultError::Corrupt(_) => 13,
        VaultError::Unsupported(_) => 14,
        VaultError::AuthenticationFailed => 15,
        VaultError::ResourceLimit(_) => 16,
        VaultError::Conflict => 17,
        VaultError::Io(_) => 18,
        VaultError::DurabilityUncertain => 19,
        VaultError::AlreadyExists => 20,
        VaultError::InvalidInput(_) => 21,
        VaultError::UnknownRecord => 22,
        VaultError::Crypto | VaultError::Random => 23,
    }
}

const USAGE: &str = "\
usage: authenticator-cli <command> [arguments]

commands (passwords: one per line on stdin, requires --password-stdin):
  info    <vault>                         header metadata, no password, not authenticated
  verify  <vault> --password-stdin        authenticate and count records
  list    <vault> --password-stdin [--show-labels]
                                          record metadata; secrets are never printed
  create  <vault> --password-stdin [--kdf M,T,P]
                                          new empty vault (password: 12..1024 bytes)
  export  <vault> <dest> --password-stdin [--kdf M,T,P]
                                          stdin: vault password, export password
  copy    <vault> <dest> --password-stdin byte-identical backup copy
  import  <vault> <source> --password-stdin
                                          replace all records; stdin: vault, source password
  restore <target> <backup> --password-stdin [--replace-damaged] [--kdf M,T,P]
                                          stdin: backup password, new target password
  help                                    this text

exit codes: 0 ok, 2 usage, 10 not found, 11 unavailable, 12 busy, 13 corrupt,
  14 unsupported, 15 authentication failed, 16 resource limit, 17 conflict,
  18 i/o, 19 durability uncertain, 20 already exists, 21 invalid input, 23 internal
";

/// Parsed command line. Holds paths and flags only, never passwords.
struct Args {
    command: String,
    paths: Vec<PathBuf>,
    password_stdin: bool,
    show_labels: bool,
    replace_damaged: bool,
    kdf: Option<KdfParams>,
}

enum Failure {
    Usage(&'static str),
    Vault(VaultError),
    Output,
}

impl From<VaultError> for Failure {
    fn from(error: VaultError) -> Self {
        Self::Vault(error)
    }
}

impl From<std::io::Error> for Failure {
    fn from(_: std::io::Error) -> Self {
        Self::Output
    }
}

fn parse_kdf(value: &OsStr) -> Result<KdfParams, Failure> {
    let text = value
        .to_str()
        .ok_or(Failure::Usage("invalid --kdf value"))?;
    let parts: Vec<&str> = text.split(',').collect();
    let [m, t, p] = parts[..] else {
        return Err(Failure::Usage("--kdf expects M,T,P"));
    };
    let parse = |part: &str| {
        part.parse::<u32>()
            .map_err(|_| Failure::Usage("--kdf expects M,T,P"))
    };
    Ok(KdfParams::new(parse(m)?, parse(t)?, parse(p)?)?)
}

fn parse_args(raw: &[OsString]) -> Result<Args, Failure> {
    let mut iter = raw.iter();
    let command = iter
        .next()
        .and_then(|value| value.to_str())
        .ok_or(Failure::Usage("missing command"))?
        .to_owned();
    let mut args = Args {
        command,
        paths: Vec::new(),
        password_stdin: false,
        show_labels: false,
        replace_damaged: false,
        kdf: None,
    };
    while let Some(value) = iter.next() {
        match value.to_str() {
            Some("--password-stdin") => args.password_stdin = true,
            Some("--show-labels") => args.show_labels = true,
            Some("--replace-damaged") => args.replace_damaged = true,
            Some("--kdf") => {
                let value = iter.next().ok_or(Failure::Usage("--kdf expects M,T,P"))?;
                args.kdf = Some(parse_kdf(value)?);
            }
            // Do not echo the value: it may be a mistyped password.
            Some(flag) if flag.starts_with("--") => return Err(Failure::Usage("unknown option")),
            _ => args.paths.push(PathBuf::from(value)),
        }
    }
    Ok(args)
}

/// Reads one password line from stdin into a zeroizing buffer.
fn read_password(stdin: &mut dyn BufRead) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let mut line = Zeroizing::new(Vec::with_capacity(MAX_PASSWORD_BYTES + 2));
    // Bounded read: a password longer than the limit is rejected by the
    // vault, not buffered without limit.
    let read = stdin
        .take(MAX_PASSWORD_BYTES as u64 + 2)
        .read_until(b'\n', &mut line)
        .map_err(|_| Failure::Usage("cannot read password from stdin"))?;
    if read == 0 {
        return Err(Failure::Usage("missing password on stdin"));
    }
    if line.last() == Some(&b'\n') {
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
    } else if line.len() > MAX_PASSWORD_BYTES {
        return Err(Failure::Vault(VaultError::InvalidInput("password length")));
    }
    Ok(line)
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

struct Context<'a> {
    args: Args,
    stdin: &'a mut dyn BufRead,
    stdin_is_terminal: bool,
    out: &'a mut dyn Write,
}

impl Context<'_> {
    fn paths<const N: usize>(&self) -> Result<[PathBuf; N], Failure> {
        <[PathBuf; N]>::try_from(self.args.paths.clone())
            .map_err(|_| Failure::Usage("wrong number of arguments"))
    }

    fn password(&mut self) -> Result<Zeroizing<Vec<u8>>, Failure> {
        if !self.args.password_stdin {
            return Err(Failure::Usage("this command needs --password-stdin"));
        }
        if self.stdin_is_terminal {
            return Err(Failure::Usage(
                "refusing to read a password from a terminal (input would be echoed); pipe it",
            ));
        }
        read_password(self.stdin)
    }

    fn kdf(&self) -> KdfParams {
        self.args.kdf.unwrap_or_default()
    }

    fn require_no_password(&self) -> Result<(), Failure> {
        if self.args.password_stdin {
            return Err(Failure::Usage("this command does not take a password"));
        }
        Ok(())
    }

    fn run(&mut self) -> Result<(), Failure> {
        match self.args.command.as_str() {
            "help" | "--help" | "-h" => {
                self.out.write_all(USAGE.as_bytes())?;
                Ok(())
            }
            "info" => self.info(),
            "verify" => self.verify(),
            "list" => self.list(),
            "create" => self.create(),
            "export" => self.export(),
            "copy" => self.copy(),
            "import" => self.import(),
            "restore" => self.restore(),
            _ => Err(Failure::Usage("unknown command")),
        }
    }

    fn info(&mut self) -> Result<(), Failure> {
        self.require_no_password()?;
        let [path] = self.paths()?;
        let info = inspect_file(&path)?;
        writeln!(
            self.out,
            "format: vault v1 (envelope {})",
            info.envelope_version
        )?;
        writeln!(
            self.out,
            "kdf: argon2id-v19 m={}KiB t={} p={}",
            info.kdf.m_cost_kib(),
            info.kdf.t_cost(),
            info.kdf.p_cost()
        )?;
        writeln!(self.out, "file_bytes: {}", info.file_len)?;
        writeln!(self.out, "ciphertext_bytes: {}", info.ciphertext_len)?;
        writeln!(self.out, "sha256: {}", hex(&info.sha256))?;
        writeln!(self.out, "authenticated: no (structure only; use verify)")?;
        Ok(())
    }

    fn verify(&mut self) -> Result<(), Failure> {
        let [path] = self.paths()?;
        let password = self.password()?;
        let count = verify_file(&path, &password)?;
        writeln!(self.out, "ok: authenticated, {count} records")?;
        Ok(())
    }

    fn list(&mut self) -> Result<(), Failure> {
        let [path] = self.paths()?;
        let password = self.password()?;
        let file = VaultFile::open(&path, &password)?;
        writeln!(self.out, "records: {}", file.vault().len())?;
        for (index, (_, record)) in file.vault().records().enumerate() {
            let (kind, moving) = match record.otp_type() {
                OtpType::Totp => ("totp", format!("period={}", record.period())),
                OtpType::Hotp => ("hotp", format!("counter={}", record.counter())),
            };
            let labels = if self.args.show_labels {
                format!(
                    "issuer={:?}\taccount={:?}",
                    record.issuer(),
                    record.account()
                )
            } else {
                format!(
                    "issuer_bytes={}\taccount_bytes={}",
                    record.issuer().len(),
                    record.account().len()
                )
            };
            writeln!(
                self.out,
                "{index}\t{kind}\t{}\t{}\t{moving}\t{labels}",
                record.algorithm().as_str(),
                record.digits().as_u32()
            )?;
        }
        Ok(())
    }

    fn create(&mut self) -> Result<(), Failure> {
        let [path] = self.paths()?;
        let password = self.password()?;
        VaultFile::create(&path, &password, self.kdf())?.close();
        writeln!(self.out, "ok: created empty vault")?;
        Ok(())
    }

    fn export(&mut self) -> Result<(), Failure> {
        let [path, dest] = self.paths()?;
        let password = self.password()?;
        let export_password = self.password()?;
        let file = VaultFile::open(&path, &password)?;
        file.export_to(&dest, &export_password, self.kdf())?;
        writeln!(
            self.out,
            "ok: exported {} records (verified)",
            file.vault().len()
        )?;
        Ok(())
    }

    fn copy(&mut self) -> Result<(), Failure> {
        let [path, dest] = self.paths()?;
        let password = self.password()?;
        let file = VaultFile::open(&path, &password)?;
        file.copy_to(&dest)?;
        writeln!(self.out, "ok: byte-identical copy written (verified)")?;
        Ok(())
    }

    fn import(&mut self) -> Result<(), Failure> {
        let [path, source] = self.paths()?;
        let password = self.password()?;
        let source_password = self.password()?;
        let mut file = VaultFile::open(&path, &password)?;
        let count = file.import_replace(&source, &source_password)?;
        writeln!(
            self.out,
            "ok: replaced records with {count} imported records"
        )?;
        Ok(())
    }

    fn restore(&mut self) -> Result<(), Failure> {
        let [target, backup] = self.paths()?;
        let backup_password = self.password()?;
        let new_password = self.password()?;
        let mode = if self.args.replace_damaged {
            RestoreMode::ReplaceDamagedTarget
        } else {
            RestoreMode::RequireIntactTarget
        };
        let file = VaultFile::restore(
            &target,
            &backup,
            &backup_password,
            &new_password,
            self.kdf(),
            mode,
        )?;
        writeln!(self.out, "ok: restored {} records", file.vault().len())?;
        Ok(())
    }
}

/// Runs the CLI. Separated from `main` so tests can drive it in-process.
pub fn run(
    raw_args: &[OsString],
    stdin: &mut dyn BufRead,
    stdin_is_terminal: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let result = parse_args(raw_args).and_then(|args| {
        Context {
            args,
            stdin,
            stdin_is_terminal,
            out,
        }
        .run()
    });
    match result {
        Ok(()) => EXIT_OK,
        Err(Failure::Usage(message)) => {
            let _ = writeln!(err, "error: {message}\n\n{USAGE}");
            EXIT_USAGE
        }
        Err(Failure::Vault(error)) => {
            let _ = writeln!(err, "error: {error}");
            exit_code(&error)
        }
        Err(Failure::Output) => {
            let _ = writeln!(err, "error: cannot write output");
            EXIT_FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    fn run_with(args: &[&str], stdin: &[u8], terminal: bool) -> (u8, String, String) {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            &os(args),
            &mut Cursor::new(stdin.to_vec()),
            terminal,
            &mut out,
            &mut err,
        );
        (
            code,
            String::from_utf8(out).expect("utf8"),
            String::from_utf8(err).expect("utf8"),
        )
    }

    #[test]
    fn password_line_strips_only_the_line_ending() {
        let read =
            |input: &[u8]| read_password(&mut Cursor::new(input.to_vec())).map(|p| p.to_vec());
        assert_eq!(read(b"secret pass\n").ok(), Some(b"secret pass".to_vec()));
        assert_eq!(read(b"secret pass\r\n").ok(), Some(b"secret pass".to_vec()));
        assert_eq!(read(b"  spaced  \n").ok(), Some(b"  spaced  ".to_vec()));
        assert_eq!(read(b"no newline").ok(), Some(b"no newline".to_vec()));
        assert!(matches!(read(b""), Err(Failure::Usage(_))));

        let mut long = vec![b'x'; MAX_PASSWORD_BYTES + 5];
        long.push(b'\n');
        assert!(matches!(
            read(&long),
            Err(Failure::Vault(VaultError::InvalidInput("password length")))
        ));

        // Two passwords are read line by line from the same stream.
        let mut stream = Cursor::new(b"first\nsecond\n".to_vec());
        assert_eq!(
            read_password(&mut stream).ok().map(|p| p.to_vec()),
            Some(b"first".to_vec())
        );
        assert_eq!(
            read_password(&mut stream).ok().map(|p| p.to_vec()),
            Some(b"second".to_vec())
        );
    }

    #[test]
    fn terminal_stdin_is_refused_for_passwords() {
        let (code, _, err) = run_with(&["verify", "x.avault", "--password-stdin"], b"pw\n", true);
        assert_eq!(code, EXIT_USAGE);
        assert!(err.contains("terminal"));
    }

    #[test]
    fn usage_errors_never_echo_argument_values() {
        for args in [
            &["verify", "x.avault", "--password=hunter2-secret"][..],
            &["verify", "x.avault", "hunter2-secret", "--password-stdin"][..],
            &["hunter2-secret"][..],
            &["verify", "x.avault"][..],
            &["info", "x.avault", "--password-stdin"][..],
            &["create", "x.avault", "--password-stdin", "--kdf", "1,2"][..],
        ] {
            let (code, out, err) = run_with(args, b"", false);
            assert_eq!(code, EXIT_USAGE, "{args:?}");
            assert!(out.is_empty());
            assert!(!err.contains("hunter2-secret"), "{args:?}");
        }
        let (code, _, _) = run_with(&[], b"", false);
        assert_eq!(code, EXIT_USAGE);
    }

    #[test]
    fn kdf_option_is_validated_by_vault_limits() {
        let (code, _, err) = run_with(
            &[
                "create",
                "x.avault",
                "--password-stdin",
                "--kdf",
                "1024,2,1",
            ],
            b"long enough password\n",
            false,
        );
        assert_eq!(code, 16, "below minimum memory cost is a resource limit");
        assert!(err.contains("kdf memory cost"));
    }

    #[test]
    fn exit_codes_are_distinct_per_class() {
        let errors = [
            VaultError::NotFound,
            VaultError::Unavailable("x"),
            VaultError::Busy,
            VaultError::Corrupt("x"),
            VaultError::Unsupported("x"),
            VaultError::AuthenticationFailed,
            VaultError::ResourceLimit("x"),
            VaultError::Conflict,
            VaultError::Io("x"),
            VaultError::DurabilityUncertain,
            VaultError::AlreadyExists,
            VaultError::InvalidInput("x"),
            VaultError::UnknownRecord,
            VaultError::Crypto,
        ];
        let codes: std::collections::BTreeSet<u8> = errors.iter().map(exit_code).collect();
        assert_eq!(codes.len(), errors.len());
        assert!(codes
            .iter()
            .all(|&code| ![EXIT_OK, EXIT_FAILURE, EXIT_USAGE].contains(&code)));
        assert_eq!(
            exit_code(&VaultError::Random),
            exit_code(&VaultError::Crypto)
        );
    }

    #[test]
    fn help_prints_usage() {
        let (code, out, _) = run_with(&["help"], b"", false);
        assert_eq!(code, EXIT_OK);
        assert!(out.contains("--password-stdin"));
    }
}
