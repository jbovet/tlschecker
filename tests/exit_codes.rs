//! End-to-end exit codes (#206): runs the real binary against in-process
//! loopback TLS servers that serve synthetic certificates.
//!
//! Loopback is offline, not network: nothing here leaves the machine, so these
//! run on every `cargo test`. Hosts that must fail before any connection use
//! an invalid address (`example.com:99999`) or a refused loopback port.

// The binary needs the default `tui` feature (`[[bin]] required-features`).
#![cfg(feature = "tui")]

use std::net::TcpListener;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{SslAcceptor, SslMethod};
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::{X509Builder, X509NameBuilder, X509};

const DAY: i64 = 86_400;

/// Flags every check run gets: the classic JSON stream and a short connect
/// budget (loopback answers or refuses at once).
const CHECK_FLAGS: [&str; 5] = ["--no-dashboard", "-o", "json", "--connect-timeout", "5"];

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs() as i64
}

/// What the certificate's Subject Alternative Name names.
enum San {
    Ip(&'static str),
    Dns(&'static str),
}

/// A self-signed EC P-256 certificate valid from `not_before` to `not_after`
/// (Unix seconds).
///
/// Its 1-bit serial number is also a CA/B Forum misissuance — a Warning, like
/// self-signed and untrusted — so the default gate is exercised against the
/// typical private-CA certificate, which must not fail the run.
fn make_cert(san: San, not_before: i64, not_after: i64) -> (X509, PKey<Private>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();

    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "tlschecker test").unwrap();
    let name = name.build();

    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    let serial = BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap();
    builder.set_serial_number(&serial).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(&Asn1Time::from_unix(not_before as _).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::from_unix(not_after as _).unwrap())
        .unwrap();
    let san = {
        let context = builder.x509v3_context(None, None);
        let mut ext = SubjectAlternativeName::new();
        match san {
            San::Ip(ip) => ext.ip(ip),
            San::Dns(dns) => ext.dns(dns),
        };
        ext.build(&context).unwrap()
    };
    builder.append_extension(san).unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();
    (builder.build(), key)
}

/// Serves `cert` on a loopback port until the test process exits, and
/// returns the port. Handshakes are served one at a time on a detached
/// thread — enough for one check per host.
fn spawn_server((cert, key): (X509, PKey<Private>)) -> u16 {
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor.set_private_key(&key).unwrap();
    acceptor.set_certificate(&cert).unwrap();
    acceptor.check_private_key().unwrap();
    let acceptor = acceptor.build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            // The client drops the connection after reading the certificate.
            let _ = acceptor.accept(stream);
        }
    });
    port
}

/// A loopback server whose certificate is valid for 127.0.0.1 with 300 days
/// left of a 365-day lifetime.
fn valid_host() -> String {
    let now = now();
    let port = spawn_server(make_cert(
        San::Ip("127.0.0.1"),
        now - 65 * DAY,
        now + 300 * DAY,
    ));
    format!("127.0.0.1:{port}")
}

/// A loopback server whose certificate only names `other.example`.
fn mismatch_host() -> String {
    let now = now();
    let port = spawn_server(make_cert(
        San::Dns("other.example"),
        now - 65 * DAY,
        now + 300 * DAY,
    ));
    format!("127.0.0.1:{port}")
}

/// A loopback server whose certificate expired ten days ago.
fn expired_host() -> String {
    let now = now();
    let port = spawn_server(make_cert(
        San::Ip("127.0.0.1"),
        now - 400 * DAY,
        now - 10 * DAY,
    ));
    format!("127.0.0.1:{port}")
}

/// A loopback address that refuses connections: bind a port, then release it.
fn refused_host() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    format!("127.0.0.1:{port}")
}

/// An address rejected before any connection is attempted.
const INVALID_HOST: &str = "example.com:99999";

/// Runs the binary with exactly `args`, from an empty directory so no stray
/// `tlschecker.toml` is picked up.
fn tlschecker(args: &[&str]) -> Output {
    let dir = tempfile::tempdir().unwrap();
    Command::new(env!("CARGO_BIN_EXE_tlschecker"))
        .args(args)
        .current_dir(dir.path())
        .stdin(Stdio::null())
        .output()
        .expect("run tlschecker")
}

/// Runs a check: [`CHECK_FLAGS`] plus `args`.
fn check(args: &[&str]) -> Output {
    let all: Vec<&str> = CHECK_FLAGS
        .iter()
        .copied()
        .chain(args.iter().copied())
        .collect();
    tlschecker(&all)
}

fn code(output: &Output) -> i32 {
    output
        .status
        .code()
        .expect("exited normally, not by signal")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Asserts the exit code, showing the run's output when it differs.
#[track_caller]
fn assert_exit(output: &Output, expected: i32) {
    assert_eq!(
        code(output),
        expected,
        "stdout:\n{}\nstderr:\n{}",
        stdout(output),
        stderr(output)
    );
}

// ── 36: usage errors and unreachable hosts (no TLS server) ──────────────

#[test]
fn test_no_hosts_is_a_usage_error() {
    let output = check(&[]);
    assert_exit(&output, 2);
    assert!(stderr(&output).contains("error: No hosts specified"));
}

// ── #209: stderr reads like a CLI, not a log ───────────────────────

#[test]
fn test_bare_invocation_prints_help() {
    let output = tlschecker(&[]);
    assert_exit(&output, 2);
    let err = stderr(&output);
    assert!(err.contains("Usage: tlschecker"), "{err}");
    assert!(!err.contains("error:"), "{err}");
}

#[test]
fn test_bare_invocation_with_broken_config_reports_it() {
    // A tlschecker.toml in the CWD makes a bare run valid, so its error must
    // be shown, not hidden behind the help.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("tlschecker.toml"), "hosts = [").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_tlschecker"))
        .current_dir(dir.path())
        .stdin(Stdio::null())
        .output()
        .expect("run tlschecker");
    assert_exit(&output, 2);
    let err = stderr(&output);
    assert!(err.contains("error: Parse Error"), "{err}");
    assert!(!err.contains("Usage: tlschecker"), "{err}");
}

#[test]
fn test_failure_is_a_plain_hint_on_stderr() {
    let refused = refused_host();
    let err = stderr(&check(&[&refused]));
    assert!(
        err.contains(&format!(
            "error: {refused}: connection refused (nothing is listening on that port)"
        )),
        "{err}"
    );
    // Piped stderr: no colour escapes, no timestamps, no log noise.
    assert!(!err.contains('\x1b'), "{err}");
    assert!(!err.contains("ERROR") && !err.contains(" INFO "), "{err}");
    // The raw OS error is only shown with -v.
    assert!(!err.contains("os error"), "{err}");
    let verbose = stderr(&check(&["-v", &refused]));
    assert!(
        verbose.contains("info: ") && verbose.contains("os error"),
        "{verbose}"
    );
}

#[test]
fn test_quiet_hides_warnings() {
    let refused = refused_host();
    // --exit-code 1 is deprecated: a warning, shown by default...
    let loud = stderr(&check(&["--exit-code", "1", &refused]));
    assert!(loud.contains("warning: "), "{loud}");
    // ...and hidden by -q, which still shows errors.
    let quiet = stderr(&check(&["-q", "--exit-code", "1", &refused]));
    assert!(!quiet.contains("warning: "), "{quiet}");
    assert!(quiet.contains("error: "), "{quiet}");
}

#[test]
fn test_json_error_carries_the_hint() {
    let refused = refused_host();
    let output = check(&[&refused]);
    let json: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    let error = &json["results"][0]["error"];
    assert_eq!(
        error["hint"],
        "connection refused (nothing is listening on that port)"
    );
    assert!(error["message"].as_str().unwrap().contains("os error"));
}

#[test]
fn test_out_of_range_flags_are_usage_errors() {
    assert_exit(&check(&["--concurrency", "0", "x"]), 2);
    assert_exit(
        &tlschecker(&[
            "--no-dashboard",
            "-o",
            "json",
            "--connect-timeout",
            "0",
            "x",
        ]),
        2,
    );
}

#[test]
fn test_config_errors_are_usage_errors() {
    let output = check(&["--config", "/nonexistent.toml", "x"]);
    assert_exit(&output, 2);
    // The actual error is printed, not only the hints.
    assert!(stderr(&output).contains("IO Error"), "{}", stderr(&output));

    let mut config = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut config, b"hosts = [unterminated").unwrap();
    let output = check(&["--config", config.path().to_str().unwrap(), "x"]);
    assert_exit(&output, 2);
    assert!(
        stderr(&output).contains("Parse Error"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn test_unsupported_legacy_exit_codes_are_usage_errors() {
    for value in ["7", "256"] {
        let output = check(&["--exit-code", value, "x"]);
        assert_exit(&output, 2);
        assert!(stderr(&output).contains("no longer supported"));
    }
}

#[test]
fn test_invalid_flag_values_are_usage_errors() {
    assert_exit(&check(&["--allow", "expired", "x"]), 2);
    assert_exit(&check(&["--fail-on", "bogus", "x"]), 2);
}

#[test]
fn test_generate_config_exits_0() {
    let output = tlschecker(&["--generate-config"]);
    assert_exit(&output, 0);
    assert!(stdout(&output).contains("fail_on = \"critical\""));
}

#[test]
fn test_unreachable_host_exits_3() {
    let refused = refused_host();

    let output = check(&[&refused]);
    assert_exit(&output, 3);
    // The host is listed as an error entry, not dropped.
    let json: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(json["results"][0]["outcome"], "error");
    assert_eq!(json["results"][0]["error"]["kind"], "connection");
    assert!(stderr(&output).contains("no host could be checked"));

    // Nothing was checked, so neither control turns this into success.
    assert_exit(&check(&["--allow-unreachable", &refused]), 3);
    assert_exit(&check(&["--fail-on", "never", &refused]), 3);
}

#[test]
fn test_invalid_address_exits_3() {
    let output = check(&[INVALID_HOST]);
    assert_exit(&output, 3);
    assert!(stderr(&output).contains("Invalid port"));
}

// ── 37: loopback TLS servers ───────────────────────────────────────────

#[test]
fn test_private_ca_certificate_passes_by_default() {
    // Self-signed, untrusted (or trust unknown without a CA bundle) and a
    // misissuance: all Warning, so the default gate passes...
    let host = valid_host();
    let output = check(&[&host]);
    assert_exit(&output, 0);
    assert!(stdout(&output).contains("\"verdict\": \"warning\""));

    // ...and --fail-on warning fails it.
    let output = check(&["--fail-on", "warning", &host]);
    assert_exit(&output, 1);
    assert!(stderr(&output).contains("SELF-SIGNED"));
}

#[test]
fn test_hostname_mismatch_fails_the_run() {
    // The #205/#206 repro: a certificate for another name, a year left.
    let host = mismatch_host();
    let output = check(&[&host]);
    assert_exit(&output, 1);
    assert!(stdout(&output).contains("\"verdict\": \"critical\""));
    let err = stderr(&output);
    assert!(err.contains("HOSTNAME MISMATCH"), "{err}");
    assert!(err.contains("--fail-on never"), "{err}");

    assert_exit(&check(&["--allow", "hostname-mismatch", &host]), 0);
    assert_exit(&check(&["--fail-on", "never", &host]), 0);
}

#[test]
fn test_expired_certificate_fails_the_run() {
    let host = expired_host();
    assert_exit(&check(&[&host]), 1);
    assert_exit(&check(&["--fail-on", "never", &host]), 0);
}

#[test]
fn test_certificate_problem_beats_unreachable() {
    assert_exit(&check(&[&expired_host(), &refused_host()]), 1);
}

#[test]
fn test_allow_unreachable_needs_one_checked_host() {
    let output = check(&["--allow-unreachable", &valid_host(), &refused_host()]);
    assert_exit(&output, 0);
    assert!(stderr(&output).contains("ignored: --allow-unreachable"));

    // An invalid address is a host-list typo, never forgiven.
    let output = check(&["--allow-unreachable", &valid_host(), INVALID_HOST]);
    assert_exit(&output, 3);
    assert!(stderr(&output).contains("invalid host address"));
}

// ── #214: host lists, --output, completions ────────────────────────

/// Runs the binary with `args` and `input` on stdin, from an empty directory.
fn tlschecker_with_stdin(args: &[&str], input: &str) -> Output {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_tlschecker"))
        .args(args)
        .current_dir(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run tlschecker");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().expect("wait for tlschecker")
}

fn json_inputs(output: &Output) -> Vec<String> {
    let json: serde_json::Value = serde_json::from_str(&stdout(output)).unwrap();
    json["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["input"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn test_hosts_from_stdin_dash() {
    let (a, b) = (refused_host(), refused_host());
    let input = format!("# list\n{a}\n\n{b}  # second\n");
    let output = tlschecker_with_stdin(
        &[
            "--no-dashboard",
            "--output",
            "json",
            "--connect-timeout",
            "5",
            "-",
        ],
        &input,
    );
    assert_exit(&output, 3);
    assert_eq!(json_inputs(&output), [a, b]);
}

#[test]
fn test_hosts_file_dash_reads_stdin_after_arguments() {
    let (a, b) = (refused_host(), refused_host());
    let output = tlschecker_with_stdin(
        &[
            "--no-dashboard",
            "-o",
            "json",
            "--connect-timeout",
            "5",
            "--hosts-file",
            "-",
            &a,
        ],
        &format!("{b}\n"),
    );
    assert_exit(&output, 3);
    assert_eq!(json_inputs(&output), [a, b]);
}

#[test]
fn test_missing_hosts_file_is_a_usage_error() {
    let output = tlschecker(&["--hosts-file", "/nonexistent/hosts.txt"]);
    assert_exit(&output, 2);
    assert!(stderr(&output).contains("cannot read hosts file '/nonexistent/hosts.txt'"));
}

#[test]
fn test_completions_print_a_script() {
    let output = tlschecker(&["--completions", "bash"]);
    assert_exit(&output, 0);
    let script = stdout(&output);
    assert!(script.contains("_tlschecker"), "{script}");
    assert!(script.contains("--hosts-file"), "{script}");
}
