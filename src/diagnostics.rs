//! Diagnostics on stderr: how log lines look and which ones are shown (#209).
//!
//! The CLI writes its diagnostics through `tracing` so library warnings and
//! CLI errors share one channel, but they are meant for a person reading a
//! terminal or a CI log, not for log aggregation:
//!
//! - **Format:** `error: <message>` / `warning: <message>` — no timestamp, no
//!   module path, no span fields (`-vv` adds the target).
//! - **Colour:** only when stderr is a terminal and `NO_COLOR` is unset or
//!   empty (<https://no-color.org>), so piped stderr and CI logs never carry
//!   escape codes.
//! - **Level:** warnings and errors by default; `-q` shows errors only, `-v`
//!   adds tlschecker's info (e.g. the raw error behind a hint), `-vv` its
//!   debug — third-party crates stay at warnings. A non-empty `RUST_LOG`
//!   (`warn`, `tlschecker=debug,reqwest=warn`, …) overrides both.
//!
//! [`failure_hint`] turns the most common connection and handshake errors into
//! a sentence a user can act on; the raw text stays available at `-v` and in
//! the JSON `error.message`.

use std::fmt;
use std::io::IsTerminal;

use tracing::{Event, Level, Subscriber};
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;

/// Installs the global subscriber. Called once, after argument parsing, so
/// `-v` / `-q` can choose the level.
pub(crate) fn init(verbose: u8, quiet: bool) {
    let rust_log = std::env::var("RUST_LOG")
        .ok()
        .filter(|v| !v.trim().is_empty());
    let (filter, bad_rust_log) = match rust_log.as_deref().map(str::parse::<Targets>) {
        Some(Ok(targets)) => (targets, None),
        Some(Err(e)) => (default_filter(verbose, quiet), Some(e.to_string())),
        None => (default_filter(verbose, quiet), None),
    };
    let ansi = use_color(
        std::io::stderr().is_terminal(),
        std::env::var_os("NO_COLOR").as_deref(),
    );

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(crate::tracing_writer)
                .with_ansi(ansi)
                .event_format(CliFormat {
                    ansi,
                    show_target: verbose >= 2,
                }),
        )
        .with(filter)
        .init();

    if let Some(e) = bad_rust_log {
        tracing::warn!("ignoring RUST_LOG ({e}); using the -v/-q level");
    }
}

/// Default threshold: errors only with `-q`, warnings by default, then info
/// and debug for each `-v`.
fn level(verbose: u8, quiet: bool) -> LevelFilter {
    match (quiet, verbose) {
        (true, _) => LevelFilter::ERROR,
        (false, 0) => LevelFilter::WARN,
        (false, 1) => LevelFilter::INFO,
        (false, _) => LevelFilter::DEBUG,
    }
}

/// `-v` / `-vv` raise tlschecker's own level only: third-party crates (hyper,
/// reqwest, rustls, …) stay at warnings (errors with `-q`), or `-vv` would
/// bury the useful lines in HTTP and TLS internals. `RUST_LOG` reaches them.
fn default_filter(verbose: u8, quiet: bool) -> Targets {
    let others = if quiet {
        LevelFilter::ERROR
    } else {
        LevelFilter::WARN
    };
    Targets::new()
        .with_default(others)
        .with_target("tlschecker", level(verbose, quiet))
}

/// Colour only for a terminal, and never when `NO_COLOR` is set to a
/// non-empty value.
fn use_color(stderr_is_terminal: bool, no_color: Option<&std::ffi::OsStr>) -> bool {
    stderr_is_terminal && no_color.is_none_or(|v| v.is_empty())
}

/// `error: message` lines (see the module docs).
struct CliFormat {
    ansi: bool,
    show_target: bool,
}

impl<S, N> FormatEvent<S, N> for CliFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let (label, color) = match *event.metadata().level() {
            Level::ERROR => ("error", "\x1b[1;31m"),
            Level::WARN => ("warning", "\x1b[1;33m"),
            Level::INFO => ("info", "\x1b[1;36m"),
            Level::DEBUG => ("debug", "\x1b[2m"),
            Level::TRACE => ("trace", "\x1b[2m"),
        };
        if self.ansi {
            write!(writer, "{color}{label}\x1b[0m: ")?;
        } else {
            write!(writer, "{label}: ")?;
        }
        if self.show_target {
            write!(writer, "[{}] ", event.metadata().target())?;
        }
        ctx.field_format().format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

/// A plain-language explanation of a host check failure, when its raw error
/// (an OpenSSL error stack or an OS error) is one of the common ones.
///
/// Matching is on lowercase substrings, most specific first. `None` means the
/// raw error is shown as is. Windows words its socket errors differently and
/// in the system's language, so they are also matched by their WSA code
/// (`os error 10061`), which every locale shares.
pub(crate) fn failure_hint(detail: &str) -> Option<&'static str> {
    const HINTS: &[(&[&str], &str)] = &[
        (
            &[
                "wrong version number",
                "packet length too long",
                "http request",
            ],
            "the port does not speak TLS (plain HTTP or another protocol?)",
        ),
        (
            &["certificate required"],
            "the server requires a client certificate",
        ),
        (
            &["unrecognized name"],
            "the server does not recognize this hostname (SNI)",
        ),
        (
            &[
                "alert protocol version",
                "unsupported protocol",
                "no protocols available",
            ],
            "no TLS version in common with the server",
        ),
        // Below TLS 1.3 there is no "certificate required" alert: a server
        // that wants a client certificate sends this same generic alert.
        (
            &["alert handshake failure", "no shared cipher"],
            "the server rejected the TLS handshake (no protocol or cipher suite in common, \
             or it requires a client certificate)",
        ),
        (
            &["unexpected eof", "unexpected end of file"],
            "the server closed the connection during the TLS handshake",
        ),
        (
            &["connection reset", "forcibly closed", "os error 10054"],
            "the server reset the connection",
        ),
        (
            &["connection refused", "actively refused", "os error 10061"],
            "connection refused (nothing is listening on that port)",
        ),
        (
            &[
                "timed out",
                "would block",
                "resource temporarily unavailable",
                "did not properly respond",
                "os error 10060",
            ],
            "timed out (raise --connect-timeout for slow links)",
        ),
        (
            &[
                "failed to lookup address",
                "name or service not known",
                "no address associated",
                "nodename nor servname",
                "temporary failure in name resolution",
                "no such host is known",
                "os error 11001",
                "os error 11002",
                "os error 11004",
            ],
            "DNS lookup failed: the host name does not resolve",
        ),
        (
            &["address family not supported", "os error 10047"],
            "address family not supported (an IPv6 address on an IPv4-only network?)",
        ),
        (
            &[
                "network is unreachable",
                "no route to host",
                "os error 10051",
                "os error 10065",
            ],
            "network unreachable (no route to the host)",
        ),
    ];
    let detail = detail.to_ascii_lowercase();
    HINTS
        .iter()
        .find(|(needles, _)| needles.iter().any(|n| detail.contains(n)))
        .map(|(_, hint)| *hint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn test_level_defaults_and_flags() {
        assert_eq!(level(0, false), LevelFilter::WARN);
        assert_eq!(level(1, false), LevelFilter::INFO);
        assert_eq!(level(2, false), LevelFilter::DEBUG);
        assert_eq!(level(5, false), LevelFilter::DEBUG);
        assert_eq!(level(0, true), LevelFilter::ERROR);
    }

    #[test]
    fn test_default_filter_hides_info_from_any_target() {
        let f = default_filter(0, false);
        assert!(f.would_enable("tlschecker", &Level::WARN));
        assert!(!f.would_enable("tlschecker", &Level::INFO));
        assert!(!f.would_enable("reqwest", &Level::INFO));
    }

    #[test]
    fn test_verbose_raises_only_our_own_level() {
        let f = default_filter(2, false);
        assert!(f.would_enable("tlschecker", &Level::DEBUG));
        assert!(f.would_enable("tlschecker::probe", &Level::DEBUG));
        assert!(!f.would_enable("hyper", &Level::DEBUG));
        assert!(f.would_enable("hyper", &Level::WARN));
        // -q: errors only, everywhere.
        let q = default_filter(0, true);
        assert!(!q.would_enable("tlschecker", &Level::WARN));
        assert!(!q.would_enable("reqwest", &Level::WARN));
        assert!(q.would_enable("reqwest", &Level::ERROR));
    }

    #[test]
    fn test_use_color() {
        assert!(use_color(true, None));
        assert!(use_color(true, Some(OsStr::new(""))));
        assert!(!use_color(true, Some(OsStr::new("1"))));
        assert!(!use_color(false, None));
    }

    #[test]
    fn test_failure_hints_for_common_errors() {
        let cases = [
            (
                "TLS Handshake error: the handshake failed: error:0A00010B:SSL routines:\
                 tls_validate_record_header:wrong version number:ssl/record/methods/tlsany_meth.c:77:",
                "does not speak TLS",
            ),
            (
                "Connection error: Connection refused (os error 111)",
                "connection refused",
            ),
            (
                "Connection error: failed to lookup address information: Name or service not known",
                "DNS lookup failed",
            ),
            (
                "Connection error: connection timed out before any address could be tried",
                "timed out",
            ),
            // A TLS 1.2 server that wants a client certificate sends the same
            // alert as one with no cipher in common, so the hint names both.
            (
                "TLS Handshake error: ... ssl3_read_bytes:ssl/tls alert handshake failure ...",
                "or it requires a client certificate",
            ),
            (
                "TLS Handshake error: ... ssl3_read_bytes:tlsv1 alert protocol version ...",
                "no TLS version in common",
            ),
            (
                "TLS Handshake error: ... unexpected eof while reading ...",
                "closed the connection",
            ),
            (
                "TLS Handshake error: ... tlsv13 alert certificate required ...",
                "client certificate",
            ),
            (
                "Connection error: Address family not supported by protocol (os error 97)",
                "IPv6",
            ),
            // Windows, as Rust prints its socket errors.
            (
                "Connection error: No connection could be made because the target machine \
                 actively refused it. (os error 10061)",
                "connection refused",
            ),
            (
                "Connection error: No such host is known. (os error 11001)",
                "DNS lookup failed",
            ),
            (
                "Connection error: A connection attempt failed because the connected party did \
                 not properly respond after a period of time, or established connection failed \
                 because connected host has failed to respond. (os error 10060)",
                "timed out",
            ),
            (
                "TLS Handshake error: An existing connection was forcibly closed by the remote \
                 host. (os error 10054)",
                "reset the connection",
            ),
            (
                "Connection error: A socket operation was attempted to an unreachable network. \
                 (os error 10051)",
                "network unreachable",
            ),
            // A non-English Windows: only the code is recognizable.
            (
                "Connection error: No se puede establecer una conexión ya que el equipo de \
                 destino denegó expresamente dicha conexión. (os error 10061)",
                "connection refused",
            ),
        ];
        for (detail, expected) in cases {
            let hint = failure_hint(detail).unwrap_or_else(|| panic!("no hint for {detail}"));
            assert!(hint.contains(expected), "{detail} -> {hint}");
        }
    }

    #[test]
    fn test_failure_hint_unknown_error_is_none() {
        assert_eq!(
            failure_hint("Invalid port '99999' in address 'x:99999'"),
            None
        );
        assert_eq!(failure_hint("internal error: worker panicked"), None);
    }
}
