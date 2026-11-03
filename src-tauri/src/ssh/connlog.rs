//! LogLevel and LogVerbose: what ssh would print about a connection, shown
//! in its terminal. Reach's own log messages (and russh's) made while the
//! connection's span is current are collected per connection and filtered
//! as ssh's log.c filters: a message shows when its level is at or below
//! LogLevel, or when LogVerbose names where it comes from.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use tracing::field::{Field, Visit};
use tracing::level_filters::LevelFilter;
use tracing::{Event, Level, Metadata, Subscriber};
use tracing_subscriber::layer::{Context, Filter, Layer};
use tracing_subscriber::registry::LookupSpan;

/// log.h LogLevel, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Quiet,
    Fatal,
    Error,
    Info,
    Verbose,
    Debug1,
    Debug2,
    Debug3,
}

impl LogLevel {
    /// log_level_number: the names ssh accepts, any case.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_uppercase().as_str() {
            "QUIET" => LogLevel::Quiet,
            "FATAL" => LogLevel::Fatal,
            "ERROR" => LogLevel::Error,
            "INFO" => LogLevel::Info,
            "VERBOSE" => LogLevel::Verbose,
            "DEBUG" | "DEBUG1" => LogLevel::Debug1,
            "DEBUG2" => LogLevel::Debug2,
            "DEBUG3" => LogLevel::Debug3,
            _ => return None,
        })
    }

    /// Where a Reach or russh message sits on ssh's scale: errors are
    /// errors, warnings are what ssh logs at INFO ("Warning: …"), info is
    /// VERBOSE detail, debug is debug1, trace debug2.
    fn of(level: &Level) -> Self {
        match *level {
            Level::ERROR => LogLevel::Error,
            Level::WARN => LogLevel::Info,
            Level::INFO => LogLevel::Verbose,
            Level::DEBUG => LogLevel::Debug1,
            Level::TRACE => LogLevel::Debug2,
        }
    }

    fn prefix(self) -> &'static str {
        match self {
            LogLevel::Debug1 => "debug1: ",
            LogLevel::Debug2 => "debug2: ",
            LogLevel::Debug3 => "debug3: ",
            _ => "",
        }
    }

    fn filter(self) -> LevelFilter {
        match self {
            LogLevel::Quiet | LogLevel::Fatal => LevelFilter::OFF,
            LogLevel::Error => LevelFilter::ERROR,
            LogLevel::Info => LevelFilter::WARN,
            LogLevel::Verbose => LevelFilter::INFO,
            LogLevel::Debug1 => LevelFilter::DEBUG,
            LogLevel::Debug2 | LogLevel::Debug3 => LevelFilter::TRACE,
        }
    }
}

/// The server's login banner goes through the log as ssh's does: shown at
/// INFO and above, as it was sent.
pub const BANNER_TARGET: &str = "reach::ssh_banner";

/// One connection's log.
pub struct ConnLog {
    pub level: LogLevel,
    /// LogVerbose patterns, "file:function:line" each.
    verbose: Vec<[String; 3]>,
    lines: Mutex<Vec<String>>,
    sink: Mutex<Option<tokio::sync::mpsc::UnboundedSender<String>>>,
    /// The session is up: russh's packet-level debug stops, since Reach's
    /// own background channels (the status bar, file browsing) would fill
    /// the terminal with it. LogVerbose can still ask for it.
    established: std::sync::atomic::AtomicBool,
    id: u64,
}

impl std::fmt::Debug for ConnLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnLog").field("level", &self.level).field("verbose", &self.verbose).finish()
    }
}

fn logs() -> &'static Mutex<HashMap<u64, Arc<ConnLog>>> {
    static LOGS: OnceLock<Mutex<HashMap<u64, Arc<ConnLog>>>> = OnceLock::new();
    LOGS.get_or_init(Default::default)
}

/// The most verbose level any open connection wants, for the filter hint.
static MAX: AtomicU64 = AtomicU64::new(0);

fn level_num(f: LevelFilter) -> u64 {
    match f.into_level() {
        None => 0,
        Some(Level::ERROR) => 1,
        Some(Level::WARN) => 2,
        Some(Level::INFO) => 3,
        Some(Level::DEBUG) => 4,
        Some(Level::TRACE) => 5,
    }
}

fn num_level(n: u64) -> LevelFilter {
    [LevelFilter::OFF, LevelFilter::ERROR, LevelFilter::WARN, LevelFilter::INFO, LevelFilter::DEBUG, LevelFilter::TRACE][n.min(5) as usize]
}

fn refresh_max() {
    // One at a time: a connection closing while another opens could otherwise
    // store its older count last and leave MAX at 0, dropping every line.
    static REFRESH: Mutex<()> = Mutex::new(());
    let _one = REFRESH.lock().unwrap_or_else(|e| e.into_inner());
    let want = logs().lock().unwrap().values().map(|l| if l.verbose.is_empty() { level_num(l.level.filter()) } else { 5 }).max().unwrap_or(0);
    if MAX.swap(want, Ordering::Relaxed) != want {
        // russh logs through the log crate; let its records through too.
        log::set_max_level(match num_level(want.max(3)).into_level() {
            Some(Level::TRACE) => log::LevelFilter::Trace,
            Some(Level::DEBUG) => log::LevelFilter::Debug,
            _ => log::LevelFilter::Info,
        });
        tracing::callsite::rebuild_interest_cache();
    }
}

impl ConnLog {
    /// A connection's log from its LogLevel and LogVerbose values.
    pub fn new(level: Option<&str>, verbose: &[String]) -> Arc<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let verbose = verbose
            .iter()
            .flat_map(|v| v.split(','))
            .filter(|p| !p.is_empty())
            .map(|p| {
                let mut it = p.splitn(3, ':');
                let mut part = || it.next().filter(|s| !s.is_empty()).unwrap_or("*").to_string();
                [part(), part(), part()]
            })
            .collect();
        let log = Arc::new(ConnLog {
            level: level.and_then(LogLevel::parse).unwrap_or(LogLevel::Info),
            verbose,
            lines: Mutex::new(Vec::new()),
            sink: Mutex::new(None),
            established: std::sync::atomic::AtomicBool::new(false),
            id: NEXT.fetch_add(1, Ordering::Relaxed),
        });
        logs().lock().unwrap().insert(log.id, log.clone());
        refresh_max();
        log
    }

    /// The span to run the connection in.
    pub fn span(&self) -> tracing::Span {
        tracing::info_span!("ssh_connection", connlog = self.id)
    }

    /// Whether ssh would show a message of this level.
    pub fn shows(&self, l: LogLevel) -> bool {
        l != LogLevel::Quiet && l <= self.level
    }

    /// log.c's log_verbose match: file (base name), function (Reach's
    /// module path, as Rust has no function names here) and line.
    fn forced(&self, meta: &Metadata<'_>) -> bool {
        use crate::ssh::sshconf::pattern::match_pattern;
        let file = meta.file().map(|f| f.rsplit(['/', '\\']).next().unwrap_or(f)).unwrap_or("");
        let module = meta.module_path().unwrap_or("");
        let line = meta.line().map(|l| l.to_string()).unwrap_or_default();
        self.verbose.iter().any(|[f, func, l]| {
            match_pattern(file, f) && (match_pattern(module, func.trim_end_matches("()")) || func == "*") && match_pattern(&line, l)
        })
    }

    fn wants(&self, meta: &Metadata<'_>) -> bool {
        // Only the SSH code's own messages: nothing another library logs
        // while the connection is current reaches the terminal.
        if !ssh_target(meta.target()) {
            return false;
        }
        if meta.target() == BANNER_TARGET {
            return self.shows(LogLevel::Info);
        }
        let level = LogLevel::of(meta.level());
        let quiet_now = level >= LogLevel::Debug1 && meta.target().starts_with("russh") && self.established.load(Ordering::Relaxed);
        (self.shows(level) && !quiet_now) || (!self.verbose.is_empty() && self.forced(meta))
    }

    fn push(&self, line: String) {
        let line = vis(&line);
        if let Some(tx) = self.sink.lock().unwrap().as_ref() {
            if tx.send(line.clone()).is_ok() {
                return;
            }
        }
        let mut lines = self.lines.lock().unwrap();
        // A connection that never shows its terminal must not grow forever.
        if lines.len() < 5000 {
            lines.push(line);
        }
    }

    /// The lines so far; later ones go to `tx`.
    pub fn attach(&self, tx: tokio::sync::mpsc::UnboundedSender<String>) -> Vec<String> {
        self.established.store(true, Ordering::Relaxed);
        let mut lines = self.lines.lock().unwrap();
        *self.sink.lock().unwrap() = Some(tx);
        std::mem::take(&mut *lines)
    }

    /// The lines so far, for an error message when the connection failed.
    pub fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.lines.lock().unwrap())
    }
}

/// Removes a connection's log once it ends.
pub fn close(log: &ConnLog) {
    logs().lock().unwrap().remove(&log.id);
    refresh_max();
}

/// Where the messages a connection shows come from.
fn ssh_target(target: &str) -> bool {
    target == BANNER_TARGET || target.starts_with(concat!(env!("CARGO_CRATE_NAME"), "::ssh")) || target.starts_with("russh")
}

/// stravis(VIS_SAFE | VIS_OCTAL | VIS_NOSLASH) as ssh applies it to the
/// banner and to what it logs: control characters (escape sequences
/// among them) are shown as octal, so a server cannot drive the terminal
/// through them. Tabs and printable text, in any script, pass.
pub fn vis(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '\t' || !c.is_control() {
            out.push(c);
        } else {
            let mut b = [0u8; 4];
            for byte in c.encode_utf8(&mut b).bytes() {
                out.push_str(&format!("\\{byte:03o}"));
            }
        }
    }
    out
}

struct Id(u64);

impl Visit for Id {
    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "connlog" {
            self.0 = value;
        }
    }
    fn record_debug(&mut self, _: &Field, _: &dyn std::fmt::Debug) {}
}

#[derive(Default)]
struct Message(String);

impl Visit for Message {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.add(field, value.to_string());
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.add(field, format!("{value:?}"));
    }
}

impl Message {
    fn add(&mut self, field: &Field, value: String) {
        if field.name() == "message" {
            self.0.insert_str(0, &value);
        } else if !field.name().starts_with("log.") {
            self.0.push_str(&format!(" {}={value}", field.name()));
        }
    }
}

fn find<S>(span: Option<tracing_subscriber::registry::SpanRef<'_, S>>) -> Option<Arc<ConnLog>>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    span?.scope().find_map(|s| s.extensions().get::<Arc<ConnLog>>().cloned())
}

/// The layer that collects connection logs.
pub struct ConnLogLayer;

impl<S> Layer<S> for ConnLogLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &tracing::span::Attributes<'_>, id: &tracing::span::Id, ctx: Context<'_, S>) {
        if attrs.metadata().name() != "ssh_connection" {
            return;
        }
        let mut v = Id(0);
        attrs.record(&mut v);
        if let (Some(log), Some(span)) = (logs().lock().unwrap().get(&v.0).cloned(), ctx.span(id)) {
            span.extensions_mut().insert(log);
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let Some(log) = find(ctx.event_span(event)) else { return };
        // log crate records (russh) carry their real place in log.* fields.
        use tracing_log::NormalizeEvent;
        let normalized = event.normalized_metadata();
        let meta = normalized.as_ref().unwrap_or_else(|| event.metadata());
        if !log.wants(meta) {
            return;
        }
        let mut m = Message::default();
        event.record(&mut m);
        if meta.target() == BANNER_TARGET {
            for l in m.0.split_inclusive('\n') {
                log.push(l.trim_end_matches(['\r', '\n']).to_string());
            }
            return;
        }
        let level = LogLevel::of(meta.level());
        log.push(format!("{}{}", level.prefix(), m.0));
    }
}

/// Lets events through to the layer only inside a connection that wants
/// them, so debug logging costs nothing elsewhere.
pub struct ConnLogFilter;

impl<S> Filter<S> for ConnLogFilter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn enabled(&self, meta: &Metadata<'_>, cx: &Context<'_, S>) -> bool {
        if meta.is_span() {
            return meta.name() == "ssh_connection" || MAX.load(Ordering::Relaxed) > 0;
        }
        if MAX.load(Ordering::Relaxed) == 0 {
            return false;
        }
        find(cx.lookup_current()).is_some_and(|l| l.wants(meta) || (!l.verbose.is_empty()))
    }

    fn callsite_enabled(&self, _meta: &'static Metadata<'static>) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(num_level(MAX.load(Ordering::Relaxed).max(1)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tests that open connection logs share MAX and tracing's global
    /// level, so they take turns.
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        static TURN: Mutex<()> = Mutex::new(());
        TURN.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn control_characters_are_shown_not_obeyed() {
        assert_eq!(vis("Welcome\x1b]0;owned\x07 to h\u{e9}llo\tok"), "Welcome\\033]0;owned\\007 to h\u{e9}llo\tok");
        assert_eq!(vis("a\u{9b}2Jb"), "a\\302\\2332Jb");
    }

    #[test]
    fn levels() {
        let _turn = serial();
        assert_eq!(LogLevel::parse("debug"), Some(LogLevel::Debug1));
        assert_eq!(LogLevel::parse("Verbose"), Some(LogLevel::Verbose));
        assert_eq!(LogLevel::parse("loud"), None);
        let l = ConnLog::new(Some("ERROR"), &[]);
        assert!(l.shows(LogLevel::Error) && !l.shows(LogLevel::Info));
        close(&l);
        let l = ConnLog::new(Some("QUIET"), &[]);
        assert!(!l.shows(LogLevel::Error));
        close(&l);
        let l = ConnLog::new(None, &[]);
        assert!(l.shows(LogLevel::Info) && !l.shows(LogLevel::Verbose));
        close(&l);
    }

    #[test]
    fn collects_inside_the_connection_only() {
        let _turn = serial();
        use tracing_subscriber::layer::SubscriberExt;
        let sub = tracing_subscriber::registry().with(ConnLogLayer.with_filter(ConnLogFilter));
        let log = ConnLog::new(Some("DEBUG1"), &["*:*connlog*:*".into()]);
        let quiet = ConnLog::new(Some("ERROR"), &[]);
        tracing::subscriber::with_default(sub, || {
            tracing::debug!("outside");
            log.span().in_scope(|| {
                tracing::warn!("a warning");
                tracing::debug!(n = 3, "some detail");
                tracing::trace!("too fine, but LogVerbose names this module");
                tracing::warn!(target: BANNER_TARGET, "Welcome\nto the host\n");
            });
            quiet.span().in_scope(|| {
                tracing::warn!("hidden at ERROR");
                tracing::warn!(target: BANNER_TARGET, "hidden banner");
                tracing::error!("an error");
            });
        });
        assert_eq!(
            log.take(),
            vec!["a warning", "debug1: some detail n=3", "debug2: too fine, but LogVerbose names this module", "Welcome", "to the host"]
        );
        assert_eq!(quiet.take(), vec!["an error"]);
        close(&log);
        close(&quiet);
    }

    #[test]
    fn a_connection_opening_as_another_closes_keeps_its_level() {
        let _turn = serial();
        // One closes while the other opens, and nothing refreshes after: the
        // count stored last must include the one still open.
        for _ in 0..300 {
            let closing = ConnLog::new(Some("ERROR"), &[]);
            let start = Arc::new(std::sync::Barrier::new(2));
            let go = start.clone();
            let t = std::thread::spawn(move || {
                go.wait();
                close(&closing);
            });
            start.wait();
            let kept = ConnLog::new(Some("DEBUG3"), &[]);
            t.join().unwrap();
            assert!(MAX.load(Ordering::Relaxed) >= level_num(kept.level.filter()));
            close(&kept);
        }
    }

    #[test]
    fn russh_packet_debug_stops_once_the_session_is_up() {
        let _turn = serial();
        use tracing_subscriber::layer::SubscriberExt;
        let sub = tracing_subscriber::registry().with(ConnLogLayer.with_filter(ConnLogFilter));
        let log = ConnLog::new(Some("DEBUG1"), &[]);
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        tracing::subscriber::with_default(sub, || {
            log.span().in_scope(|| tracing::debug!(target: "russh::client", "kex packet"));
            let early = log.attach(tx);
            assert_eq!(early, vec!["debug1: kex packet"]);
            log.span().in_scope(|| {
                tracing::debug!(target: "russh::client", "status bar packet");
                tracing::warn!(target: "russh::client", "a russh warning");
            });
        });
        // Live lines went to the sink; nothing russh-debug was sent.
        let mut rx = _rx;
        let mut live = Vec::new();
        while let Ok(l) = rx.try_recv() {
            live.push(l);
        }
        assert_eq!(live, vec!["a russh warning"]);
        close(&log);
    }
}
