//! What ssh_config says about the session itself, for a session with
//! ssh_config settings: RequestTTY, RemoteCommand, SessionType, SetEnv,
//! SendEnv, StdinNull, the escape character and its command line,
//! ObscureKeystrokeTiming, ChannelTimeout and LocalCommand. Ported from
//! ssh.c, clientloop.c and channels.c.

use std::time::{Duration, Instant};

use super::sshconf::keyword::Kw;
use super::sshconf::pattern;
use super::sshconf::resolve::Options;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tty {
    Auto,
    Yes,
    No,
    Force,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionType {
    Default,
    /// No session channel: the connection only carries forwards.
    None,
    /// RemoteCommand names a subsystem (e.g. sftp).
    Subsystem,
}

#[derive(Debug, Clone)]
pub struct SessionPolicy {
    pub tty: Tty,
    /// RemoteCommand, tokens expanded.
    pub remote_command: Option<String>,
    pub session_type: SessionType,
    /// SetEnv, then the local variables SendEnv names.
    pub env: Vec<(String, String)>,
    pub stdin_null: bool,
    /// EscapeChar; `None` for `none`.
    pub escape: Option<u8>,
    pub escape_cmdline: bool,
    /// ObscureKeystrokeTiming interval; zero when off.
    pub obscure_ms: u32,
    /// LocalCommand when PermitLocalCommand is on and the user approved it.
    pub local_command: Option<String>,
    /// ChannelTimeout: (channel type pattern, idle time).
    pub channel_timeouts: Vec<(String, Duration)>,
    /// ForwardAgent, on and approved: ask for agent forwarding.
    pub agent_forward: bool,
}

impl SessionPolicy {
    /// `send_env_allowed`: SendEnv shares this computer's environment with
    /// the server, so it applies only once the user approved it.
    pub fn from_options(o: &Options, local_command: Option<String>, send_env_allowed: bool) -> SessionPolicy {
        let tty = match o.first(Kw::RequestTTY) {
            Some("yes") => Tty::Yes,
            Some("no") => Tty::No,
            Some("force") => Tty::Force,
            _ => Tty::Auto,
        };
        let session_type = match o.first(Kw::SessionType) {
            Some("none") => SessionType::None,
            Some("subsystem") => SessionType::Subsystem,
            _ => SessionType::Default,
        };
        let mut env: Vec<(String, String)> = o
            .get(Kw::SetEnv)
            .map(|s| s.args.iter().filter_map(|a| a.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect())
            .unwrap_or_default();
        // SendEnv: local variables whose names match, as ssh's
        // env_permitted; SetEnv wins for a name it already set.
        if send_env_allowed {
            for k in send_env_names(o) {
                if env.iter().any(|(n, _)| *n == k) {
                    continue;
                }
                if let Ok(v) = std::env::var(&k) {
                    env.push((k, v));
                }
            }
        }
        let escape = match o.first(Kw::EscapeChar) {
            None => Some(b'~'),
            Some("none") => None,
            Some(e) if e.len() == 2 && e.starts_with('^') => Some(e.as_bytes()[1] & 31),
            Some(e) => e.bytes().next(),
        };
        let obscure_ms = match o.first(Kw::ObscureKeystrokeTiming) {
            Some("no") => 0,
            Some(x) if x.starts_with("interval:") => x[9..].parse().unwrap_or(20),
            _ => 20,
        };
        let channel_timeouts = o
            .get(Kw::ChannelTimeout)
            .filter(|s| !s.args.first().is_some_and(|a| a.eq_ignore_ascii_case("none")))
            .map(|s| {
                s.args
                    .iter()
                    .filter_map(|a| a.split_once('='))
                    .filter_map(|(t, d)| super::sshconf::value::convtime_f(d).map(|secs| (t.to_string(), Duration::from_secs_f64(secs))))
                    .filter(|(_, d)| !d.is_zero())
                    .collect()
            })
            .unwrap_or_default();
        SessionPolicy {
            tty,
            remote_command: o.first(Kw::RemoteCommand).filter(|c| !c.eq_ignore_ascii_case("none")).map(str::to_string),
            session_type,
            env,
            stdin_null: o.first(Kw::StdinNull) == Some("yes"),
            escape,
            escape_cmdline: o.first(Kw::EnableEscapeCommandline) == Some("yes"),
            obscure_ms,
            local_command,
            channel_timeouts,
            agent_forward: false,
        }
    }

    /// Whether to ask for a terminal, as ssh.c decides: a shell gets one
    /// unless RequestTTY no; a command only when asked (yes/force). Reach's
    /// window is always a terminal, so "auto" means yes for a shell.
    pub fn wants_tty(&self, has_command: bool) -> bool {
        match self.tty {
            Tty::No => false,
            Tty::Yes | Tty::Force => self.session_type != SessionType::None,
            Tty::Auto => !has_command && self.session_type == SessionType::Default,
        }
    }

    /// ChannelTimeout for a channel type ("session", "direct-tcpip", …).
    pub fn timeout_for(&self, channel_type: &str) -> Option<Duration> {
        self.channel_timeouts
            .iter()
            .find(|(p, _)| p == "global" || pattern::match_pattern(channel_type, p))
            .map(|(_, d)| *d)
    }
}

/// The local environment variables SendEnv would send, by name, sorted.
pub fn send_env_names(o: &Options) -> Vec<String> {
    if o.send_env.is_empty() {
        return Vec::new();
    }
    let mut names: Vec<String> = std::env::vars()
        .map(|(k, _)| k)
        .filter(|k| o.send_env.iter().any(|p| pattern::match_pattern(k, p)))
        .collect();
    names.sort();
    names
}

/// How an approval of SendEnv is stored: the patterns, as one weakening.
pub fn send_env_key(o: &Options) -> String {
    super::sshconf::apply::weakening_key(Kw::SendEnv, &o.send_env.join(" "))
}

/// Open the session as the policy says. `reach_shell` is the session's own
/// login shell setting, which like a command on ssh's command line wins
/// over RemoteCommand. Returns whether a terminal was allocated.
pub async fn setup_channel(
    channel: &russh::Channel<russh::client::Msg>,
    p: &SessionPolicy,
    cols: u16,
    rows: u16,
    reach_shell: Option<&str>,
    x11: Option<&crate::ssh::x11::X11Auth>,
) -> Result<bool, String> {
    let shell = reach_shell.map(str::trim).filter(|s| !s.is_empty());
    let command = shell.map(|s| if s.split_whitespace().nth(1).is_some() { format!("exec {s}") } else { format!("exec {s} -l") }).or(p.remote_command.clone());
    let tty = p.wants_tty(command.is_some());
    if tty {
        channel
            .request_pty(false, "xterm-256color", cols as u32, rows as u32, 0, 0, &[])
            .await
            .map_err(|e| format!("PTY request failed: {e}"))?;
    }
    let _ = channel.set_env(false, "COLORTERM", "truecolor").await;
    if p.agent_forward {
        channel.agent_forward(false).await.map_err(|e| format!("Agent forwarding request failed: {e}"))?;
    }
    if let Some(a) = x11 {
        // A refusal is not fatal, as with ssh.
        if let Err(e) = channel.request_x11(false, false, a.proto.as_str(), a.fake_hex(), a.screen).await {
            tracing::warn!("X11 forwarding request failed: {e}");
        }
    }
    for (k, v) in &p.env {
        // Servers accept only what AcceptEnv lists; a refusal is not fatal,
        // as with ssh.
        let _ = channel.set_env(false, k.as_str(), v.as_str()).await;
    }
    match (p.session_type, command) {
        (SessionType::Subsystem, Some(name)) => channel.request_subsystem(false, name).await.map_err(|e| format!("Subsystem request failed: {e}"))?,
        (SessionType::Subsystem, None) => return Err("SessionType subsystem needs RemoteCommand to name the subsystem".into()),
        (_, Some(cmd)) => channel.exec(false, cmd.as_bytes()).await.map_err(|e| format!("Command failed: {e}"))?,
        (_, None) => channel.request_shell(false).await.map_err(|e| format!("Shell request failed: {e}"))?,
    }
    Ok(tty)
}

/// What a keystroke sequence asked for, besides the bytes to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscapeAction {
    /// Text to show in the terminal (escape echo, help, messages).
    Show(String),
    Disconnect,
    Break,
    Rekey,
    /// List the open channels (forwards).
    ListChannels,
    /// The ~C command line, entered.
    Command(String),
}

/// clientloop.c process_escapes: the escape character after a newline (or
/// at the start) introduces a command.
#[derive(Debug, Clone)]
pub struct Escapes {
    ch: u8,
    cmdline: bool,
    last_was_cr: bool,
    pending: bool,
    /// Collecting a ~C line.
    line: Option<Vec<u8>>,
}

impl Escapes {
    pub fn new(ch: u8, cmdline: bool) -> Self {
        Escapes { ch, cmdline, last_was_cr: true, pending: false, line: None }
    }

    fn help(&self) -> String {
        let e = self.ch as char;
        format!(
            "Supported escape sequences:\r\n {e}.   - terminate connection (and any multiplexed sessions)\r\n {e}B   - send a BREAK to the remote system\r\n {e}C   - open a command line\r\n {e}R   - request rekey\r\n {e}#   - list forwarded connections\r\n {e}?   - this message\r\n {e}{e}   - send the escape character by typing it twice\r\n(Note that escapes are only recognized immediately after newline.)\r\n"
        )
    }

    /// Feed typed bytes; returns the bytes to send and what to do.
    pub fn feed(&mut self, input: &[u8]) -> (Vec<u8>, Vec<EscapeAction>) {
        let mut out = Vec::new();
        let mut actions = Vec::new();
        for &c in input {
            if let Some(line) = self.line.as_mut() {
                match c {
                    b'\r' | b'\n' => {
                        let text = String::from_utf8_lossy(line).into_owned();
                        self.line = None;
                        actions.push(EscapeAction::Show("\r\n".into()));
                        actions.push(EscapeAction::Command(text));
                        self.last_was_cr = true;
                    }
                    0x7f | 0x08 => {
                        if line.pop().is_some() {
                            actions.push(EscapeAction::Show("\x08 \x08".into()));
                        }
                    }
                    0x03 | 0x1b => {
                        self.line = None;
                        actions.push(EscapeAction::Show("\r\n".into()));
                        self.last_was_cr = true;
                    }
                    _ => {
                        line.push(c);
                        actions.push(EscapeAction::Show((c as char).to_string()));
                    }
                }
                continue;
            }
            if self.pending {
                self.pending = false;
                let e = self.ch as char;
                match c {
                    b'.' => {
                        actions.push(EscapeAction::Show(format!("{e}.\r\n")));
                        actions.push(EscapeAction::Disconnect);
                        return (out, actions);
                    }
                    b'B' => {
                        actions.push(EscapeAction::Show(format!("{e}B\r\n")));
                        actions.push(EscapeAction::Break);
                        continue;
                    }
                    b'R' => {
                        actions.push(EscapeAction::Rekey);
                        continue;
                    }
                    b'?' => {
                        actions.push(EscapeAction::Show(self.help()));
                        continue;
                    }
                    b'#' => {
                        actions.push(EscapeAction::Show(format!("{e}#\r\n")));
                        actions.push(EscapeAction::ListChannels);
                        continue;
                    }
                    b'C' => {
                        if self.cmdline {
                            actions.push(EscapeAction::Show("\r\nssh> ".into()));
                            self.line = Some(Vec::new());
                        } else {
                            actions.push(EscapeAction::Show("commandline disabled\r\n".into()));
                        }
                        continue;
                    }
                    // ^Z (suspend), & (background), V/v (log level) belong
                    // to a terminal program's own process; Reach has none to
                    // suspend or fork.
                    0x1a | b'&' | b'V' | b'v' => {
                        let shown = if c == 0x1a { "^Z".to_string() } else { (c as char).to_string() };
                        actions.push(EscapeAction::Show(format!("{e}{shown} is not available in Reach\r\n")));
                        continue;
                    }
                    _ => {
                        if c != self.ch {
                            out.push(self.ch);
                        }
                    }
                }
            } else if self.last_was_cr && c == self.ch {
                self.pending = true;
                continue;
            }
            self.last_was_cr = c == b'\r' || c == b'\n';
            out.push(c);
        }
        (out, actions)
    }
}

/// clientloop.c obfuscate_keystroke_timing: while the user types, data goes
/// out on a jittered fixed interval, and SSH2_MSG_PING chaff fills the
/// intervals with no keystroke, for one to three seconds after the last one.
#[derive(Debug)]
pub struct Obscure {
    interval: Duration,
    active: bool,
    next: Instant,
    chaff_until: Instant,
    rate_fuzz: Duration,
    pub queued: Vec<u8>,
}

impl Obscure {
    pub fn new(interval_ms: u32) -> Self {
        let now = Instant::now();
        Obscure { interval: Duration::from_millis(interval_ms as u64), active: false, next: now, chaff_until: now, rate_fuzz: Duration::ZERO, queued: Vec::new() }
    }

    fn set_next(&mut self, now: Instant, starting: bool) {
        // SSH_KEYSTROKE_TIMING_FUZZ: 10%, centred, plus a per-burst rate fuzz.
        let fuzz = self.interval / 10;
        if starting {
            self.rate_fuzz = fuzz.mul_f64(rand::random::<f64>());
        }
        self.next = now + (self.interval - fuzz) + fuzz.mul_f64(rand::random::<f64>()) + self.rate_fuzz;
    }

    /// A keystroke to send: queued for the next interval.
    pub fn keystroke(&mut self, bytes: &[u8]) {
        let now = Instant::now();
        if !self.active {
            self.active = true;
            self.set_next(now, true);
        }
        self.queued.extend_from_slice(bytes);
        // SSH_KEYSTROKE_CHAFF_MIN_MS + random(SSH_KEYSTROKE_CHAFF_RNG_MS).
        self.chaff_until = now + Duration::from_millis(1024 + (rand::random::<u64>() % 2048));
    }

    /// At a tick: what to send now. `Some(bytes)` sends data (empty means
    /// chaff); `None` sends nothing.
    pub fn tick(&mut self, now: Instant) -> Option<Vec<u8>> {
        if !self.active || now < self.next {
            return None;
        }
        if self.queued.is_empty() && now >= self.chaff_until {
            self.active = false;
            return None;
        }
        self.set_next(now, false);
        Some(std::mem::take(&mut self.queued))
    }

    pub fn active(&self) -> bool {
        self.active
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_only_after_a_newline() {
        let mut e = Escapes::new(b'~', false);
        let (out, a) = e.feed(b"~.");
        assert!(out.is_empty());
        assert_eq!(a.last(), Some(&EscapeAction::Disconnect));
        let mut e = Escapes::new(b'~', false);
        let (out, a) = e.feed(b"ls ~.\r");
        assert_eq!(out, b"ls ~.\r");
        assert!(a.is_empty());
        let (out, _) = e.feed(b"~~x");
        assert_eq!(out, b"~x");
        let (out, a) = e.feed(b"\r~R");
        assert_eq!(out, b"\r");
        assert_eq!(a, [EscapeAction::Rekey]);
        // An unknown escape sends both characters.
        let mut e = Escapes::new(b'~', false);
        assert_eq!(e.feed(b"~q").0, b"~q");
    }

    #[test]
    fn the_command_line() {
        let mut e = Escapes::new(b'~', true);
        let (_, a) = e.feed(b"~C-L 8080:db:5432\r");
        assert!(a.contains(&EscapeAction::Command("-L 8080:db:5432".into())));
        let mut off = Escapes::new(b'~', false);
        assert!(off.feed(b"~C").1.contains(&EscapeAction::Show("commandline disabled\r\n".into())));
    }

    #[test]
    fn keystrokes_go_out_on_the_interval_then_chaff_then_stop() {
        let mut o = Obscure::new(20);
        let t0 = Instant::now();
        o.keystroke(b"a");
        assert_eq!(o.tick(t0), None, "held until the interval");
        let sent = o.tick(t0 + Duration::from_millis(40)).unwrap();
        assert_eq!(sent, b"a");
        // Nothing typed: chaff (empty data) while chaff time lasts.
        assert_eq!(o.tick(t0 + Duration::from_millis(80)), Some(Vec::new()));
        // Long after: obfuscation stops.
        assert_eq!(o.tick(t0 + Duration::from_secs(5)), None);
        assert!(!o.active());
    }

    #[test]
    fn send_env_sends_nothing_until_approved() {
        // A variable whose exact name is known: cargo sets it for tests (PATH
        // is "Path" on Windows, and SendEnv matches names as written).
        let o = Options { send_env: vec!["CARGO_PKG_NAME".into()], ..Default::default() };
        assert!(SessionPolicy::from_options(&o, None, false).env.is_empty());
        let allowed = SessionPolicy::from_options(&o, None, true);
        assert!(allowed.env.iter().any(|(k, _)| k == "CARGO_PKG_NAME") || std::env::var("CARGO_PKG_NAME").is_err());
        assert_eq!(send_env_key(&o), "SendEnv CARGO_PKG_NAME");
    }

    #[test]
    fn tty_choice_follows_ssh() {
        let mut o = Options::default();
        let at = super::super::sshconf::resolve::At { file: "f".into(), line: 1 };
        let p = SessionPolicy::from_options(&o, None, false);
        assert!(p.wants_tty(false));
        assert!(!p.wants_tty(true));
        o.single.insert(Kw::RequestTTY, super::super::sshconf::resolve::Setting { args: vec!["force".into()], at });
        assert!(SessionPolicy::from_options(&o, None, false).wants_tty(true));
    }
}
