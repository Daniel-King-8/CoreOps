//! Reading ssh_config for one host the way OpenSSH's ssh does: the user's
//! file, then the system's; `Host` and `Match` blocks; `Include`; the first
//! value obtained wins; a second, final pass when `Match final` or host
//! name canonicalisation asks for one. Ported from readconf.c and ssh.c.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::expand::{self, TokenSet, Tokens};
use super::forward::{self, Forward};
use super::keyword::{lookup, Kw, Lookup};
use super::lex::{argv_split, split_keyword};
use super::pattern::{self, ListMatch};
use super::value::{self as v, algos};

/// Where a line came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct At {
    pub file: String,
    pub line: usize,
}

/// A value as the config gave it: the arguments after checking, and where.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Setting {
    pub args: Vec<String>,
    pub at: At,
}

/// What became of one line of a config file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "detail", rename_all = "camelCase")]
pub enum Status {
    /// In force for this host.
    Applied,
    /// In a block that applies, but an earlier line already set it.
    Overridden,
    /// In a `Host` or `Match` block that does not apply to this host.
    Inactive,
    /// A `Host`, `Match` or `Include` line.
    Structure,
    /// OpenSSH refuses the line; with it in the file, ssh connects nowhere.
    Error(String),
    /// Named in IgnoreUnknown, or `Protocol`.
    Ignored,
    /// No longer does anything in OpenSSH.
    Deprecated,
    /// Refused by OpenSSH as unsupported (Kerberos v4 options and the like).
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Note {
    pub at: At,
    /// The keyword as written.
    pub keyword: String,
    pub kw: Option<Kw>,
    /// The rest of the line as written.
    pub text: String,
    pub status: Status,
}

/// A config file's contents, or where to read it.
#[derive(Debug, Clone)]
pub struct Source {
    pub path: PathBuf,
    pub text: Option<String>,
    /// The user's file (relative Includes resolve in ~/.ssh, `~` allowed),
    /// or the system's (relative to the system ssh directory).
    pub user: bool,
}

/// What the resolver needs from the machine it runs on.
pub trait Env {
    fn home(&self) -> String;
    fn local_user(&self) -> String;
    fn uid(&self) -> String;
    fn local_host(&self) -> String;
    /// The system configuration directory (/etc/ssh, %ProgramData%\ssh).
    fn system_dir(&self) -> String;
    fn read(&self, path: &Path) -> Option<String>;
    fn glob(&self, pattern: &str) -> Vec<PathBuf>;
    fn getenv(&self, name: &str) -> Option<String>;
    fn local_addresses(&self) -> Vec<std::net::IpAddr>;
    /// Run a `Match exec` command. `Err` when it may not or cannot run here
    /// (not yet approved, or a phone); the criterion then fails.
    fn exec(&self, command: &str) -> Result<bool, String>;
    /// Look a name up for canonicalisation: `Some(cname)` (possibly empty)
    /// when it resolves.
    fn resolve(&self, name: &str) -> Option<String>;
    /// The OpenSSH release `Match version` compares with.
    fn version(&self) -> String {
        "OpenSSH_10.3".into()
    }
}

/// The options in force: first value obtained wins, except the keywords
/// OpenSSH collects (IdentityFile, CertificateFile, the forwards, SendEnv).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Options {
    pub single: BTreeMap<Kw, Setting>,
    pub identity_files: Vec<Setting>,
    pub certificate_files: Vec<Setting>,
    /// LocalForward and DynamicForward, in order.
    pub local_forwards: Vec<(Forward, At)>,
    pub remote_forwards: Vec<(Forward, At)>,
    pub send_env: Vec<String>,
}

impl Options {
    pub fn get(&self, kw: Kw) -> Option<&Setting> {
        self.single.get(&kw)
    }
    pub fn first(&self, kw: Kw) -> Option<&str> {
        self.single.get(&kw).and_then(|s| s.args.first()).map(String::as_str)
    }
    fn unset(&self, kw: Kw) -> bool {
        !self.single.contains_key(&kw)
    }
    fn set(&mut self, kw: Kw, args: Vec<String>, at: &At) {
        self.single.insert(kw, Setting { args, at: at.clone() });
    }
}

/// The result for one host.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Resolved {
    /// The host name as asked for (an alias, usually).
    pub original_host: String,
    /// The host to connect to after HostName, `%h` and canonicalisation.
    pub host: String,
    pub options: Options,
    /// Every line read, in order, with what became of it. Lines of the
    /// final pass replace the first pass's notes for the same line.
    pub notes: Vec<Note>,
    /// A `RefuseConnection` that applies: ssh would stop with this message.
    pub refused: Option<String>,
    pub final_pass: bool,
}

impl Resolved {
    /// Nothing configured: Reach's own defaults.
    pub fn empty(host: &str) -> Resolved {
        Resolved { original_host: host.into(), host: host.into(), options: Options::default(), notes: vec![], refused: None, final_pass: false }
    }

    /// True when OpenSSH would refuse to use these files at all.
    pub fn has_errors(&self) -> bool {
        self.notes.iter().any(|n| matches!(n.status, Status::Error(_)))
    }
}

/// A question to answer: one host, with what `ssh` would have on its
/// command line.
#[derive(Debug, Clone, Default)]
pub struct Query {
    pub host: String,
    /// The remote command (for `Match command` and `sessiontype`).
    pub command: Option<String>,
    /// `-o`-style options given before the files are read; they win.
    pub overrides: Vec<(String, String)>,
}

const MAX_DEPTH: usize = 16;
const MAX_IDENTITY_FILES: usize = 100;
const MAX_HOSTS_FILES: usize = 32;

struct Reader<'a> {
    env: &'a dyn Env,
    opts: Options,
    notes: Vec<Note>,
    host: String,
    original_host: String,
    command: Option<String>,
    final_pass: bool,
    want_final: bool,
    refused: Option<String>,
}

/// Resolve `query.host` against the given files (user file first, then the
/// system file, as ssh reads them).
pub fn resolve(sources: &[Source], query: &Query, env: &dyn Env) -> Resolved {
    let mut r = Reader {
        env,
        opts: Options::default(),
        notes: Vec::new(),
        host: query.host.clone(),
        original_host: query.host.clone(),
        command: query.command.clone(),
        final_pass: false,
        want_final: false,
        refused: None,
    };
    for (i, (k, val)) in query.overrides.iter().enumerate() {
        let at = At { file: "command line".into(), line: i + 1 };
        let mut active = true;
        r.line(&format!("{k} {val}"), &at, &mut active, true, false, true, 0);
    }
    r.read_all(sources);
    // ssh.c: HostName takes effect (with %h), then canonicalisation.
    let mut host = query.host.clone();
    if let Some(h) = r.opts.first(Kw::Hostname) {
        let t = Tokens { host: query.host.clone(), ..Default::default() };
        if let Ok(x) = expand::expand(h, &t, TokenSet::HostnameOnly, false, &|_| None) {
            host = x;
        }
    }
    let is_addr = is_addr_fast(&host) || host.parse::<std::net::IpAddr>().is_ok();
    if !is_addr {
        host = host.to_ascii_lowercase();
    }
    let canon = r.opts.first(Kw::CanonicalizeHostname).unwrap_or("no").to_string();
    if canon != "no" && !is_addr {
        if let Some(h) = r.canonicalize(&host, &canon) {
            host = h;
        }
    }
    let want_final = r.want_final || canon != "no";
    if want_final {
        // The second pass keeps everything the first set (first value
        // wins); it fills in what is still unset, with Host now matching
        // the canonical name and `Match final`/`canonical` true.
        r.final_pass = true;
        r.host = host.clone();
        r.opts.set(Kw::Hostname, vec![host.clone()], &At { file: "canonical".into(), line: 0 });
        let first_notes = std::mem::take(&mut r.notes);
        r.read_all(sources);
        r.notes = merge_notes(first_notes, std::mem::take(&mut r.notes));
    }
    Resolved {
        original_host: query.host.clone(),
        host,
        options: r.opts,
        notes: r.notes,
        refused: r.refused,
        final_pass: want_final,
    }
}

/// After a final pass, a line's final-pass note is the one that counts,
/// except that a line applied in the first pass stays applied (its value
/// was taken then).
fn merge_notes(first: Vec<Note>, second: Vec<Note>) -> Vec<Note> {
    let mut out = second;
    for f in first {
        if let Some(n) = out.iter_mut().find(|n| n.at == f.at) {
            if f.status == Status::Applied {
                n.status = Status::Applied;
            }
        } else {
            out.push(f);
        }
    }
    out
}

fn is_addr_fast(name: &str) -> bool {
    name.contains('%') || name.contains(':') || name.bytes().all(|b| b.is_ascii_digit() || b == b'.')
}

impl Reader<'_> {
    fn read_all(&mut self, sources: &[Source]) {
        for s in sources {
            let text = match &s.text {
                Some(t) => Some(t.clone()),
                None => self.env.read(&s.path),
            };
            if let Some(text) = text {
                let mut active = true;
                self.read_text(&text, &s.path.display().to_string(), &mut active, s.user, false, 0);
            }
        }
    }

    fn read_text(&mut self, text: &str, file: &str, active: &mut bool, user: bool, never_match: bool, depth: usize) {
        // A byte order mark (PowerShell's `>` writes one) would glue itself
        // to the first keyword.
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        for (i, raw) in text.split('\n').enumerate() {
            let at = At { file: file.to_string(), line: i + 1 };
            self.line(raw, &at, active, false, never_match, user, depth);
        }
    }

    fn note(&mut self, at: &At, keyword: &str, kw: Option<Kw>, text: &str, status: Status) {
        self.notes.push(Note { at: at.clone(), keyword: keyword.to_string(), kw, text: text.to_string(), status });
    }

    /// Match-context host: HostName with %h, or the canonical name.
    fn match_host(&self) -> String {
        if self.final_pass {
            return self.opts.first(Kw::Hostname).unwrap_or(&self.host).to_string();
        }
        match self.opts.first(Kw::Hostname) {
            Some(h) => {
                let t = Tokens { host: self.host.clone(), ..Default::default() };
                expand::expand(h, &t, TokenSet::HostnameOnly, false, &|_| None).unwrap_or_else(|_| self.host.clone())
            }
            None => self.host.clone(),
        }
    }

    /// Tokens for `Match exec` and `Include`.
    fn tokens(&self) -> Tokens {
        let host = self.match_host();
        let port = self.opts.first(Kw::Port).unwrap_or("22").to_string();
        let local_user = self.env.local_user();
        let ruser = self.opts.first(Kw::User).map(str::to_string).unwrap_or_else(|| local_user.clone());
        let local_host = self.env.local_host();
        let jump = self.opts.first(Kw::ProxyJump).filter(|j| !j.eq_ignore_ascii_case("none")).unwrap_or("").to_string();
        Tokens {
            conn_hash: expand::connection_hash(&local_host, &host, &port, &ruser, &jump),
            short_local: local_host.split('.').next().unwrap_or("").to_string(),
            home: self.env.home(),
            key_alias: self.opts.first(Kw::HostKeyAlias).unwrap_or(&host).to_string(),
            host,
            local_host,
            original_host: self.original_host.clone(),
            port,
            remote_user: ruser,
            local_user,
            uid: self.env.uid(),
            jump,
            tunnel: None,
            known_hosts: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn line(&mut self, raw: &str, at: &At, active: &mut bool, cmdline: bool, never_match: bool, user: bool, depth: usize) {
        let Some(l) = split_keyword(raw) else { return };
        let keyword = l.keyword.clone();
        let rest = l.rest.clone();
        if rest.is_empty() {
            self.note(at, &keyword, None, "", Status::Error(format!("no argument after keyword \"{}\"", keyword.to_ascii_lowercase())));
            return;
        }
        let found = lookup(&keyword);
        let kw = match found {
            Lookup::Known(k) => k,
            Lookup::Ignored => return self.note(at, &keyword, None, &rest, Status::Ignored),
            Lookup::Deprecated => return self.note(at, &keyword, None, &rest, Status::Deprecated),
            Lookup::Unsupported => return self.note(at, &keyword, None, &rest, Status::Unsupported),
            Lookup::Unknown => {
                // IgnoreUnknown, as set so far, lets an unknown keyword pass.
                let ignored = self
                    .opts
                    .first(Kw::IgnoreUnknown)
                    .is_some_and(|list| pattern::match_pattern_list(&keyword.to_ascii_lowercase(), list, true) == ListMatch::Match);
                let status = if ignored { Status::Ignored } else { Status::Error(format!("Bad configuration option: {}", keyword.to_ascii_lowercase())) };
                return self.note(at, &keyword, None, &rest, status);
            }
        };
        let args = match argv_split(&rest) {
            Ok(a) => a,
            Err(e) => return self.note(at, &keyword, Some(kw), &rest, Status::Error(e)),
        };
        let was_active = *active;
        let outcome = self.apply(kw, args, &rest, at, active, cmdline, never_match, user, depth);
        let status = match outcome {
            Err(e) => Status::Error(e),
            Ok(Outcome::Structure) => Status::Structure,
            Ok(Outcome::Set) => Status::Applied,
            Ok(Outcome::Kept) if was_active => Status::Overridden,
            Ok(Outcome::Kept) => Status::Inactive,
        };
        self.note(at, &keyword, Some(kw), &rest, status);
    }
}

enum Outcome {
    /// The value was taken.
    Set,
    /// Valid, but not taken (inactive block, or already set).
    Kept,
    Structure,
}

fn one(args: &[String], what: &str) -> Result<String, String> {
    match args.first() {
        Some(a) if !a.is_empty() => Ok(a.clone()),
        _ => Err(format!("Missing {what}argument.")),
    }
}

impl Reader<'_> {
    /// One keyword. Mirrors the switch in process_config_line_depth.
    #[allow(clippy::too_many_arguments)]
    fn apply(
        &mut self,
        kw: Kw,
        args: Vec<String>,
        rest: &str,
        at: &At,
        active: &mut bool,
        cmdline: bool,
        never_match: bool,
        user: bool,
        depth: usize,
    ) -> Result<Outcome, String> {
        let on = *active;
        // Most keywords: one checked value, first wins.
        let first_wins = |r: &mut Self, value: Vec<String>| -> Outcome {
            if on && r.opts.unset(kw) {
                r.opts.set(kw, value, at);
                Outcome::Set
            } else {
                Outcome::Kept
            }
        };
        let extra = |n: usize| -> Result<(), String> {
            if args.len() > n {
                Err(format!("keyword {} extra arguments at end of line", kw.name().to_ascii_lowercase()))
            } else {
                Ok(())
            }
        };
        use Kw::*;
        let words = |w: v::Words| -> Result<Vec<String>, String> {
            extra(1)?;
            Ok(vec![v::multistate(args.first().map(String::as_str), w)?.to_string()])
        };
        let outcome = match kw {
            Host => {
                if cmdline {
                    return Err("Host directive not supported as a command-line option".into());
                }
                *active = false;
                for a in &args {
                    if a.is_empty() {
                        return Err("keyword host empty argument".into());
                    }
                    if never_match {
                        break;
                    }
                    let (neg, pat) = match a.strip_prefix('!') {
                        Some(p) => (true, p),
                        None => (false, a.as_str()),
                    };
                    if pattern::match_pattern(&self.host, pat) {
                        if neg {
                            *active = false;
                            break;
                        }
                        *active = true;
                    }
                }
                Outcome::Structure
            }
            Match => {
                if cmdline {
                    return Err("Match directive not supported as a command-line option".into());
                }
                let r = self.match_line(&args)?;
                *active = !never_match && r;
                Outcome::Structure
            }
            Include => {
                if cmdline {
                    return Err("Include directive not supported as a command-line option".into());
                }
                self.include(&args, at, active, user, never_match, depth)?;
                Outcome::Structure
            }
            // Flags.
            ForwardX11 | ForwardX11Trusted | GatewayPorts | ExitOnForwardFailure | PasswordAuthentication
            | KbdInteractiveAuthentication | HostbasedAuthentication | GSSAPIAuthentication
            | GSSAPIDelegateCredentials | BatchMode | CheckHostIP | NoHostAuthenticationForLocalhost
            | ClearAllForwardings | HashKnownHosts | PermitLocalCommand | VisualHostKey | StdinNull
            | ForkAfterAuthentication | ProxyUseFdpass | CanonicalizeFallbackLocal | StreamLocalBindUnlink
            | EnableSSHKeysign | IdentitiesOnly | EnableEscapeCommandline | UseKeychain | GSSAPIKeyExchange
            | GSSAPIRenewalForcesRekey | GSSAPITrustDns => {
                let value = words(v::FLAG)?;
                first_wins(self, value)
            }
            VerifyHostKeyDNS | UpdateHostKeys => {
                let value = words(v::YES_NO_ASK)?;
                first_wins(self, value)
            }
            StrictHostKeyChecking => {
                let value = words(v::STRICT_HOST_KEY)?;
                first_wins(self, value)
            }
            Compression => {
                let value = words(v::COMPRESSION)?;
                first_wins(self, value)
            }
            TCPKeepAlive => {
                let value = words(v::KEEPALIVES)?;
                first_wins(self, value)
            }
            PubkeyAuthentication => {
                let value = words(v::PUBKEY_AUTH)?;
                first_wins(self, value)
            }
            AddressFamily => {
                let value = words(v::ADDRESS_FAMILY)?;
                first_wins(self, value)
            }
            ControlMaster => {
                let value = words(v::CONTROL_MASTER)?;
                first_wins(self, value)
            }
            Tunnel => {
                let value = words(v::TUNNEL)?;
                first_wins(self, value)
            }
            RequestTTY => {
                let value = words(v::REQUEST_TTY)?;
                first_wins(self, value)
            }
            SessionType => {
                let value = words(v::SESSION_TYPE)?;
                first_wins(self, value)
            }
            CanonicalizeHostname => {
                let value = words(v::CANONICALIZE)?;
                first_wins(self, value)
            }
            WarnWeakCrypto => {
                let value = words(v::WARN_WEAK_CRYPTO)?;
                first_wins(self, value)
            }
            ForwardAgent => {
                extra(1)?;
                let a = one(&args, "")?;
                match v::multistate(Some(&a), v::FLAG) {
                    Ok(w) => first_wins(self, vec![w.to_string()]),
                    // Not yes or no: a socket path (or $VAR) to forward.
                    Err(_) => {
                        agent_path(&a, self.env)?;
                        first_wins(self, vec![a])
                    }
                }
            }
            IdentityAgent => {
                extra(1)?;
                let a = one(&args, "")?;
                agent_path(&a, self.env)?;
                first_wins(self, vec![a])
            }
            // Times.
            ConnectTimeout | ForwardX11Timeout | ServerAliveInterval => {
                extra(1)?;
                let a = args.first().filter(|a| !a.is_empty()).ok_or("missing time value.")?;
                if a == "none" {
                    // "none" is OpenSSH's "unset" (-1): it takes nothing,
                    // so a later line can still set the value.
                    return Ok(if on { Outcome::Set } else { Outcome::Kept });
                }
                if v::convtime(a).is_none() {
                    return Err("invalid time value.".into());
                }
                first_wins(self, vec![a.clone()])
            }
            // Integers.
            ConnectionAttempts | NumberOfPasswordPrompts | ServerAliveCountMax | CanonicalizeMaxDots
            | RequiredRSASize => {
                extra(1)?;
                let n = v::atoi(args.first().map(String::as_str))?;
                first_wins(self, vec![n.to_string()])
            }
            Port => {
                extra(1)?;
                let a = one(&args, "")?;
                let p = v::port(&a).filter(|p| *p > 0).ok_or(format!("Bad port '{a}'."))?;
                first_wins(self, vec![p.to_string()])
            }
            // Strings.
            User | Hostname | Tag | HostKeyAlias | PreferredAuthentications | BindAddress | BindInterface
            | PKCS11Provider | SecurityKeyProvider | XAuthLocation | KbdInteractiveDevices | IgnoreUnknown
            | ControlPath | GSSAPIClientIdentity | GSSAPIServerIdentity => {
                extra(1)?;
                let a = one(&args, "")?;
                first_wins(self, vec![a])
            }
            GSSAPIKexAlgorithms => {
                extra(1)?;
                let a = one(&args, "")?;
                if !crate::ssh::gssapi::kex_names_valid(&a) {
                    return Err(format!("Bad GSSAPI KexAlgorithms '{a}'."));
                }
                first_wins(self, vec![a])
            }
            // Commands: the rest of the line, as written.
            ProxyCommand | KnownHostsCommand | LocalCommand | RemoteCommand => {
                let cmd = rest.trim_start_matches([' ', '\t', '=']).to_string();
                if kw == ProxyCommand {
                    // ProxyJump set first leaves ProxyCommand "none".
                    if on && self.opts.unset(ProxyCommand) {
                        self.opts.set(ProxyCommand, vec![cmd], at);
                        Outcome::Set
                    } else {
                        Outcome::Kept
                    }
                } else {
                    first_wins(self, vec![cmd])
                }
            }
            ProxyJump => {
                let spec = rest.trim_start_matches([' ', '\t', '=']);
                let spec = spec.split('#').next().unwrap_or("").trim_end();
                if spec.eq_ignore_ascii_case("none") {
                    if on && self.opts.unset(ProxyJump) {
                        self.opts.set(ProxyJump, vec!["none".into()], at);
                        Outcome::Set
                    } else {
                        Outcome::Kept
                    }
                } else {
                    for hop in spec.split(',') {
                        jump_hop(hop)?;
                    }
                    if on && self.opts.unset(ProxyCommand) && self.opts.unset(ProxyJump) {
                        self.opts.set(ProxyJump, vec![spec.to_string()], at);
                        self.opts.set(ProxyCommand, vec!["none".into()], at);
                        Outcome::Set
                    } else {
                        Outcome::Kept
                    }
                }
            }
            // Algorithm lists.
            Ciphers | MACs | KexAlgorithms | HostKeyAlgorithms | CASignatureAlgorithms
            | HostbasedAcceptedAlgorithms | PubkeyAcceptedAlgorithms => {
                extra(1)?;
                let a = one(&args, "")?;
                let known = match kw {
                    Ciphers => algos::CIPHERS,
                    MACs => algos::MACS,
                    KexAlgorithms => algos::KEX,
                    CASignatureAlgorithms => algos::CA_SIGS,
                    _ => algos::KEYS,
                };
                v::algo_list(&a, known).map_err(|e| format!("Bad SSH2 {} spec '{a}': {e}", kw.name()))?;
                first_wins(self, vec![a])
            }
            LogLevel => {
                extra(1)?;
                let a = args.first().cloned().unwrap_or_default();
                if !v::LOG_LEVELS.iter().any(|l| l.eq_ignore_ascii_case(&a)) {
                    return Err(format!("unsupported log level '{a}'"));
                }
                first_wins(self, vec![a.to_ascii_uppercase()])
            }
            SyslogFacility => {
                extra(1)?;
                let a = args.first().cloned().unwrap_or_default();
                if !v::SYSLOG_FACILITIES.iter().any(|l| l.eq_ignore_ascii_case(&a)) {
                    return Err(format!("unsupported log facility '{a}'"));
                }
                // OpenSSH sets this one whether or not the block applies.
                if self.opts.unset(kw) {
                    self.opts.set(kw, vec![a.to_ascii_uppercase()], at);
                    Outcome::Set
                } else {
                    Outcome::Kept
                }
            }
            RekeyLimit => {
                extra(2)?;
                let a = one(&args, "")?;
                if a != "default" {
                    let n = v::scaled(&a).ok_or(format!("Bad number '{a}'"))?;
                    if n != 0 && n < 16 {
                        return Err("RekeyLimit too small".into());
                    }
                }
                if let Some(t) = args.get(1) {
                    if t != "none" && v::convtime(t).is_none() {
                        return Err("invalid time value.".into());
                    }
                }
                first_wins(self, args.clone())
            }
            EscapeChar => {
                extra(1)?;
                let a = one(&args, "")?;
                let b = a.as_bytes();
                let ok = a == "none" || b.len() == 1 || (b.len() == 2 && b[0] == b'^' && (64..128).contains(&b[1]));
                if !ok {
                    return Err("Bad escape character.".into());
                }
                first_wins(self, vec![a])
            }
            IdentityFile | CertificateFile => {
                extra(1)?;
                let a = one(&args, "")?;
                if on {
                    let list = if kw == IdentityFile { &mut self.opts.identity_files } else { &mut self.opts.certificate_files };
                    if list.len() >= MAX_IDENTITY_FILES {
                        return Err("Too many identity files specified (max 100).".into());
                    }
                    // add_identity_file skips a file already listed.
                    if !list.iter().any(|s| s.args[0] == a) {
                        list.push(Setting { args: vec![a], at: at.clone() });
                    }
                    Outcome::Set
                } else {
                    Outcome::Kept
                }
            }
            GlobalKnownHostsFile | UserKnownHostsFile | RevokedHostKeys | LogVerbose => {
                if args.is_empty() {
                    return Err(format!("no {} specified", kw.name()));
                }
                for (i, a) in args.iter().enumerate() {
                    if a.is_empty() {
                        return Err(format!("keyword {} empty argument", kw.name().to_ascii_lowercase()));
                    }
                    if a.eq_ignore_ascii_case("none") && (i > 0 || args.len() > 1) {
                        return Err(format!("keyword {} \"none\" argument must appear alone.", kw.name().to_ascii_lowercase()));
                    }
                }
                if matches!(kw, GlobalKnownHostsFile | UserKnownHostsFile) && args.len() > MAX_HOSTS_FILES {
                    return Err(format!("too many {} entries.", kw.name().to_ascii_lowercase()));
                }
                first_wins(self, args.clone())
            }
            CanonicalDomains => {
                if args.is_empty() {
                    return Err("no CanonicalDomains specified".into());
                }
                let mut out = Vec::new();
                for (i, a) in args.iter().enumerate() {
                    if a.eq_ignore_ascii_case("none") && (i > 0 || args.len() > 1) {
                        return Err("keyword canonicaldomains \"none\" argument must appear alone.".into());
                    }
                    out.push(v::domain(a)?);
                }
                first_wins(self, out)
            }
            CanonicalizePermittedCNAMEs => {
                if args.is_empty() {
                    return Err("no CanonicalizePermittedCNAMEs specified".into());
                }
                let mut out = Vec::new();
                for (i, a) in args.iter().enumerate() {
                    if a.eq_ignore_ascii_case("none") {
                        if i > 0 || args.len() > 1 {
                            return Err("keyword canonicalizepermittedcnames \"none\" argument must appear alone.".into());
                        }
                        out.push("none".to_string());
                    } else if a == "*" {
                        out.push("*".to_string());
                    } else {
                        let lower = a.to_ascii_lowercase();
                        match lower.split_once(':') {
                            Some((_, t)) if !t.is_empty() => out.push(lower.clone()),
                            _ => return Err(format!("Invalid permitted CNAME \"{a}\"")),
                        }
                    }
                }
                first_wins(self, out)
            }
            ChannelTimeout => {
                if args.is_empty() {
                    return Err("no ChannelTimeout specified".into());
                }
                for (i, a) in args.iter().enumerate() {
                    if a.eq_ignore_ascii_case("none") {
                        if i > 0 || args.len() > 1 {
                            return Err("keyword channeltimeout \"none\" argument must appear alone.".into());
                        }
                    } else {
                        let ok = a.split_once('=').is_some_and(|(t, s)| !t.is_empty() && v::convtime_f(s).is_some());
                        if !ok {
                            return Err(format!("invalid channel timeout {a}"));
                        }
                    }
                }
                first_wins(self, args.clone())
            }
            PermitRemoteOpen => {
                if args.is_empty() {
                    return Err("missing PermitRemoteOpen specification".into());
                }
                for (i, a) in args.iter().enumerate() {
                    if a.eq_ignore_ascii_case("none") || a.eq_ignore_ascii_case("any") {
                        if i > 0 || args.len() > 1 {
                            return Err(format!("keyword permitremoteopen \"{a}\" argument must appear alone."));
                        }
                    } else {
                        let (_, port) = split_host_port(a).ok_or("missing host in PermitRemoteOpen")?;
                        if port != "*" && v::port(&port).is_none_or(|p| p == 0) {
                            return Err("bad port number in PermitRemoteOpen".into());
                        }
                    }
                }
                first_wins(self, args.clone())
            }
            SendEnv => {
                if args.is_empty() {
                    return Err("no SendEnv specified".into());
                }
                for a in &args {
                    if a.is_empty() || a.contains('=') {
                        return Err("Invalid environment name.".into());
                    }
                }
                if !on {
                    return Ok(Outcome::Kept);
                }
                // SendEnv adds to the list wherever it appears; `-NAME`
                // takes matching names off it.
                for a in &args {
                    if let Some(pat) = a.strip_prefix('-') {
                        self.opts.send_env.retain(|e| !pattern::match_pattern(e, pat));
                    } else {
                        self.opts.send_env.push(a.clone());
                    }
                }
                Outcome::Set
            }
            SetEnv => {
                if args.is_empty() {
                    return Err("no SetEnv specified".into());
                }
                let mut out: Vec<String> = Vec::new();
                for a in &args {
                    let Some((name, _)) = a.split_once('=') else {
                        return Err("Invalid SetEnv.".into());
                    };
                    // A name repeated on the line: the first one counts.
                    if !out.iter().any(|o| o.split_once('=').is_some_and(|(n, _)| n == name)) {
                        out.push(a.clone());
                    }
                }
                first_wins(self, out)
            }
            LocalForward | RemoteForward | DynamicForward => {
                let a = one(&args, "")?;
                let remote = kw == RemoteForward;
                let mut dynamic = kw == DynamicForward;
                let spec = if dynamic {
                    extra(1)?;
                    a.clone()
                } else {
                    extra(2)?;
                    match args.get(1).filter(|s| !s.is_empty()) {
                        Some(b) => format!("{a}:{b}"),
                        None if remote => {
                            dynamic = true;
                            a.clone()
                        }
                        None => return Err("Missing target argument.".into()),
                    }
                };
                // parse_forward expands ${VAR} (not % tokens) first, so a
                // variable holding a path makes it a socket forward.
                let expanded = expand::dollar(&spec, &|n| self.env.getenv(n)).map_err(|_| "Bad forwarding specification.")?;
                let fwd = forward::parse(&expanded, dynamic, remote).ok_or("Bad forwarding specification.")?;
                if on {
                    if remote {
                        // add_remote_forward drops an exact duplicate.
                        if !self.opts.remote_forwards.iter().any(|(f, _)| *f == fwd) {
                            self.opts.remote_forwards.push((fwd, at.clone()));
                        }
                    } else if !self.opts.local_forwards.iter().any(|(f, _)| *f == fwd) {
                        self.opts.local_forwards.push((fwd, at.clone()));
                    }
                    Outcome::Set
                } else {
                    Outcome::Kept
                }
            }
            ControlPersist => {
                extra(1)?;
                let a = one(&args, "ControlPersist ")?;
                let ok = matches!(a.as_str(), "no" | "false" | "yes" | "true") || v::convtime(&a).is_some();
                if !ok {
                    return Err("Bad ControlPersist argument.".into());
                }
                first_wins(self, vec![a])
            }
            TunnelDevice => {
                extra(1)?;
                let a = one(&args, "")?;
                if !v::tunnel_device(&a) {
                    return Err("Bad tun device.".into());
                }
                first_wins(self, vec![a])
            }
            IPQoS => {
                extra(2)?;
                let a = args.first().cloned().unwrap_or_default();
                if !v::ipqos(&a) {
                    return Err(format!("Bad IPQoS value: {a}"));
                }
                if let Some(b) = args.get(1) {
                    if !v::ipqos(b) {
                        return Err(format!("Bad IPQoS value: {b}"));
                    }
                }
                first_wins(self, args.clone())
            }
            StreamLocalBindMask => {
                extra(1)?;
                let a = one(&args, "StreamLocalBindMask ")?;
                // strtol(arg, &end, 8): the leading octal digits count.
                let digits: String = a.trim_start().chars().take_while(|c| ('0'..='7').contains(c)).collect();
                match u32::from_str_radix(&digits, 8) {
                    Ok(m) if m <= 0o777 => {}
                    _ => return Err("Bad mask.".into()),
                }
                // OpenSSH sets this one wherever it appears, last one
                // winning, applying or not.
                self.opts.set(kw, vec![a], at);
                Outcome::Set
            }
            FingerprintHash => {
                extra(1)?;
                let a = one(&args, "")?;
                if !v::DIGESTS.iter().any(|d| d.eq_ignore_ascii_case(&a)) {
                    return Err(format!("Invalid hash algorithm \"{a}\"."));
                }
                first_wins(self, vec![a.to_ascii_lowercase()])
            }
            AddKeysToAgent => {
                let a = args.first().cloned().unwrap_or_default();
                let b = args.get(1);
                extra(2)?;
                let word = v::multistate(Some(&a), v::YES_NO_ASK_CONFIRM).ok();
                let value = match (word, b) {
                    (Some("confirm"), Some(t)) => {
                        v::convtime(t).ok_or("invalid time value.")?;
                        vec!["confirm".into(), t.clone()]
                    }
                    (None, None) => {
                        v::convtime(&a).ok_or("unsupported option")?;
                        vec!["yes".into(), a.clone()]
                    }
                    (Some(w), None) => vec![w.to_string()],
                    _ => return Err("unsupported option".into()),
                };
                first_wins(self, value)
            }
            ObscureKeystrokeTiming => {
                extra(1)?;
                let a = args.first().cloned().ok_or("missing argument")?;
                let value = match a.as_str() {
                    "yes" | "true" => "yes".to_string(),
                    "no" | "false" => "no".to_string(),
                    x if x.starts_with("interval:") => {
                        let n = v::atoi(Some(&x[9..]))?;
                        if !(1..=1000).contains(&n) {
                            return Err("value out of range.".into());
                        }
                        x.to_string()
                    }
                    _ => return Err(format!("unsupported argument \"{a}\"")),
                };
                first_wins(self, vec![value])
            }
            VersionAddendum => {
                let text = rest.trim_start_matches([' ', '\t']);
                if text.contains('\r') {
                    return Err("Invalid VersionAddendum argument".into());
                }
                let text = text.split('#').next().unwrap_or("").trim_end().to_string();
                let value = if text.eq_ignore_ascii_case("none") { String::new() } else { text };
                return Ok(first_wins(self, vec![value]));
            }
            RefuseConnection => {
                let a = one(&args, "")?;
                if on && self.refused.is_none() {
                    self.refused = Some(a.clone());
                }
                if on { Outcome::Set } else { Outcome::Kept }
            }
        };
        // VersionAddendum, ProxyCommand and the like take the whole rest of
        // the line; every other keyword must have used all its arguments.
        Ok(outcome)
    }

    /// `match_cfg_line`: true when the criteria all hold.
    fn match_line(&mut self, args: &[String]) -> Result<bool, String> {
        let host = self.match_host();
        let ruser = self.opts.first(Kw::User).map(str::to_string).unwrap_or_else(|| self.env.local_user());
        let mut result = true;
        let mut attributes = 0;
        let mut i = 0;
        while i < args.len() {
            let raw = &args[i];
            i += 1;
            if raw.starts_with('#') {
                break;
            }
            let (negate, attr) = match raw.strip_prefix('!') {
                Some(a) => (true, a),
                None => (false, raw.as_str()),
            };
            let lower = attr.to_ascii_lowercase();
            if lower == "all" {
                let more = args.get(i).is_some_and(|a| !a.is_empty() && !a.starts_with('#'));
                if attributes > 1 || more {
                    return Err(format!("'{raw}' cannot be combined with other Match attributes"));
                }
                if result {
                    result = !negate;
                }
                return Ok(result);
            }
            attributes += 1;
            if lower == "canonical" || lower == "final" {
                if lower == "final" && !negate {
                    self.want_final = true;
                }
                if self.final_pass == negate {
                    result = false;
                }
                continue;
            }
            const WITH_EQ: &[&str] = &["host", "originalhost", "user", "localuser", "localnetwork", "version", "tagged", "command", "exec"];
            let (name, arg) = match lower.split_once('=') {
                Some((n, _)) if WITH_EQ.contains(&n) => (n.to_string(), attr[n.len() + 1..].to_string()),
                _ => {
                    let a = args.get(i).cloned().ok_or(format!("missing argument for Match '{raw}'"))?;
                    i += 1;
                    (lower.clone(), a)
                }
            };
            if (arg.is_empty() && name != "tagged" && name != "command") || arg.starts_with('#') {
                return Err(format!("Missing Match criteria for {name}"));
            }
            let hit = match name.as_str() {
                "host" => pattern::match_hostname(&host, &arg) == ListMatch::Match,
                "originalhost" => pattern::match_hostname(&self.original_host, &arg) == ListMatch::Match,
                "user" => pattern::match_pattern_list(&ruser, &arg, false) == ListMatch::Match,
                "localuser" => pattern::match_pattern_list(&self.env.local_user(), &arg, false) == ListMatch::Match,
                "localnetwork" => {
                    let nets = pattern::parse_cidr_list(&arg)?;
                    self.env.local_addresses().iter().any(|a| nets.iter().any(|n| n.contains(*a)))
                }
                "version" => pattern::match_pattern_list(&self.env.version(), &arg, false) == ListMatch::Match,
                "tagged" => {
                    let tag = self.opts.first(Kw::Tag).unwrap_or("");
                    if tag.is_empty() { arg.is_empty() } else { pattern::match_pattern_list(tag, &arg, false) == ListMatch::Match }
                }
                "command" => {
                    let cmd = self.command.clone().unwrap_or_default();
                    if cmd.is_empty() { arg.is_empty() } else { pattern::match_pattern_list(&cmd, &arg, false) == ListMatch::Match }
                }
                "sessiontype" => {
                    let st = match self.opts.first(Kw::SessionType) {
                        Some("subsystem") => "subsystem",
                        Some("none") => "none",
                        _ if self.command.as_deref().is_some_and(|c| !c.is_empty()) => "exec",
                        _ => "shell",
                    };
                    pattern::match_pattern_list(st, &arg, false) == ListMatch::Match
                }
                "exec" => {
                    let cmd = expand::expand(&arg, &self.tokens(), TokenSet::Default, false, &|_| None)
                        .map_err(|e| format!("failed to expand match exec '{arg}': {e}"))?;
                    if !result {
                        // A criterion already failed: the command is not run.
                        continue;
                    }
                    self.env.exec(&cmd).unwrap_or(false)
                }
                _ => return Err(format!("Unsupported Match attribute {name}")),
            };
            if hit == negate {
                result = false;
            }
        }
        if attributes == 0 {
            return Err("One or more attributes required for Match".into());
        }
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    fn include(&mut self, args: &[String], at: &At, active: &mut bool, user: bool, never_match: bool, depth: usize) -> Result<(), String> {
        if args.is_empty() {
            return Err("no argument after keyword \"include\"".into());
        }
        if depth >= MAX_DEPTH {
            return Err("Too many recursive configuration includes".into());
        }
        for a in args {
            if a.is_empty() {
                return Err("keyword include empty argument".into());
            }
            let toks = self.tokens();
            let p = match expand::expand(a, &toks, TokenSet::Default, true, &|n| self.env.getenv(n)) {
                Ok(p) => p,
                Err(e) => {
                    self.note(at, "Include", Some(Kw::Include), a, Status::Error(format!("Unable to expand user config file '{a}': {e}")));
                    continue;
                }
            };
            if p.starts_with('~') && !user {
                return Err(format!("bad include path {p}."));
            }
            let anchored = if is_absolute(&p) || p.starts_with('~') {
                p.clone()
            } else if user {
                format!("~/.ssh/{p}")
            } else {
                format!("{}/{p}", self.env.system_dir())
            };
            let pattern = expand::tilde(&anchored, &self.env.home());
            let mut files = self.env.glob(&pattern);
            files.sort();
            let outer = *active;
            for f in files {
                let Some(text) = self.env.read(&f) else { continue };
                self.read_text(&text, &f.display().to_string(), active, user, never_match || !outer, depth + 1);
                // A Match inside the included file does not change the
                // including file's state.
                *active = outer;
            }
        }
        Ok(())
    }

    /// resolve_canonicalize: try each CanonicalDomains suffix.
    fn canonicalize(&self, host: &str, mode: &str) -> Option<String> {
        let direct = self.opts.first(Kw::ProxyCommand).is_none_or(|c| c.eq_ignore_ascii_case("none"))
            && self.opts.first(Kw::ProxyJump).is_none_or(|j| j.eq_ignore_ascii_case("none"));
        if !direct && mode != "always" {
            return None;
        }
        let cnames = self.opts.get(Kw::CanonicalizePermittedCNAMEs).map(|s| s.args.clone()).unwrap_or_default();
        let follow = |name: &str, cname: &str| -> String {
            if cname.is_empty() || name == cname || cnames.is_empty() || cnames == ["none"] {
                return name.to_string();
            }
            for rule in &cnames {
                let (src, dst) = if rule == "*" { ("*", "*") } else { rule.split_once(':').unwrap_or(("", "")) };
                if pattern::match_pattern_list(name, src, true) == ListMatch::Match
                    && pattern::match_pattern_list(cname, dst, true) == ListMatch::Match
                {
                    return cname.to_ascii_lowercase();
                }
            }
            name.to_string()
        };
        if let Some(stripped) = host.strip_suffix('.') {
            return self.env.resolve(host).map(|c| follow(stripped, &c));
        }
        let max_dots: usize = self.opts.first(Kw::CanonicalizeMaxDots).and_then(|n| n.parse().ok()).unwrap_or(1);
        if host.matches('.').count() > max_dots {
            return None;
        }
        let domains = self.opts.get(Kw::CanonicalDomains).map(|s| s.args.clone()).unwrap_or_default();
        for d in domains {
            if d.eq_ignore_ascii_case("none") {
                break;
            }
            let full = format!("{host}.{d}.");
            if let Some(cname) = self.env.resolve(&full) {
                return Some(follow(&full[..full.len() - 1], &cname));
            }
        }
        None
    }
}

fn is_absolute(p: &str) -> bool {
    p.starts_with('/') || p.starts_with('\\') || (p.len() > 2 && p.as_bytes()[1] == b':')
}

/// Check an IdentityAgent / ForwardAgent path's `$VAR` forms, as OpenSSH does.
fn agent_path(a: &str, env: &dyn Env) -> Result<(), String> {
    if a.contains("${") {
        expand::expand(a, &Tokens::default(), TokenSet::Default, true, &|n| env.getenv(n).or(Some(String::new())))
            .map_err(|_| format!("Invalid environment expansion {a}."))?;
    }
    if let Some(name) = a.strip_prefix('$') {
        if !name.starts_with('{') && !v::env_name(name) {
            return Err(format!("Invalid environment name {a}."));
        }
    }
    Ok(())
}

/// `[user@]host[:port]` or `ssh://[user@]host[:port]`.
pub fn jump_hop(hop: &str) -> Result<(Option<String>, String, Option<u16>), String> {
    let hop = hop.trim();
    let s = hop.strip_prefix("ssh://").unwrap_or(hop);
    let s = s.strip_suffix('/').unwrap_or(s);
    let (user, hostport) = match s.rsplit_once('@') {
        Some((u, h)) => (Some(u.to_string()), h),
        None => (None, s),
    };
    let (host, port) = split_host_port(hostport).ok_or(format!("Invalid ProxyJump \"{hop}\""))?;
    let port = if port.is_empty() {
        None
    } else {
        Some(v::port(&port).filter(|p| *p > 0).ok_or(format!("Invalid ProxyJump \"{hop}\""))?)
    };
    // From a file, OpenSSH checks only the form of a hop (parse_jump is
    // strict for the command line alone).
    if host.is_empty() {
        return Err(format!("Invalid ProxyJump \"{hop}\""));
    }
    Ok((user, host, port))
}

/// `host`, `host:port`, `[v6]` or `[v6]:port`. The port is empty when none.
fn split_host_port(s: &str) -> Option<(String, String)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (h, after) = rest.split_once(']')?;
        let port = match after {
            "" => String::new(),
            p => p.strip_prefix(':')?.to_string(),
        };
        return Some((h.to_string(), port));
    }
    match s.split_once(':') {
        Some((h, p)) if !p.contains(':') => Some((h.to_string(), p.to_string())),
        Some(_) => None,
        None => Some((s.to_string(), String::new())),
    }
}

impl Resolved {
    /// The tokens for this connection, as ssh.c sets them up after the
    /// config is read (`cinfo`).
    pub fn tokens(&self, env: &dyn Env) -> Tokens {
        let local_host = env.local_host();
        let port = self.options.first(Kw::Port).unwrap_or("22").to_string();
        let local_user = env.local_user();
        let remote_user = self.options.first(Kw::User).map(str::to_string).unwrap_or_else(|| local_user.clone());
        let jump = self.options.first(Kw::ProxyJump).filter(|j| !j.eq_ignore_ascii_case("none")).map(jump_host_of).unwrap_or_default();
        Tokens {
            conn_hash: expand::connection_hash(&local_host, &self.host, &port, &remote_user, &jump),
            short_local: local_host.split('.').next().unwrap_or("").to_string(),
            home: env.home(),
            key_alias: self.options.first(Kw::HostKeyAlias).map(str::to_string).unwrap_or_else(|| self.original_host.clone()),
            host: self.host.clone(),
            local_host,
            original_host: self.original_host.clone(),
            port,
            remote_user,
            local_user,
            uid: env.uid(),
            jump,
            tunnel: None,
            known_hosts: None,
        }
    }

    /// The expansions ssh.c makes once the config is read: `%` tokens and
    /// `${VAR}` in User, RemoteCommand, ControlPath, IdentityAgent,
    /// RevokedHostKeys, the ForwardAgent socket, VersionAddendum,
    /// UserKnownHostsFile, SetEnv values and socket forward paths.
    /// LocalCommand, ProxyCommand and KnownHostsCommand are expanded when
    /// they run. Returns the errors ssh would stop on.
    pub fn finish(&mut self, env: &dyn Env) -> Vec<String> {
        let mut errors = Vec::new();
        let getenv = |n: &str| env.getenv(n);
        let home = env.home();
        if let Some(a) = self.options.single.get_mut(&Kw::HostKeyAlias) {
            a.args[0] = a.args[0].to_ascii_lowercase();
        }
        // User first: the other tokens' %r and %C depend on it.
        if let Some(u) = self.options.single.get(&Kw::User).map(|s| s.args[0].clone()) {
            let t = self.tokens(env);
            match expand::expand(&u, &t, TokenSet::NoUser, true, &getenv) {
                Ok(x) => self.options.single.get_mut(&Kw::User).unwrap().args[0] = x,
                Err(e) => errors.push(format!("User: {e}")),
            }
        }
        let t = self.tokens(env);
        // (keyword, tilde-expand, ${VAR}-expand), as ssh.c treats each.
        let mut plan = vec![(Kw::RemoteCommand, false, false), (Kw::VersionAddendum, false, true)];
        for kw in [Kw::ControlPath, Kw::IdentityAgent, Kw::RevokedHostKeys, Kw::ForwardAgent, Kw::UserKnownHostsFile] {
            if !self.options.first(kw).is_some_and(|v| v.eq_ignore_ascii_case("none")) {
                plan.push((kw, true, true));
            }
        }
        for (kw, tilde, dollar) in plan {
            let Some(s) = self.options.single.get_mut(&kw) else { continue };
            for a in s.args.iter_mut() {
                if kw == Kw::ForwardAgent && (a == "yes" || a == "no") {
                    continue;
                }
                let src = if tilde { expand::tilde(a, &home) } else { a.clone() };
                match expand::expand(&src, &t, TokenSet::Default, dollar, &getenv) {
                    Ok(x) => *a = x,
                    Err(e) => errors.push(format!("{}: {e}", kw.name())),
                }
            }
        }
        if let Some(s) = self.options.single.get_mut(&Kw::SetEnv) {
            for a in s.args.iter_mut() {
                if let Some((name, value)) = a.split_once('=') {
                    match expand::expand(value, &t, TokenSet::Default, true, &getenv) {
                        Ok(x) => *a = format!("{name}={x}"),
                        Err(e) => errors.push(format!("SetEnv: {e}")),
                    }
                }
            }
        }
        for (fwd, _) in self.options.local_forwards.iter_mut().chain(self.options.remote_forwards.iter_mut()) {
            for end in [Some(&mut fwd.listen), fwd.connect.as_mut()].into_iter().flatten() {
                if let forward::End::Socket { path } = end {
                    match expand::expand(path, &t, TokenSet::Default, false, &getenv) {
                        Ok(x) => *path = x,
                        Err(e) => errors.push(format!("forward path: {e}")),
                    }
                }
            }
        }
        for kw in [Kw::GlobalKnownHostsFile, Kw::UserKnownHostsFile] {
            if let Some(s) = self.options.get(kw) {
                if s.args.len() > 1 && s.args[0].eq_ignore_ascii_case("none") {
                    errors.push(format!("Invalid {}: \"none\" appears with other entries", kw.name()));
                }
            }
        }
        if self.options.first(Kw::ConnectionAttempts) == Some("0") {
            errors.push("Invalid number of ConnectionAttempts".into());
        }
        let jump = self.options.first(Kw::ProxyJump).is_some_and(|j| !j.eq_ignore_ascii_case("none"));
        let cmd = self.options.first(Kw::ProxyCommand).is_some_and(|c| !c.eq_ignore_ascii_case("none"));
        if jump && cmd {
            errors.push("inconsistent options: ProxyCommand+ProxyJump".into());
        }
        errors
    }
}

/// The host of the last hop in a ProxyJump list (the one connected to
/// first, as OpenSSH's `jump_host`).
fn jump_host_of(spec: &str) -> String {
    let last = spec.rsplit(',').next().unwrap_or(spec);
    jump_hop(last).map(|(_, h, _)| h).unwrap_or_default()
}
