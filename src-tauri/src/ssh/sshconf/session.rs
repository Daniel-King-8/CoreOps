//! ssh_config settings as a session keeps them, and resolving them for a
//! connection. The files are stored with the session, so it resolves the
//! same way on every device it syncs to.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::env::{ExecPolicy, SystemEnv};
use super::resolve::{resolve, Env, Query, Resolved, Source};

/// What part a stored file played.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FileRole {
    /// ~/.ssh/config, read first.
    User,
    /// /etc/ssh/ssh_config (or Windows' %ProgramData%\ssh\ssh_config).
    System,
    /// A file one of them includes.
    Included,
}

/// One config file as it was read when the session was imported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigFile {
    pub path: String,
    pub text: String,
    pub role: FileRole,
}

/// What a session was imported from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Imported {
    /// The name the host was asked for by (the `Host` alias): `%n`,
    /// `Match originalhost`, and what `Host` patterns are matched against.
    pub alias: String,
    pub files: Vec<ConfigFile>,
    /// When, in Unix seconds.
    #[serde(default)]
    pub at: i64,
}

/// A session's ssh_config settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imported: Option<Imported>,
    /// Lines set in Reach ("MACs +hmac-sha1"). They win over the files, as
    /// `ssh -o` does.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lines: Vec<String>,
    /// Approvals of commands (ProxyCommand, LocalCommand, KnownHostsCommand,
    /// Match exec, XAuthLocation, token and security-key libraries), each
    /// signed by the person who gave it for this session (see `approvals`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approved_commands: Vec<String>,
    /// Approvals of weaker settings ("Keyword value"), signed the same way.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_weakenings: Vec<String>,
    /// The connecting person's own approvals, in plain words: filled from
    /// the verified signed ones when a session is read, set by the editor,
    /// and signed into the lists above when it is saved. Never stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub my_approved_commands: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub my_accepted_weakenings: Option<Vec<String>>,
    /// Lines typed into the session do not count as approved by themselves:
    /// set for every stored session, whose lines anyone with write access to
    /// its vault may have written.
    #[serde(skip)]
    pub untrusted_lines: bool,
}

impl SshOptions {
    /// What a connection uses: only the person's own approvals, and typed
    /// lines needing one like anything else.
    pub fn effective(&self) -> SshOptions {
        SshOptions {
            approved_commands: self.my_approved_commands.clone().unwrap_or_default(),
            accepted_weakenings: self.my_accepted_weakenings.clone().unwrap_or_default(),
            my_approved_commands: None,
            my_accepted_weakenings: None,
            untrusted_lines: true,
            ..self.clone()
        }
    }

    /// After reading a session: the approvals `who` really gave for it as it
    /// now is (`context`). Whatever a stored record claims in the plain
    /// fields is replaced.
    pub fn open_for(&mut self, key: Option<&[u8; 32]>, who: Option<&str>, context: &str) {
        use super::approvals::{verified, Kind};
        let (cmds, weak) = match (key, who) {
            (Some(k), Some(w)) => (
                verified(&self.approved_commands, k, w, Kind::Command, context),
                verified(&self.accepted_weakenings, k, w, Kind::Weakening, context),
            ),
            _ => (Vec::new(), Vec::new()),
        };
        self.my_approved_commands = Some(cmds);
        self.my_accepted_weakenings = Some(weak);
    }

    /// Before storing a session: `who`'s plain approvals signed into the
    /// lists, other people's kept, the plain fields dropped.
    pub fn seal_for(&mut self, key: Option<&[u8; 32]>, who: Option<&str>, context: &str) {
        use super::approvals::{replace_mine, Kind};
        if let (Some(k), Some(w)) = (key, who) {
            if let Some(m) = self.my_approved_commands.take() {
                self.approved_commands = replace_mine(&self.approved_commands, &m, k, w, Kind::Command, context);
            }
            if let Some(m) = self.my_accepted_weakenings.take() {
                self.accepted_weakenings = replace_mine(&self.accepted_weakenings, &m, k, w, Kind::Weakening, context);
            }
        }
        self.my_approved_commands = None;
        self.my_accepted_weakenings = None;
    }

    pub fn is_empty(&self) -> bool {
        self.imported.is_none() && self.lines.is_empty()
    }
}

/// The machine, answering file reads from the stored copies: an Include
/// finds the file it found at import, on any device.
struct StoredEnv<'a> {
    sys: &'a SystemEnv,
    files: &'a [ConfigFile],
}

fn norm(p: &str) -> String {
    p.replace('\\', "/")
}

impl Env for StoredEnv<'_> {
    fn home(&self) -> String {
        self.sys.home()
    }
    fn local_user(&self) -> String {
        self.sys.local_user()
    }
    fn uid(&self) -> String {
        self.sys.uid()
    }
    fn local_host(&self) -> String {
        self.sys.local_host()
    }
    fn system_dir(&self) -> String {
        self.sys.system_dir()
    }
    fn read(&self, path: &Path) -> Option<String> {
        let want = norm(&path.display().to_string());
        self.files.iter().find(|f| norm(&f.path) == want).map(|f| f.text.clone())
    }
    fn glob(&self, pattern: &str) -> Vec<PathBuf> {
        let pat = norm(pattern);
        self.files
            .iter()
            .filter(|f| super::pattern::match_pattern(&norm(&f.path), &pat))
            .map(|f| PathBuf::from(&f.path))
            .collect()
    }
    fn getenv(&self, name: &str) -> Option<String> {
        self.sys.getenv(name)
    }
    fn local_addresses(&self) -> Vec<std::net::IpAddr> {
        self.sys.local_addresses()
    }
    fn exec(&self, command: &str) -> Result<bool, String> {
        self.sys.exec(command)
    }
    fn resolve(&self, name: &str) -> Option<String> {
        self.sys.resolve(name)
    }
}

/// A session's settings, resolved.
pub struct SessionResolution {
    pub resolved: Resolved,
    /// Expansion errors ssh would stop on.
    pub errors: Vec<String>,
    /// `Match exec` commands that wanted to run but are not approved.
    pub exec_pending: Vec<String>,
}

/// Resolve a session's settings for connecting. `host`, `port` and `user`
/// are the session's own fields; like ssh's command line they win.
pub fn resolve_session(opts: &SshOptions, host: &str, port: u16, user: &str) -> SessionResolution {
    let sys = SystemEnv::new(ExecPolicy::Approved(opts.approved_commands.clone()));
    let empty = Vec::new();
    let files = opts.imported.as_ref().map_or(&empty, |i| &i.files);
    let env = StoredEnv { sys: &sys, files };
    let alias = opts.imported.as_ref().map_or(host.to_string(), |i| i.alias.clone());
    let mut overrides = vec![("HostName".to_string(), host.to_string()), ("Port".to_string(), port.to_string())];
    if !user.is_empty() {
        overrides.push(("User".to_string(), user.to_string()));
    }
    for line in &opts.lines {
        if let Some(l) = super::lex::split_keyword(line) {
            overrides.push((l.keyword, l.rest));
        }
    }
    // ssh reads the user's file, then the system's; included files are
    // reached through them.
    let sources: Vec<Source> = [FileRole::User, FileRole::System]
        .iter()
        .filter_map(|role| files.iter().find(|f| f.role == *role))
        .map(|f| Source { path: PathBuf::from(&f.path), text: Some(f.text.clone()), user: f.role == FileRole::User })
        .collect();
    let mut r = resolve(&sources, &Query { host: alias, command: None, overrides }, &env);
    let errors = r.finish(&env);
    let exec_pending = sys.refused.borrow().clone();
    SessionResolution { resolved: r, errors, exec_pending }
}

/// The plan for one hop of a session: the session's settings for its own
/// host, or, for a jump host, the imported files looked up by that host's
/// name (as ssh does for each ProxyJump hop), without the session's own
/// lines, which are for the target.
pub fn plan_for(opts: Option<&SshOptions>, host: &str, port: u16, user: &str, jump: bool) -> super::apply::Plan {
    let base = russh::client::Config::default();
    let Some(opts) = opts.filter(|o| !o.is_empty()) else {
        let empty = Resolved::empty(host);
        return super::apply::Plan::new(&empty, base, &[], false);
    };
    let scoped;
    let opts = if jump {
        scoped = SshOptions { lines: Vec::new(), ..opts.clone() };
        &scoped
    } else {
        opts
    };
    let SessionResolution { resolved: r, errors, exec_pending } = resolve_session(opts, host, port, user);
    for c in &exec_pending {
        tracing::warn!("ssh_config for {host}: Match exec \"{c}\" is not approved; taken as not matching");
    }
    for e in &errors {
        tracing::warn!("ssh_config for {host}: {e}");
    }
    let mut plan = super::apply::Plan::new(&r, base, &opts.accepted_weakenings, !opts.untrusted_lines);
    if !jump {
        plan.control = crate::ssh::control::ControlPlan::from(r.options.first(super::keyword::Kw::ControlPath), r.options.first(super::keyword::Kw::ControlMaster), r.options.first(super::keyword::Kw::ControlPersist));
    }
    plan.log = Some((r.options.first(super::keyword::Kw::LogLevel).map(str::to_string), r.options.get(super::keyword::Kw::LogVerbose).map(|s| s.args.clone()).unwrap_or_default()));
    plan.auth = Some(auth_policy(&r, &plan, opts.imported.is_some(), &opts.approved_commands));
    let hk = hostkey_policy(&r, &plan, opts);
    if hk.use_files {
        // Ask for host certificates too: they are checked against
        // @cert-authority lines, and fall back to the plain key.
        use russh::keys::{Algorithm, EcdsaCurve, HashAlg};
        plan.config.preferred.host_key_certificates = std::borrow::Cow::Owned(vec![
            Algorithm::Ed25519,
            Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 },
            Algorithm::Ecdsa { curve: EcdsaCurve::NistP384 },
            Algorithm::Ecdsa { curve: EcdsaCurve::NistP521 },
            Algorithm::Rsa { hash: Some(HashAlg::Sha512) },
            Algorithm::Rsa { hash: Some(HashAlg::Sha256) },
        ]);
    }
    plan.hostkeys = Some(hk);
    plan.refused = r.refused.clone().map(|m| format!("RefuseConnection: {m}"));
    {
        use super::keyword::Kw;
        if let Some(cmd) = r.options.first(Kw::ProxyCommand).filter(|c| !c.eq_ignore_ascii_case("none")) {
            if opts.approved_commands.iter().any(|a| a == cmd) {
                plan.proxy_command = Some(crate::ssh::proxycmd::ProxyCommand {
                    command: cmd.to_string(),
                    use_fdpass: r.options.first(Kw::ProxyUseFdpass) == Some("yes"),
                    original_host: r.original_host.clone(),
                    key_alias: r.options.first(Kw::HostKeyAlias).map(str::to_string).unwrap_or_else(|| r.original_host.clone()),
                });
            } else if plan.refused.is_none() {
                // Connecting directly instead would skip the path the config
                // asks for.
                plan.refused = Some(format!("ProxyCommand \"{cmd}\" waits for your approval in the session's SSH options"));
            }
        }
    }
    if !jump {
        use super::keyword::Kw;
        // LocalCommand runs only with PermitLocalCommand, and only once the
        // user allowed that exact command.
        let local = r
            .options
            .first(Kw::LocalCommand)
            .filter(|_| r.options.first(Kw::PermitLocalCommand) == Some("yes"))
            .filter(|c| opts.approved_commands.iter().any(|a| a == c))
            .map(str::to_string);
        let key = crate::ssh::session_opts::send_env_key(&r.options);
        let send_env_allowed = opts.accepted_weakenings.contains(&key);
        let mut session = crate::ssh::session_opts::SessionPolicy::from_options(&r.options, local, send_env_allowed);
        let forwards = forward_policy(&r, &plan, &opts.approved_commands);
        session.agent_forward = forwards.agent.is_some();
        plan.session = Some(session);
        plan.forwards = Some(forwards);
    }
    for w in &plan.weakenings {
        tracing::warn!("ssh_config for {host}: {} {} weakens the connection: {}", w.keyword, w.value, w.reason);
    }
    for (kw, u) in &plan.uses {
        tracing::info!("ssh_config for {host}: {} {:?}", kw.name(), u);
    }
    plan
}

/// Forwards as the config sets them. ForwardAgent applies once approved
/// (it lets the server use your keys).
fn forward_policy(r: &Resolved, plan: &super::apply::Plan, approved_commands: &[String]) -> crate::ssh::forwarding::ForwardPolicy {
    use super::keyword::Kw;
    use crate::ssh::userauth::AgentChoice;
    let o = &r.options;
    let clear = o.first(Kw::ClearAllForwardings) == Some("yes");
    let agent = match o.first(Kw::ForwardAgent) {
        None | Some("no") => None,
        Some(v) if !plan.approved(o, Kw::ForwardAgent, v) => {
            tracing::warn!("ForwardAgent {v} waits for approval; not forwarding the agent");
            None
        }
        Some("yes") => Some(AgentChoice::Default),
        Some(path) => Some(AgentChoice::Socket(path.to_string())),
    };
    let permit_remote_open = o.get(Kw::PermitRemoteOpen).map(|s| s.args.clone()).filter(|a| !(a.len() == 1 && a[0].eq_ignore_ascii_case("any")));
    let bind_mask = o
        .first(Kw::StreamLocalBindMask)
        .map(|m| m.trim_start().chars().take_while(|c| ('0'..='7').contains(c)).collect::<String>())
        .and_then(|d| u32::from_str_radix(&d, 8).ok())
        .unwrap_or(0o177);
    let timeouts = o
        .get(Kw::ChannelTimeout)
        .filter(|s| !s.args.first().is_some_and(|a| a.eq_ignore_ascii_case("none")))
        .map(|s| {
            s.args
                .iter()
                .filter_map(|a| a.split_once('='))
                .filter_map(|(t, d)| super::value::convtime_f(d).map(|x| (t.to_string(), std::time::Duration::from_secs_f64(x))))
                .filter(|(_, d)| !d.is_zero())
                .collect()
        })
        .unwrap_or_default();
    crate::ssh::forwarding::ForwardPolicy {
        local: if clear { Vec::new() } else { o.local_forwards.iter().map(|(f, _)| f.clone()).collect() },
        remote: if clear { Vec::new() } else { o.remote_forwards.iter().map(|(f, _)| f.clone()).collect() },
        gateway_ports: o.first(Kw::GatewayPorts) == Some("yes") && plan.approved(o, Kw::GatewayPorts, "yes"),
        exit_on_failure: o.first(Kw::ExitOnForwardFailure) == Some("yes"),
        permit_remote_open,
        bind_mask,
        bind_unlink: o.first(Kw::StreamLocalBindUnlink) == Some("yes"),
        agent,
        timeouts,
        x11: x11_config(o, plan, approved_commands),
        tun: if clear { None } else { crate::ssh::tun::TunConfig::parse(o.first(Kw::Tunnel), o.first(Kw::TunnelDevice)).filter(|_| tunnel_approved(o, plan)) },
    }
}

/// Tunnel joins this computer's network to the server's: only once approved.
fn tunnel_approved(o: &super::resolve::Options, plan: &super::apply::Plan) -> bool {
    let v = o.first(super::keyword::Kw::Tunnel).unwrap_or("no");
    let ok = plan.approved(o, super::keyword::Kw::Tunnel, v);
    if !ok {
        tracing::warn!("Tunnel {v} waits for approval; no tunnel");
    }
    ok
}

/// ForwardX11 with its trust, timeout and xauth, when on and approved and
/// this machine has a display.
fn x11_config(o: &super::resolve::Options, plan: &super::apply::Plan, approved_commands: &[String]) -> Option<crate::ssh::x11::X11Config> {
    use super::keyword::Kw;
    if o.first(Kw::ForwardX11) != Some("yes") {
        return None;
    }
    if !plan.approved(o, Kw::ForwardX11, "yes") {
        tracing::warn!("ForwardX11 yes waits for approval; not forwarding X11");
        return None;
    }
    let display = match std::env::var("DISPLAY") {
        Ok(d) if !d.is_empty() => d,
        // Windows has no X server of its own: Reach provides one (an
        // empty display asks for it, see ssh/xserver.rs).
        _ if cfg!(windows) => String::new(),
        _ if cfg!(target_os = "macos") => {
            tracing::warn!("ForwardX11: no X server on this Mac; install XQuartz (xquartz.org), log out and in, and connect again");
            return None;
        }
        _ => {
            tracing::warn!("ForwardX11: DISPLAY is not set on this computer; not forwarding X11");
            return None;
        }
    };
    let trusted = o.first(Kw::ForwardX11Trusted) == Some("yes");
    let trusted = if trusted && !plan.approved(o, Kw::ForwardX11Trusted, "yes") {
        tracing::warn!("ForwardX11Trusted yes waits for approval; forwarding X11 untrusted");
        false
    } else {
        trusted
    };
    // ForwardX11Timeout: 20 minutes by default, 0 never expires.
    let timeout = match o.first(Kw::ForwardX11Timeout).and_then(super::value::convtime) {
        Some(0) => None,
        Some(s) if s > 0 => Some(std::time::Duration::from_secs(s as u64)),
        _ => Some(std::time::Duration::from_secs(1200)),
    };
    // XAuthLocation names a program Reach runs: like the other commands,
    // it runs only once approved. Without approval X11 still works, with
    // the usual xauth.
    let xauth = match o.first(Kw::XAuthLocation) {
        Some(x) if approved_commands.iter().any(|a| a == x) => x.to_string(),
        Some(x) => {
            tracing::warn!("XAuthLocation {x} waits for approval; using the usual xauth");
            default_xauth()
        }
        None => default_xauth(),
    };
    Some(crate::ssh::x11::X11Config { display, trusted, timeout, xauth })
}

/// _PATH_XAUTH as the usual builds set it, plus XQuartz and VcXsrv.
fn default_xauth() -> String {
    let candidates: &[&str] = if cfg!(windows) {
        &[r"C:\Program Files\VcXsrv\xauth.exe", r"C:\Program Files (x86)\Xming\xauth.exe"]
    } else {
        &["/usr/bin/xauth", "/opt/X11/bin/xauth", "/usr/X11R6/bin/xauth", "/usr/local/bin/xauth", "/usr/openwin/bin/xauth"]
    };
    candidates.iter().find(|p| std::path::Path::new(p).exists()).unwrap_or(&candidates[0]).to_string()
}

/// The host-key policy. UserKnownHostsFile and RevokedHostKeys come
/// expanded from `finish`; the defaults are OpenSSH's.
fn hostkey_policy(r: &Resolved, plan: &super::apply::Plan, opts: &SshOptions) -> crate::ssh::hostkeys::HostKeyPolicy {
    use super::keyword::Kw;
    use crate::ssh::hostkeys::{HostKeyPolicy, Strict};
    let o = &r.options;
    let sys = SystemEnv::new(ExecPolicy::Never);
    let home = sys.home();
    let list = |kw: Kw, default: &[String]| -> Vec<std::path::PathBuf> {
        let args: Vec<String> = o.get(kw).map(|s| s.args.clone()).unwrap_or_else(|| default.to_vec());
        if args.first().is_some_and(|a| a.eq_ignore_ascii_case("none")) {
            return Vec::new();
        }
        args.iter().map(|a| std::path::PathBuf::from(super::expand::tilde(a, &home))).collect()
    };
    let sys_dir = sys.system_dir();
    let user_default = vec!["~/.ssh/known_hosts".to_string(), "~/.ssh/known_hosts2".to_string()];
    let global_default = vec![format!("{sys_dir}/ssh_known_hosts"), format!("{sys_dir}/ssh_known_hosts2")];
    let flag = |kw: Kw, default: bool| o.first(kw).map_or(default, |v| v != "no");
    let command = o
        .first(Kw::KnownHostsCommand)
        .filter(|c| !c.eq_ignore_ascii_case("none"))
        .filter(|c| opts.approved_commands.iter().any(|a| a == c))
        .map(str::to_string);
    let strict = match o.first(Kw::StrictHostKeyChecking) {
        Some("yes") => Strict::Yes,
        Some("accept-new") => Strict::AcceptNew,
        Some("no") if plan.approved(o, Kw::StrictHostKeyChecking, "no") => Strict::No,
        _ => Strict::Ask,
    };
    HostKeyPolicy {
        strict,
        use_files: opts.imported.is_some() || o.get(Kw::UserKnownHostsFile).is_some() || o.get(Kw::GlobalKnownHostsFile).is_some(),
        user_files: list(Kw::UserKnownHostsFile, &user_default),
        global_files: list(Kw::GlobalKnownHostsFile, &global_default),
        alias: o.first(Kw::HostKeyAlias).map(|a| a.to_ascii_lowercase()),
        check_host_ip: flag(Kw::CheckHostIP, false),
        hash: flag(Kw::HashKnownHosts, false),
        no_auth_localhost: flag(Kw::NoHostAuthenticationForLocalhost, false) && plan.approved(o, Kw::NoHostAuthenticationForLocalhost, "yes"),
        revoked: list(Kw::RevokedHostKeys, &[]),
        command,
        visual: flag(Kw::VisualHostKey, false),
        fingerprint_hash: o.first(Kw::FingerprintHash).unwrap_or("sha256").to_string(),
        min_rsa_bits: o.first(Kw::RequiredRSASize).and_then(|n| n.parse().ok()).unwrap_or(1024),
        ca_signature_algorithms: plan.ca_signature_algorithms.clone(),
        proxied: o.first(Kw::ProxyJump).is_some_and(|j| j != "none") || o.first(Kw::ProxyCommand).is_some_and(|c| c != "none"),
        tokens: r.tokens(&sys),
        warn_weak_crypto: o.first(Kw::WarnWeakCrypto) != Some("no"),
        verify_dns: match o.first(Kw::VerifyHostKeyDNS) {
            Some("yes" | "true") => 1,
            Some("ask") => 2,
            _ => 0,
        },
        update_host_keys: crate::ssh::hostkey_update::UpdateHostKeys::from_config(
            o.first(Kw::UpdateHostKeys),
            o.first(Kw::VerifyHostKeyDNS),
            crate::ssh::hostkey_update::raw_user_files(r).as_deref(),
        ),
        host_key_algorithms: plan.config.preferred.key.iter().map(|a| a.as_str().to_string()).collect(),
    }
}

/// The login policy: IdentityFile and CertificateFile expanded as ssh
/// expands them when it loads them (`~`, `%` tokens, `${VAR}`).
/// PKCS11Provider and SecurityKeyProvider libraries run their code when
/// loaded, so like commands they apply only once approved.
fn auth_policy(r: &Resolved, plan: &super::apply::Plan, imported: bool, approved: &[String]) -> crate::ssh::userauth::AuthPolicy {
    use super::expand::{expand, tilde, TokenSet};
    let sys = SystemEnv::new(ExecPolicy::Never);
    let tokens = r.tokens(&sys);
    let home = sys.home();
    let paths = |list: &[super::resolve::Setting]| -> Vec<String> {
        list.iter()
            .filter_map(|s| match expand(&tilde(&s.args[0], &home), &tokens, TokenSet::Default, true, &|n| std::env::var(n).ok()) {
                Ok(p) => Some(p),
                Err(e) => {
                    tracing::warn!("ssh_config: {}: {e}", s.args[0]);
                    None
                }
            })
            .collect()
    };
    let ids = paths(&r.options.identity_files);
    let certs = paths(&r.options.certificate_files);
    let mut p = crate::ssh::userauth::AuthPolicy::from_options(&r.options, ids, certs, plan.pubkey_algorithms.clone(), imported);
    // GSSAPIDelegateCredentials hands the server your Kerberos credentials:
    // only once approved.
    let delegate_ok = plan.approved(&r.options, super::keyword::Kw::GSSAPIDelegateCredentials, "yes");
    if let Some(g) = p.gssapi.as_mut().filter(|g| g.delegate) {
        if !delegate_ok {
            tracing::warn!("GSSAPIDelegateCredentials yes waits for approval; not delegating");
            g.delegate = false;
        }
    }
    if let Some(k) = p.gss_kex.as_mut() {
        if k.gss.delegate && !delegate_ok {
            k.gss.delegate = false;
        }
        // The 1024-bit group only once approved, as other weak algorithms.
        if k.algorithms.contains(&russh::kex::GSS_G1_SHA1) {
            let list = r.options.first(super::keyword::Kw::GSSAPIKexAlgorithms).unwrap_or_default();
            if !plan.approved(&r.options, super::keyword::Kw::GSSAPIKexAlgorithms, list) {
                tracing::warn!("GSSAPIKexAlgorithms: gss-group1-sha1- waits for approval; not offered");
                k.algorithms.retain(|n| *n != russh::kex::GSS_G1_SHA1);
            }
        }
    }
    p.hostbased = crate::ssh::hostbased::HostbasedContext::from_options(&r.options, plan);
    p.pkcs11_provider = crate::ssh::pkcs11::provider_from(&r.options, approved);
    p.sk_provider = crate::ssh::sk::Provider::from_options(&r.options, approved);
    p
}
