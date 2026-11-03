//! What Reach does with each line of a host's ssh_config: shown on import
//! and on the session, so no line is dropped without a word.

use serde::Serialize;

use super::apply::{Plan, Use, Weakening};
use super::keyword::Kw;
use super::resolve::{At, Resolved, Status};

/// Whether Reach acts on a keyword yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Support {
    /// Used when connecting.
    Yes,
    /// Shapes how the file is read (Host, Match, Include, IgnoreUnknown…).
    Structure,
    /// Taken by the session's own fields (host, port, user, key, jump hosts).
    SessionField,
    /// Read and kept with the session, not acted on yet.
    NotYet,
}

/// Where each keyword stands. Every keyword is listed here, so a new one
/// cannot be forgotten.
pub fn support(kw: Kw) -> Support {
    use Kw::*;
    match kw {
        Host | Match | Include | IgnoreUnknown | Tag | CanonicalizeHostname | CanonicalDomains
        | CanonicalizeFallbackLocal | CanonicalizeMaxDots | CanonicalizePermittedCNAMEs => Support::Structure,
        Hostname | Port | User | ProxyJump => Support::SessionField,
        Ciphers | MACs | KexAlgorithms | HostKeyAlgorithms | Compression | ServerAliveInterval | ServerAliveCountMax
        | RekeyLimit | VersionAddendum | ConnectTimeout | ConnectionAttempts | AddressFamily | BindAddress
        | BindInterface | TCPKeepAlive | IPQoS => Support::Yes,
        // Logging in (ssh/userauth.rs).
        IdentityFile | IdentitiesOnly | IdentityAgent | CertificateFile | AddKeysToAgent | BatchMode
        | KbdInteractiveAuthentication | KbdInteractiveDevices | NumberOfPasswordPrompts | PasswordAuthentication
        | PreferredAuthentications | PubkeyAcceptedAlgorithms | PubkeyAuthentication | UseKeychain => Support::Yes,
        // Kerberos (ssh/gssapi.rs), with the Debian/Fedora patch's options.
        GSSAPIAuthentication | GSSAPIDelegateCredentials | GSSAPIClientIdentity | GSSAPIServerIdentity
        | GSSAPITrustDns => Support::Yes,
        // GSS-API key exchange (russh's kex/gss.rs, ssh/gssapi.rs).
        GSSAPIKeyExchange | GSSAPIKexAlgorithms | GSSAPIRenewalForcesRekey => Support::Yes,
        // Token and security key libraries (ssh/pkcs11.rs, ssh/sk.rs).
        PKCS11Provider | SecurityKeyProvider => Support::Yes,
        // Host keys (ssh/hostkeys.rs).
        StrictHostKeyChecking | UserKnownHostsFile | GlobalKnownHostsFile | HostKeyAlias | CheckHostIP
        | HashKnownHosts | NoHostAuthenticationForLocalhost | RevokedHostKeys | KnownHostsCommand | VisualHostKey
        | FingerprintHash | RequiredRSASize | CASignatureAlgorithms | VerifyHostKeyDNS => Support::Yes,
        // The session (ssh/session_opts.rs), ProxyCommand (ssh/proxycmd.rs).
        // ForkAfterAuthentication backgrounds ssh before the session: a
        // Reach connection already runs in the background. SyslogFacility
        // applies to ssh only when it logs to syslog (-y); it never does by
        // its own choice, and Reach does not either.
        RequestTTY | RemoteCommand | SessionType | SetEnv | SendEnv | StdinNull | EscapeChar | ObscureKeystrokeTiming | LocalCommand | PermitLocalCommand | RefuseConnection | ProxyCommand | ProxyUseFdpass | WarnWeakCrypto | ForkAfterAuthentication | SyslogFacility => Support::Yes,
        // Forwarding (ssh/forwarding.rs).
        LocalForward | RemoteForward | DynamicForward | ClearAllForwardings | ExitOnForwardFailure | GatewayPorts | PermitRemoteOpen | StreamLocalBindMask | StreamLocalBindUnlink | ChannelTimeout | EnableEscapeCommandline | ForwardAgent => Support::Yes,
        // Connection sharing (ssh/control.rs).
        ControlMaster | ControlPath | ControlPersist => Support::Yes,
        // Logging (ssh/connlog.rs).
        LogLevel | LogVerbose => Support::Yes,
        // X11 (ssh/x11.rs).
        ForwardX11 | ForwardX11Trusted | ForwardX11Timeout | XAuthLocation => Support::Yes,
        // UpdateHostKeys (ssh/hostkey_update.rs), Tunnel (ssh/tun.rs),
        // hostbased (ssh/hostbased.rs; EnableSSHKeysign is read by
        // ssh-keysign itself from the system's ssh_config, as with ssh).
        UpdateHostKeys | Tunnel | TunnelDevice | HostbasedAuthentication | HostbasedAcceptedAlgorithms | EnableSSHKeysign => Support::Yes,
    }
}

/// Keywords that run a program on this machine, or load a library into
/// Reach (PKCS11Provider, SecurityKeyProvider); they need the user's
/// approval before Reach runs them.
pub fn runs_command(kw: Kw) -> bool {
    matches!(
        kw,
        Kw::ProxyCommand | Kw::LocalCommand | Kw::KnownHostsCommand | Kw::XAuthLocation | Kw::PKCS11Provider | Kw::SecurityKeyProvider
    )
}

/// Settings that make the connection less safe than Reach's defaults,
/// besides the algorithms the plan reports.
pub fn weakening(kw: Kw, args: &[String]) -> Option<&'static str> {
    let v = args.first().map(String::as_str).unwrap_or("");
    Some(match (kw, v) {
        (Kw::StrictHostKeyChecking, "no") => "accepts any host key, including one an attacker presents",
        (Kw::UserKnownHostsFile, "/dev/null") | (Kw::GlobalKnownHostsFile, "/dev/null") => {
            "never remembers host keys, so every key is new and none can be checked"
        }
        (Kw::ForwardAgent, x) if x != "no" => "lets the server use your keys while you are connected",
        (Kw::GSSAPIDelegateCredentials, "yes") => "gives the server your Kerberos credentials",
        (Kw::GSSAPIKexAlgorithms, x) if x.split(',').any(|a| a == "gss-group1-sha1-") => {
            "offers the 1024-bit Diffie-Hellman group, within reach of a well-funded attacker"
        }
        (Kw::ForwardX11Trusted, "yes") => "gives the server full access to your display",
        (Kw::ForwardX11, "yes") => "lets the server open windows on your display",
        (Kw::GatewayPorts, "yes") => "opens forwarded ports to the whole network, not just this machine",
        (Kw::NoHostAuthenticationForLocalhost, "yes") => "skips the host key check for localhost",
        (Kw::Tunnel, x) if x != "no" => "joins this computer's network to the server's through a tunnel device",
        (Kw::CheckHostIP, "no") => return None,
        (Kw::PubkeyAcceptedAlgorithms | Kw::CASignatureAlgorithms | Kw::HostbasedAcceptedAlgorithms, x)
            if x.contains("ssh-rsa") || x.contains("ssh-dss") =>
        {
            "allows SHA-1 RSA or DSA signatures"
        }
        _ => return None,
    })
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Line {
    pub at: At,
    pub keyword: String,
    pub text: String,
    pub status: Status,
    pub support: Option<Support>,
    /// For an applied line: what the connection did with it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used: Option<Use>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weakening: Option<String>,
    /// The command it would run, when it runs one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub host: String,
    pub lines: Vec<Line>,
    pub weakenings: Vec<Weakening>,
    /// Commands the config would run for this host.
    pub commands: Vec<String>,
    /// A RefuseConnection that applies.
    pub refused: Option<String>,
    /// Errors that would make ssh refuse the files, and expansion errors.
    pub errors: Vec<String>,
    /// Lines in `Host` blocks for other hosts, left out of `lines`: in a
    /// file of hundreds of hosts they would be most of every report.
    pub other_host_lines: usize,
}

/// Which notes sit in a `Host` block that does not apply: its header and
/// every line under it inactive. Errors and `Match` blocks always stay.
fn other_host_blocks(notes: &[super::resolve::Note]) -> Vec<bool> {
    let mut hide = vec![false; notes.len()];
    let mut i = 0;
    while i < notes.len() {
        let n = &notes[i];
        let header = n.status == Status::Structure && n.keyword.eq_ignore_ascii_case("host");
        if !header {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        while j < notes.len()
            && notes[j].at.file == n.at.file
            && !(notes[j].status == Status::Structure && (notes[j].keyword.eq_ignore_ascii_case("host") || notes[j].keyword.eq_ignore_ascii_case("match")))
        {
            j += 1;
        }
        let body = &notes[i + 1..j];
        if !body.is_empty() && body.iter().all(|b| b.status == Status::Inactive) {
            for h in &mut hide[i..j] {
                *h = true;
            }
        }
        i = j;
    }
    hide
}

/// The report for a resolved host and the plan made from it. `exec_asked`
/// lists `Match exec` commands that wanted to run.
pub fn build(r: &Resolved, plan: &Plan, finish_errors: &[String], exec_asked: &[String]) -> Report {
    let mut weakenings = plan.weakenings.clone();
    let mut commands: Vec<String> = exec_asked.to_vec();
    let mut lines = Vec::new();
    let hide = other_host_blocks(&r.notes);
    let other_host_lines = hide.iter().filter(|h| **h).count();
    for (n, hidden) in r.notes.iter().zip(&hide) {
        if *hidden {
            continue;
        }
        let mut line = Line {
            at: n.at.clone(),
            keyword: n.keyword.clone(),
            text: n.text.clone(),
            status: n.status.clone(),
            support: n.kw.map(support),
            used: None,
            weakening: None,
            command: None,
        };
        if let (Some(kw), Status::Applied) = (n.kw, &n.status) {
            line.used = plan.uses.iter().find(|(k, _)| *k == kw).map(|(_, u)| u.clone());
            let args = r.options.get(kw).map(|s| s.args.clone()).unwrap_or_default();
            if let Some(why) = weakening(kw, &args) {
                line.weakening = Some(why.to_string());
                if !weakenings.iter().any(|w| w.keyword == kw.name()) {
                    let value = args.join(" ");
                    let accepted = plan.approved(&r.options, kw, &value);
                    weakenings.push(Weakening { keyword: kw.name().into(), value, reason: why.into(), accepted });
                }
            }
            let weak: Vec<String> = plan
                .weakenings
                .iter()
                .filter(|w| w.keyword == kw.name())
                .map(|w| format!("{}: {}{}", w.value, w.reason, if w.accepted { "" } else { " (waiting for your approval)" }))
                .collect();
            if !weak.is_empty() {
                line.weakening = Some(weak.join("; "));
            }
            if runs_command(kw) {
                // SecurityKeyProvider internal is built in: nothing to load.
                let builtin = |c: &str| c.eq_ignore_ascii_case("none") || (kw == Kw::SecurityKeyProvider && c.eq_ignore_ascii_case("internal"));
                if let Some(c) = r.options.first(kw).filter(|c| !builtin(c)) {
                    line.command = Some(c.to_string());
                    if !commands.iter().any(|x| x == c) {
                        commands.push(c.to_string());
                    }
                }
            }
        }
        lines.push(line);
    }
    // SendEnv: the local variables it would share, by name, for approval.
    if !r.options.send_env.is_empty() {
        let names = crate::ssh::session_opts::send_env_names(&r.options);
        let key = crate::ssh::session_opts::send_env_key(&r.options);
        let shown = if names.is_empty() { "none right now".to_string() } else { names.join(", ") };
        weakenings.push(Weakening {
            keyword: "SendEnv".into(),
            value: r.options.send_env.join(" "),
            reason: format!("sends this computer's environment variables to the server; would send: {shown}"),
            accepted: plan.accepted.contains(&key),
        });
    }
    let mut errors: Vec<String> = r
        .notes
        .iter()
        .filter_map(|n| match &n.status {
            Status::Error(e) => Some(format!("{} line {}: {e}", n.at.file, n.at.line)),
            _ => None,
        })
        .collect();
    errors.extend(finish_errors.iter().cloned());
    Report { host: r.host.clone(), lines, weakenings, commands, refused: r.refused.clone(), errors, other_host_lines }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn other_hosts_blocks_are_counted_not_listed() {
        use super::super::env::{ExecPolicy, SystemEnv};
        use super::super::resolve::{resolve, Query, Source};
        let text = "Host a
  Port 1
Host b
  Port 2
  User x
Match host zzz
  User y
Host *
  Compression yes
";
        let env = SystemEnv::new(ExecPolicy::Never);
        let src = Source { path: "cfg".into(), text: Some(text.into()), user: true };
        let mut r = resolve(&[src], &Query { host: "a".into(), ..Default::default() }, &env);
        let fe = r.finish(&env);
        let plan = Plan::new(&r, russh::client::Config::default(), &[], true);
        let rep = build(&r, &plan, &fe, &[]);
        // Host b and its two lines are left out and counted.
        assert_eq!(rep.other_host_lines, 3);
        let kws: Vec<&str> = rep.lines.iter().map(|l| l.keyword.as_str()).collect();
        assert!(!kws.contains(&"User") || rep.lines.iter().any(|l| l.keyword == "User" && l.text == "y"), "{kws:?}");
        // The Match block stays, though it does not apply.
        assert!(rep.lines.iter().any(|l| l.keyword.eq_ignore_ascii_case("match")));
        assert!(rep.lines.iter().any(|l| l.keyword == "Compression"));
    }

    #[test]
    fn every_keyword_has_a_place() {
        for kw in Kw::ALL {
            let _ = support(*kw);
        }
    }
}
