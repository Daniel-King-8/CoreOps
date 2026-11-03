//! The resolver against OpenSSH's own rules: hand-written cases, and every
//! case compared with what `ssh -G` prints for the same files.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use super::forward::End;
use super::keyword::Kw;
use super::resolve::{resolve, Env, Query, Resolved, Source, Status};
use super::value;

/// A machine whose answers the test chooses.
struct Fake {
    files: BTreeMap<String, String>,
    addrs: Vec<IpAddr>,
    exec_true: Vec<String>,
    ran: RefCell<Vec<String>>,
    dns: Vec<String>,
}

impl Fake {
    fn new() -> Self {
        Fake { files: BTreeMap::new(), addrs: vec![], exec_true: vec![], ran: RefCell::new(vec![]), dns: vec![] }
    }
}

impl Env for Fake {
    fn home(&self) -> String {
        "/home/me".into()
    }
    fn local_user(&self) -> String {
        "me".into()
    }
    fn uid(&self) -> String {
        "1000".into()
    }
    fn local_host(&self) -> String {
        "laptop.home".into()
    }
    fn system_dir(&self) -> String {
        "/etc/ssh".into()
    }
    fn read(&self, path: &Path) -> Option<String> {
        self.files.get(&path.display().to_string().replace('\\', "/")).cloned()
    }
    fn glob(&self, pattern: &str) -> Vec<PathBuf> {
        let pattern = pattern.replace('\\', "/");
        self.files.keys().filter(|k| super::pattern::match_pattern(k, &pattern)).map(PathBuf::from).collect()
    }
    fn getenv(&self, name: &str) -> Option<String> {
        (name == "AGENT").then(|| "/run/agent.sock".into())
    }
    fn local_addresses(&self) -> Vec<IpAddr> {
        self.addrs.clone()
    }
    fn exec(&self, command: &str) -> Result<bool, String> {
        self.ran.borrow_mut().push(command.to_string());
        Ok(self.exec_true.iter().any(|c| c == command))
    }
    fn resolve(&self, name: &str) -> Option<String> {
        self.dns.iter().any(|d| d == name).then(String::new)
    }
}

fn run(env: &Fake, text: &str, host: &str) -> Resolved {
    let src = Source { path: "/home/me/.ssh/config".into(), text: Some(text.into()), user: true };
    resolve(&[src], &Query { host: host.into(), ..Default::default() }, env)
}

fn first(r: &Resolved, kw: Kw) -> Option<&str> {
    r.options.first(kw)
}

#[test]
fn first_value_wins_across_blocks_and_host_star_fills_the_rest() {
    let r = run(&Fake::new(), "Host web\n  Port 2222\nHost *\n  Port 22\n  User admin\n", "web");
    assert_eq!(first(&r, Kw::Port), Some("2222"));
    assert_eq!(first(&r, Kw::User), Some("admin"));
    let statuses: Vec<_> = r.notes.iter().map(|n| (n.at.line, n.status.clone())).collect();
    assert!(statuses.contains(&(4, Status::Overridden)));
    assert!(statuses.contains(&(2, Status::Applied)));
}

#[test]
fn a_negated_pattern_closes_the_block() {
    let text = "Host * !bastion\n  ProxyJump bastion\n";
    assert_eq!(first(&run(&Fake::new(), text, "web"), Kw::ProxyJump), Some("bastion"));
    assert_eq!(first(&run(&Fake::new(), text, "bastion"), Kw::ProxyJump), None);
}

#[test]
fn host_patterns_are_case_sensitive_but_match_host_is_not() {
    let text = "Host WEB\n  Port 1\nMatch host WEB\n  User u\n";
    let r = run(&Fake::new(), text, "web");
    assert_eq!(first(&r, Kw::Port), None);
    assert_eq!(first(&r, Kw::User), Some("u"));
}

#[test]
fn match_criteria() {
    let mut env = Fake::new();
    env.addrs = vec!["192.168.1.20".parse().unwrap()];
    env.exec_true = vec!["test -e /x".into()];
    let text = "\
Match originalhost web user root
  Port 1
Match localnetwork 192.168.1.0/24
  User root
Match exec \"test -e /x\" host web
  Compression yes
Match !exec \"never\"
  Tag t
Match all
  LogLevel ERROR
";
    let r = run(&env, text, "web");
    // `user root` is checked with the user known at that point (none yet:
    // the local user, me), so the first block does not apply.
    assert_eq!(first(&r, Kw::Port), None);
    assert_eq!(first(&r, Kw::User), Some("root"));
    assert_eq!(first(&r, Kw::Compression), Some("yes"));
    assert_eq!(first(&r, Kw::Tag), Some("t"));
    assert_eq!(first(&r, Kw::LogLevel), Some("ERROR"));
}

#[test]
fn match_exec_does_not_run_once_a_criterion_failed() {
    let env = Fake::new();
    run(&env, "Match host other exec \"touch /tmp/x\"\n  Port 1\n", "web");
    assert!(env.ran.borrow().is_empty());
}

#[test]
fn match_final_reads_the_file_again() {
    let text = "Host web\n  HostName web.example.com\nMatch final host web.example.com\n  User deploy\n";
    let r = run(&Fake::new(), text, "web");
    assert!(r.final_pass);
    assert_eq!(r.host, "web.example.com");
    assert_eq!(first(&r, Kw::User), Some("deploy"));
}

#[test]
fn canonicalisation_tries_each_domain_then_reads_again() {
    let mut env = Fake::new();
    env.dns = vec!["db.prod.example.".into()];
    let text = "CanonicalizeHostname yes\nCanonicalDomains dev.example prod.example\nHost *.prod.example\n  User ops\n";
    let r = run(&env, text, "db");
    assert_eq!(r.host, "db.prod.example");
    assert_eq!(first(&r, Kw::User), Some("ops"));
}

#[test]
fn include_reads_relative_to_dot_ssh_and_keeps_the_outer_state() {
    let mut env = Fake::new();
    env.files.insert("/home/me/.ssh/conf.d/a.conf".into(), "Host web\n  Port 2200\nMatch all\n  User inc\n".into());
    let text = "Host web\n  Include conf.d/*.conf\n  Compression yes\nHost other\n  Include conf.d/*.conf\n";
    let r = run(&env, text, "web");
    assert_eq!(first(&r, Kw::Port), Some("2200"));
    assert_eq!(first(&r, Kw::User), Some("inc"));
    assert_eq!(first(&r, Kw::Compression), Some("yes"));
    // Read under a block that does not apply, nothing inside may apply.
    let r = run(&env, "Host nope\n  Include conf.d/*.conf\n", "web");
    assert_eq!(first(&r, Kw::Port), None);
}

#[test]
fn unknown_keywords_are_errors_unless_ignored() {
    let r = run(&Fake::new(), "Bogus yes\n", "web");
    assert!(r.has_errors());
    let r = run(&Fake::new(), "IgnoreUnknown bogus,UseKeychainX\nBogus yes\n", "web");
    assert!(!r.has_errors());
    assert!(r.notes.iter().any(|n| n.keyword == "Bogus" && n.status == Status::Ignored));
}

#[test]
fn an_error_in_a_block_that_does_not_apply_is_still_an_error() {
    let r = run(&Fake::new(), "Host other\n  Port notaport\n", "web");
    assert!(r.has_errors());
}

#[test]
fn proxyjump_and_proxycommand_exclude_each_other() {
    let r = run(&Fake::new(), "Host web\n  ProxyJump a,b\n  ProxyCommand nc %h %p\n", "web");
    assert_eq!(first(&r, Kw::ProxyJump), Some("a,b"));
    assert_eq!(first(&r, Kw::ProxyCommand), Some("none"));
    let r = run(&Fake::new(), "Host web\n  ProxyCommand nc %h %p\n  ProxyJump a\n", "web");
    assert_eq!(first(&r, Kw::ProxyCommand), Some("nc %h %p"));
    assert_eq!(first(&r, Kw::ProxyJump), None);
}

#[test]
fn collected_keywords() {
    let text = "\
Host web
  IdentityFile ~/.ssh/a
  IdentityFile ~/.ssh/a
  SendEnv LANG LC_* XYZ
  SendEnv -LC_*
  LocalForward 8080 db:5432
  DynamicForward 1080
  RemoteForward 9000
Host *
  IdentityFile ~/.ssh/b
  SetEnv A=1 A=2 B=3
";
    let r = run(&Fake::new(), text, "web");
    let ids: Vec<_> = r.options.identity_files.iter().map(|s| s.args[0].as_str()).collect();
    assert_eq!(ids, ["~/.ssh/a", "~/.ssh/b"]);
    assert_eq!(r.options.send_env, ["LANG", "XYZ"]);
    assert_eq!(r.options.local_forwards.len(), 2);
    assert_eq!(r.options.remote_forwards[0].0.connect, None, "a RemoteForward with one argument is a SOCKS proxy");
    assert_eq!(r.options.get(Kw::SetEnv).unwrap().args, ["A=1", "B=3"]);
}

#[test]
fn finishing_expands_tokens_like_ssh() {
    let text = "\
Host web
  HostName %h.example.com
  User %u-admin
  RemoteCommand echo %r@%h:%p
  ControlPath ~/.ssh/cm-%C
  IdentityAgent ${AGENT}
  SetEnv WHO=%n
";
    let env = Fake::new();
    let mut r = run(&env, text, "web");
    assert!(r.finish(&env).is_empty());
    assert_eq!(r.host, "web.example.com");
    assert_eq!(first(&r, Kw::User), Some("me-admin"));
    assert_eq!(first(&r, Kw::RemoteCommand), Some("echo me-admin@web.example.com:22"));
    assert!(first(&r, Kw::ControlPath).unwrap().starts_with("/home/me/.ssh/cm-"));
    assert_eq!(first(&r, Kw::IdentityAgent), Some("/run/agent.sock"));
    assert_eq!(r.options.get(Kw::SetEnv).unwrap().args, ["WHO=web"]);
}

#[test]
fn refuse_connection_is_reported() {
    let r = run(&Fake::new(), "Host old\n  RefuseConnection \"use new instead\"\n", "old");
    assert_eq!(r.refused.as_deref(), Some("use new instead"));
}

#[test]
fn command_line_overrides_win() {
    let src = Source { path: "/c".into(), text: Some("Host web\n  Port 2222\n  User a\n".into()), user: true };
    let q = Query { host: "web".into(), overrides: vec![("Port".into(), "22".into())], ..Default::default() };
    let r = resolve(&[src], &q, &Fake::new());
    assert_eq!(first(&r, Kw::Port), Some("22"));
    assert_eq!(first(&r, Kw::User), Some("a"));
}

#[test]
fn the_legacy_mac_server_from_discord() {
    let r = run(&Fake::new(), "Host monitoring\n  HostName 192.168.1.70\n  User root\n  MACs +hmac-sha1\n", "monitoring");
    assert_eq!(r.host, "192.168.1.70");
    assert_eq!(first(&r, Kw::MACs), Some("+hmac-sha1"));
    assert!(!r.has_errors());
}

// ---------------------------------------------------------------------
// Against OpenSSH itself.
// ---------------------------------------------------------------------

/// What `ssh -G` would print for what the config set, in its format.
fn as_ssh_g(r: &Resolved) -> Vec<String> {
    use Kw::*;
    let mut out = vec![format!("hostname {}", r.host)];
    let shown = |kw: Kw, words: value::Words, v: &str| -> String {
        // ssh -G prints the first word with the same meaning.
        let name = words.iter().find(|(_, c)| *c == v).map_or(v, |(w, _)| *w);
        format!("{} {name}", kw.name().to_ascii_lowercase())
    };
    for (kw, s) in &r.options.single {
        let k = kw.name().to_ascii_lowercase();
        let a0 = s.args[0].as_str();
        let line = match kw {
            // Algorithm lists print as the assembled list of the ssh
            // binary's build; compared separately.
            Ciphers | MACs | KexAlgorithms | HostKeyAlgorithms | PubkeyAcceptedAlgorithms | CASignatureAlgorithms
            | HostbasedAcceptedAlgorithms => continue,
            Hostname | ProxyCommand | GSSAPIKeyExchange | GSSAPIClientIdentity | GSSAPIServerIdentity
            | GSSAPIRenewalForcesRekey | GSSAPITrustDns | GSSAPIKexAlgorithms | UseKeychain => continue,
            StrictHostKeyChecking => shown(*kw, value::STRICT_HOST_KEY, a0),
            VerifyHostKeyDNS | UpdateHostKeys => shown(*kw, value::YES_NO_ASK, a0),
            ControlMaster => shown(*kw, value::CONTROL_MASTER, a0),
            Tunnel => shown(*kw, value::TUNNEL, a0),
            RequestTTY => shown(*kw, value::REQUEST_TTY, a0),
            CanonicalizeHostname => shown(*kw, value::CANONICALIZE, a0),
            PubkeyAuthentication => shown(*kw, value::PUBKEY_AUTH, a0),
            // OpenSSH 10.3 prints yes/no here.
            TCPKeepAlive => format!("{k} {a0}"),
            ControlPersist => match a0 {
                "yes" | "true" => format!("{k} yes"),
                "no" | "false" => format!("{k} no"),
                t => format!("{k} {}", value::convtime(t).unwrap()),
            },
            ConnectTimeout | ServerAliveInterval | ForwardX11Timeout => {
                format!("{k} {}", value::convtime(a0).map_or("none".into(), |v| v.to_string()))
            }
            ObscureKeystrokeTiming => {
                let ms = match a0 {
                    "yes" => "20".to_string(),
                    "no" => "0".to_string(),
                    x => x.trim_start_matches("interval:").to_string(),
                };
                format!("{k} {ms}")
            }
            AddKeysToAgent => match s.args.get(1) {
                Some(t) => format!("{k}{} {}", if a0 == "confirm" { " confirm" } else { "" }, value::convtime(t).unwrap()),
                None => shown(*kw, value::YES_NO_ASK_CONFIRM, a0),
            },
            RekeyLimit => {
                let bytes = if a0 == "default" { 0 } else { value::scaled(a0).unwrap() };
                let secs = s.args.get(1).map_or(0, |t| if t == "none" { 0 } else { value::convtime(t).unwrap() });
                format!("{k} {bytes} {secs}")
            }
            EscapeChar => {
                let b = a0.as_bytes();
                let shown = if a0 == "none" {
                    "none".to_string()
                } else if b.len() == 2 && b[0] == b'^' {
                    format!("\\^{}", b[1] as char)
                } else {
                    a0.to_string()
                };
                format!("{k} {shown}")
            }
            StreamLocalBindMask => {
                let digits: String = a0.chars().take_while(|c| ('0'..='7').contains(c)).collect();
                format!("{k} 0{:o}", u32::from_str_radix(&digits, 8).unwrap())
            }
            TunnelDevice => {
                let (l, rr) = a0.split_once(':').unwrap_or((a0, "any"));
                format!("{k} {l}:{rr}")
            }
            SetEnv | SendEnv => {
                for a in &s.args {
                    out.push(format!("{k} {a}"));
                }
                continue;
            }
            CanonicalizePermittedCNAMEs => format!("{k} {}", s.args.join(" ")),
            _ => format!("{k} {}", s.args.join(" ")),
        };
        out.push(line);
    }
    for e in &r.options.send_env {
        out.push(format!("sendenv {e}"));
    }
    for s in &r.options.identity_files {
        out.push(format!("identityfile {}", s.args[0]));
    }
    for s in &r.options.certificate_files {
        out.push(format!("certificatefile {}", s.args[0]));
    }
    let end = |e: &End| match e {
        End::Tcp { host: Some(h), port } => format!("[{h}]:{port}"),
        End::Tcp { host: None, port } => port.to_string(),
        End::Socket { path } => path.clone(),
    };
    for (f, _) in &r.options.local_forwards {
        match &f.connect {
            None => out.push(format!("dynamicforward {}", end(&f.listen))),
            Some(c) => out.push(format!("localforward {} {}", end(&f.listen), end(c))),
        }
    }
    for (f, _) in &r.options.remote_forwards {
        match &f.connect {
            None => out.push(format!("remoteforward {} [socks]:0", end(&f.listen))),
            Some(c) => out.push(format!("remoteforward {} {}", end(&f.listen), end(c))),
        }
    }
    out
}

/// Configs that exercise the rules. Each: (minimum OpenSSH major version,
/// config text, hosts to ask about).
const CORPUS: &[(u32, &str, &[&str])] = &[
    (8, "Host web\n  HostName 10.0.0.%h\n  User admin\n  Port 2222\n  ConnectTimeout 1m30s\nHost *\n  User nobody\n  ServerAliveInterval 15\n", &["web", "db"]),
    (8, "Host a b\n  Port 1\nHost b\n  Port 2\n  User x\nHost * !b\n  User y\n", &["a", "b", "c"]),
    (8, "Match host *.lan\n  User lan\nHost web\n  HostName web.lan\n", &["web", "x.lan", "other"]),
    (8, "Host web\n  HostName real.example\nMatch originalhost web\n  Port 3\nMatch host real.example\n  User r\n", &["web"]),
    (8, "Match user root\n  Port 9\nHost *\n  User root\nMatch user root\n  Compression yes\n", &["h"]),
    (8, "Match all\n  ForwardAgent yes\n  StrictHostKeyChecking accept-new\n  RequestTTY force\n", &["h"]),
    (8, "Match !host foo\n  ServerAliveCountMax 7\n", &["foo", "bar"]),
    (8, "Host web\n  HostName web.example.com\nMatch final host web.example.com\n  User deploy\nMatch canonical\n  Port 77\n", &["web", "other"]),
    (8, "Host web\n  LocalForward 8080 db:5432\n  LocalForward [::1]:8081 [fd00::1]:22\n  DynamicForward 1080\n  RemoteForward 9000 localhost:9000\n  RemoteForward 9001\n", &["web"]),
    // OpenSSH 8.9 (Ubuntu 22.04) keeps the second A=; 9.5 and later the
    // first, as Reach does.
    (9, "Host web\n  SendEnv LANG LC_*\n  SendEnv -LC_*\n  SetEnv A=1 B=\"x y\" A=2\nHost *\n  SetEnv C=3\n", &["web", "x"]),
    (8, "Host web\n  IdentityFile ~/.ssh/id_a\n  IdentityFile ~/.ssh/id_a\nHost *\n  IdentityFile ~/.ssh/id_b\n  CertificateFile ~/.ssh/c\n", &["web"]),
    (8, "Host web\n  ProxyJump bastion\n  ProxyCommand nc %h %p\nHost db\n  ProxyCommand nc %h %p\n  ProxyJump bastion\n", &["web", "db"]),
    (8, "Host web\n  RekeyLimit 1G 1h\n  EscapeChar ^A\n  AddKeysToAgent confirm 5m\n  StreamLocalBindMask 0077\n  LogLevel debug2\n", &["web"]),
    (8, "Host web\n  IPQoS af21 cs1\n  TunnelDevice 1:2\n  Tunnel ethernet\n  CanonicalizeMaxDots 2\n  VisualHostKey yes\n", &["web"]),
    (8, "Port=2200\nUser = \"quoted user\"\nHostName\tspaced.example\n", &["h"]),
    (8, "IgnoreUnknown UseKeychain,Foo*\nUseKeychain yes\nFooBar 1\nPort 5\n", &["h"]),
    (8, "Host web\n  RemoteCommand echo %r@%h:%p %n\n  ControlPath /tmp/cm-%r@%h:%p\n  ControlMaster auto\n  ControlPersist 10m\n  User u\n", &["web"]),
    (10, "Host web\n  ChannelTimeout session=5m agent-connection=1h\n  ObscureKeystrokeTiming interval:40\n  EnableEscapeCommandline yes\n", &["web"]),
    (10, "Match tagged prod\n  User prodadmin\nHost web\n  Tag prod\nMatch tagged \"\"\n  Port 1\n", &["web", "x"]),
    (10, "Host old\n  User a\nMatch version OpenSSH_10*\n  Port 1010\n", &["old"]),
    // OpenSSH 8.9's ssh -G prints only the last PermitRemoteOpen value.
    (9, "Host web\n  PermitRemoteOpen localhost:80 [::1]:443\n  GatewayPorts yes\n  ExitOnForwardFailure yes\n  ClearAllForwardings no\n", &["web"]),
    (8, "Host web\n  KbdInteractiveDevices pam\n  PreferredAuthentications publickey,password\n  NumberOfPasswordPrompts 1\n  BatchMode yes\n  IdentitiesOnly yes\n  PubkeyAuthentication host-bound\n", &["web"]),
    (8, "Host web\n  UserKnownHostsFile ~/.ssh/kh1 ~/.ssh/kh2\n  GlobalKnownHostsFile none\n  HashKnownHosts yes\n  CheckHostIP yes\n  HostKeyAlias WebAlias\n  UpdateHostKeys ask\n", &["web"]),
    (8, "Host web\n  ServerAliveInterval none\n  ConnectionAttempts 3\n  TCPKeepAlive no\n  AddressFamily inet6\n  BindAddress 10.0.0.1\n", &["web"]),
];

fn ssh_bin() -> Option<(String, u32)> {
    let bin = std::env::var("REACH_SSH_BIN").unwrap_or_else(|_| "ssh".into());
    let out = std::process::Command::new(&bin).arg("-V").output().ok()?;
    let text = String::from_utf8_lossy(&out.stderr).to_string() + &String::from_utf8_lossy(&out.stdout);
    // "OpenSSH_10.3p1, …" or "OpenSSH_for_Windows_9.5p2, …"
    let v = text.split("OpenSSH_").nth(1)?.trim_start_matches("for_Windows_");
    let major: u32 = v.split('.').next()?.parse().ok()?;
    Some((bin, major))
}

fn ssh_g(bin: &str, config: &Path, host: &str) -> Vec<String> {
    let out = std::process::Command::new(bin).arg("-G").arg("-F").arg(config).arg(host).output().unwrap();
    assert!(out.status.success(), "ssh -G failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).lines().map(str::to_string).collect()
}

/// For every case, the lines ssh -G prints differently from an empty
/// config must all be among Reach's, and every line Reach prints must be
/// one ssh -G printed.
#[test]
fn agrees_with_ssh_g() {
    let Some((bin, major)) = ssh_bin() else {
        eprintln!("no OpenSSH client here; skipped");
        return;
    };
    let dir = std::env::temp_dir().join(format!("reach-sshconf-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let empty = dir.join("empty");
    std::fs::write(&empty, "").unwrap();
    let env = super::env::SystemEnv::new(super::env::ExecPolicy::Any);
    let home_probe = dir.join("home");
    std::fs::write(&home_probe, "IdentityAgent %d
").unwrap();
    let ssh_home = ssh_g(&bin, &home_probe, "h")
        .into_iter()
        .find_map(|l| l.strip_prefix("identityagent ").map(str::to_string))
        .unwrap_or_default();
    let mut checked = 0;
    let mut failures = Vec::new();
    for (i, (min, text, hosts)) in CORPUS.iter().enumerate() {
        if major < *min {
            continue;
        }
        let file = dir.join(format!("c{i}"));
        std::fs::write(&file, text).unwrap();
        for host in *hosts {
            let base: std::collections::HashSet<String> = ssh_g(&bin, &empty, host).into_iter().collect();
            let theirs = ssh_g(&bin, &file, host);
            let changed: Vec<&String> = theirs.iter().filter(|l| !base.contains(*l)).collect();
            let src = Source { path: file.clone(), text: Some(text.to_string()), user: true };
            let mut r = resolve(&[src], &Query { host: host.to_string(), ..Default::default() }, &env);
            let errors = r.finish(&env);
            assert!(errors.is_empty() && !r.has_errors(), "case {i} {host}: {errors:?} {:?}", r.notes);
            // The home directory as that ssh binary writes it (Git's MSYS
            // build says /c/Users/…).
            let home = super::resolve::Env::home(&env);
            let ours: Vec<String> = as_ssh_g(&r)
                .into_iter()
                .map(|l| if home != ssh_home && l.contains(&home) { l.replace(&home, &ssh_home).replace('\\', "/") } else { l })
                .collect();
            const ALGOS: &[&str] = &["ciphers ", "macs ", "kexalgorithms ", "hostkeyalgorithms ", "pubkeyacceptedalgorithms ", "casignaturealgorithms ", "hostbasedacceptedalgorithms "];
            for line in &changed {
                if ALGOS.iter().any(|a| line.starts_with(a)) || line.starts_with("host ") || line.starts_with("proxycommand ") {
                    continue;
                }
                // Defaults a config change switches on (UpdateHostKeys off
                // when UserKnownHostsFile is set, ExitOnForwardFailure…)
                // are derived when connecting; they are not config lines.
                if line.starts_with("updatehostkeys ") && !text.contains("UpdateHostKeys") {
                    continue;
                }
                // Debian's patch: ServerAliveInterval defaults to 300 under
                // BatchMode. Upstream (and Reach) keep 0.
                if *line == "serveraliveinterval 300" && text.contains("BatchMode yes") && !text.contains("ServerAliveInterval") {
                    continue;
                }
                // An ssh built without zlib (Apple's) prints "compression
                // UNKNOWN" for Compression yes; Reach has compression.
                if *line == "compression UNKNOWN" {
                    continue;
                }
                if !ours.contains(line) {
                    failures.push(format!("case {i} host {host}: ssh -G has \"{line}\""));
                }
            }
            for line in &ours {
                if line == "compression yes" && theirs.iter().any(|l| l == "compression UNKNOWN") {
                    continue;
                }
                if !theirs.contains(line) {
                    failures.push(format!("case {i} host {host}: Reach has \"{line}\""));
                }
            }
            checked += 1;
        }
    }
    std::fs::remove_dir_all(&dir).ok();
    eprintln!("checked {checked} host lookups against {bin} (OpenSSH {major})");
    assert!(failures.is_empty(), "{}", failures.join("
"));
    assert!(checked > 0);
}

/// Only approvals the connecting person signed for this session count, and
/// a stored session's typed lines need one like anything else.
#[test]
fn approvals_belong_to_who_gave_them() {
    use super::approvals::{sign, Kind};
    use super::session::{plan_for, SshOptions};
    use crate::ssh::hostkeys::Strict;
    let alice_key = [7u8; 32];
    let mallory_key = [9u8; 32];
    let stored = SshOptions {
        lines: vec!["ProxyCommand nc %h %p".into(), "StrictHostKeyChecking no".into()],
        approved_commands: vec![
            // Mallory, in alice's name, with her own key.
            sign(&mallory_key, "alice", Kind::Command, "s1", "nc %h %p"),
            // Alice's real approval, but for another session.
            sign(&alice_key, "alice", Kind::Command, "s2", "nc %h %p"),
            "nc %h %p".into(),
        ],
        accepted_weakenings: vec![sign(&alice_key, "alice", Kind::Weakening, "s1", "StrictHostKeyChecking no")],
        // A record can claim anything in the plain fields; reading replaces them.
        my_approved_commands: Some(vec!["nc %h %p".into()]),
        ..Default::default()
    };
    let mut alice = stored.clone();
    alice.open_for(Some(&alice_key), Some("alice"), "s1");
    assert_eq!(alice.my_approved_commands, Some(vec![]));
    assert_eq!(alice.my_accepted_weakenings, Some(vec!["StrictHostKeyChecking no".to_string()]));
    let used = alice.effective();
    let plan = plan_for(Some(&used), "h", 22, "u", false);
    assert!(plan.proxy_command.is_none() && plan.refused.is_some(), "the ProxyCommand waits for alice's own approval");
    assert_eq!(plan.hostkeys.map(|h| h.strict), Some(Strict::No));
    // Bob opens the same record: nothing is his, the typed line counts for nothing.
    let mut bob = stored.clone();
    bob.open_for(Some(&mallory_key), Some("bob"), "s1");
    let plan = plan_for(Some(&bob.effective()), "h", 22, "u", false);
    assert_ne!(plan.hostkeys.map(|h| h.strict), Some(Strict::No));
    // Saving signs alice's choices and keeps the rest for their owners.
    let mut saved = alice.clone();
    saved.my_approved_commands = Some(vec!["nc %h %p".into()]);
    saved.seal_for(Some(&alice_key), Some("alice"), "s1");
    assert!(saved.my_approved_commands.is_none());
    let mut reopened = saved.clone();
    reopened.open_for(Some(&alice_key), Some("alice"), "s1");
    assert_eq!(reopened.my_approved_commands, Some(vec!["nc %h %p".to_string()]));
}
