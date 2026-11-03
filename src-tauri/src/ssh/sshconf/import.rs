//! Importing hosts from ~/.ssh/config: each concrete `Host` name, resolved
//! as ssh would, with the files it read kept for the session and a report
//! of every line.

use std::cell::RefCell;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::env::{ExecPolicy, SystemEnv};
use super::keyword::{lookup, Kw, Lookup};
use super::lex::{argv_split, split_keyword};
use super::report::{self, Report};
use super::resolve::{jump_hop, resolve, Env, Query, Source};
use super::session::{ConfigFile, FileRole, Imported, SshOptions};

/// The machine, with every file read noted.
struct Recording<'a> {
    sys: &'a SystemEnv,
    read: RefCell<Vec<(PathBuf, String)>>,
}

impl Env for Recording<'_> {
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
        let text = self.sys.read(path)?;
        let mut r = self.read.borrow_mut();
        if !r.iter().any(|(p, _)| p == path) {
            r.push((path.to_path_buf(), text.clone()));
        }
        Some(text)
    }
    fn glob(&self, pattern: &str) -> Vec<PathBuf> {
        self.sys.glob(pattern)
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

/// One hop of a ProxyJump, as the import resolves it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Hop {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub identity_files: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostImport {
    /// The `Host` name.
    pub alias: String,
    pub hostname: String,
    pub port: u16,
    pub user: String,
    pub identity_files: Vec<String>,
    /// Outermost first.
    pub proxy_jump: Vec<Hop>,
    /// What the new session stores.
    pub options: SshOptions,
    pub report: Report,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Scan {
    pub hosts: Vec<HostImport>,
    /// The files read, for the dialog to name.
    pub files: Vec<String>,
}

fn sources(user: &Path, system: &Path) -> Vec<Source> {
    vec![
        Source { path: user.to_path_buf(), text: None, user: true },
        Source { path: system.to_path_buf(), text: None, user: false },
    ]
}

/// The concrete names of `Host` lines in a file (no wildcards, no `!`).
fn host_names(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let Some(l) = split_keyword(raw) else { continue };
        if lookup(&l.keyword) != Lookup::Known(Kw::Host) {
            continue;
        }
        for p in argv_split(&l.rest).unwrap_or_default() {
            if !p.is_empty() && !p.starts_with('!') && !p.contains(['*', '?']) && !out.contains(&p) {
                out.push(p);
            }
        }
    }
    out
}

/// Read the files and resolve every concrete host in them.
pub fn scan(user: &Path, system: &Path) -> Scan {
    let sys = SystemEnv::new(ExecPolicy::Never);
    // A first read with a name no Host can match brings in every file,
    // Includes under blocks that do not apply included.
    let probe = Recording { sys: &sys, read: RefCell::new(Vec::new()) };
    let _ = resolve(&sources(user, system), &Query { host: "\u{1}reach-scan".into(), ..Default::default() }, &probe);
    let all_files = probe.read.into_inner();
    let system_path = system.to_path_buf();
    let mut names = Vec::new();
    for (path, text) in &all_files {
        if *path == system_path {
            continue;
        }
        for n in host_names(text) {
            if !names.contains(&n) {
                names.push(n);
            }
        }
    }
    let hosts = names.iter().map(|alias| import_host(alias, user, system, &sys)).collect();
    Scan { hosts, files: all_files.iter().map(|(p, _)| p.display().to_string()).collect() }
}

fn import_host(alias: &str, user: &Path, system: &Path, sys: &SystemEnv) -> HostImport {
    let env = Recording { sys, read: RefCell::new(Vec::new()) };
    sys.refused.borrow_mut().clear();
    let mut r = resolve(&sources(user, system), &Query { host: alias.into(), ..Default::default() }, &env);
    let finish_errors = r.finish(&env);
    let exec_asked = sys.refused.borrow().clone();
    let plan = super::apply::Plan::new(&r, russh::client::Config::default(), &[], false);
    let report = report::build(&r, &plan, &finish_errors, &exec_asked);
    let files: Vec<ConfigFile> = env
        .read
        .into_inner()
        .into_iter()
        .map(|(p, text)| {
            let role = if p == user {
                FileRole::User
            } else if p == system {
                FileRole::System
            } else {
                FileRole::Included
            };
            ConfigFile { path: p.display().to_string(), text, role }
        })
        .collect();
    let o = &r.options;
    let local_user = sys.local_user();
    let home = sys.home();
    let identity_files =
        o.identity_files.iter().map(|s| super::expand::tilde(&s.args[0], &home)).collect::<Vec<_>>();
    let proxy_jump = o
        .first(Kw::ProxyJump)
        .filter(|j| !j.eq_ignore_ascii_case("none"))
        .map(|spec| hops(spec, user, system, sys, &local_user, &mut vec![alias.to_string()]))
        .unwrap_or_default();
    HostImport {
        alias: alias.to_string(),
        hostname: r.host.clone(),
        port: o.first(Kw::Port).and_then(|p| p.parse().ok()).unwrap_or(22),
        user: o.first(Kw::User).map(str::to_string).unwrap_or_else(|| local_user.clone()),
        identity_files,
        proxy_jump,
        options: SshOptions {
            imported: Some(Imported { alias: alias.to_string(), files, at: chrono_now() }),
            ..Default::default()
        },
        report,
    }
}

fn chrono_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

/// A ProxyJump list, each hop resolved by its own name (as ssh does), its
/// own ProxyJump first. `seen` stops a loop.
fn hops(spec: &str, user: &Path, system: &Path, sys: &SystemEnv, local_user: &str, seen: &mut Vec<String>) -> Vec<Hop> {
    let mut out = Vec::new();
    for hop in spec.split(',') {
        let Ok((hop_user, name, hop_port)) = jump_hop(hop) else { continue };
        if seen.contains(&name) {
            continue;
        }
        seen.push(name.clone());
        let mut overrides = Vec::new();
        if let Some(p) = hop_port {
            overrides.push(("Port".to_string(), p.to_string()));
        }
        if let Some(u) = &hop_user {
            overrides.push(("User".to_string(), u.clone()));
        }
        let mut r = resolve(&sources(user, system), &Query { host: name.clone(), command: None, overrides }, sys);
        let _ = r.finish(sys);
        if let Some(inner) = r.options.first(Kw::ProxyJump).filter(|j| !j.eq_ignore_ascii_case("none")) {
            let inner = inner.to_string();
            out.extend(hops(&inner, user, system, sys, local_user, seen));
        }
        let home = sys.home();
        out.push(Hop {
            host: r.host.clone(),
            port: r.options.first(Kw::Port).and_then(|p| p.parse().ok()).unwrap_or(22),
            user: r.options.first(Kw::User).map(str::to_string).unwrap_or_else(|| local_user.to_string()),
            identity_files: r.options.identity_files.iter().map(|s| super::expand::tilde(&s.args[0], &home)).collect(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_listed_once_without_patterns() {
        assert_eq!(host_names("Host web db\n  User a\nHost web *.lan !x\nhost=other\n"), ["web", "db", "other"]);
    }

    #[test]
    fn a_whole_import_from_real_files() {
        let dir = std::env::temp_dir().join(format!("reach-import-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("conf.d")).unwrap();
        let user = dir.join("config");
        std::fs::write(
            &user,
            format!(
                "Include {}/conf.d/*.conf\nHost centreon\n  HostName 192.168.1.70\n  User root\n  MACs +hmac-sha1\n  StrictHostKeyChecking no\n  ProxyJump bastion\nHost *\n  ServerAliveInterval 30\n",
                dir.display().to_string().replace('\\', "/")
            ),
        )
        .unwrap();
        std::fs::write(dir.join("conf.d").join("b.conf"), "Host bastion\n  HostName 10.0.0.1\n  Port 2200\n  User jump\n").unwrap();
        let s = scan(&user, &dir.join("no-system-config"));
        let names: Vec<_> = s.hosts.iter().map(|h| h.alias.as_str()).collect();
        assert_eq!(names, ["centreon", "bastion"]);
        let c = s.hosts.iter().find(|h| h.alias == "centreon").unwrap();
        assert_eq!((c.hostname.as_str(), c.port, c.user.as_str()), ("192.168.1.70", 22, "root"));
        assert_eq!(c.proxy_jump.len(), 1);
        assert_eq!((c.proxy_jump[0].host.as_str(), c.proxy_jump[0].port, c.proxy_jump[0].user.as_str()), ("10.0.0.1", 2200, "jump"));
        let files = &c.options.imported.as_ref().unwrap().files;
        assert_eq!(files.len(), 2, "the user's file and the included one");
        let kws: Vec<_> = c.report.weakenings.iter().map(|w| w.keyword.as_str()).collect();
        assert!(kws.contains(&"MACs") && kws.contains(&"StrictHostKeyChecking"), "{kws:?}");
        // The stored copy resolves the same way, without the disk.
        std::fs::remove_dir_all(&dir).unwrap();
        let res = super::super::session::resolve_session(&c.options, "192.168.1.70", 22, "root");
        let r = res.resolved;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        assert_eq!(r.options.first(Kw::MACs), Some("+hmac-sha1"));
        assert_eq!(r.options.first(Kw::ServerAliveInterval), Some("30"));
    }
}
