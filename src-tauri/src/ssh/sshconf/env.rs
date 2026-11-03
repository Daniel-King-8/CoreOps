//! The machine the resolver runs on: home, user, host name, networks, DNS,
//! files, and (when allowed) `Match exec` commands.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use super::resolve::Env;

/// Whether `Match exec` commands may run, and which.
#[derive(Debug, Clone)]
pub enum ExecPolicy {
    /// None run; the criterion fails and the import says so.
    Never,
    /// Only these exact commands (the user approved them).
    Approved(Vec<String>),
    /// Any (tests only).
    #[cfg(test)]
    Any,
}

pub struct SystemEnv {
    pub exec: ExecPolicy,
    /// `Match exec` commands asked for but not allowed to run.
    pub refused: std::cell::RefCell<Vec<String>>,
    /// What one resolve (or one import of many hosts) asks the system again
    /// and again, asked once: files, names, addresses. A SystemEnv lives for
    /// one scan or one connection, so nothing goes stale.
    cache: Cache,
}

#[derive(Default)]
struct Cache {
    home: std::cell::OnceCell<String>,
    user: std::cell::OnceCell<String>,
    host: std::cell::OnceCell<String>,
    addrs: std::cell::OnceCell<Vec<IpAddr>>,
    files: std::cell::RefCell<std::collections::HashMap<PathBuf, Option<String>>>,
    globs: std::cell::RefCell<std::collections::HashMap<String, Vec<PathBuf>>>,
}

impl SystemEnv {
    pub fn new(exec: ExecPolicy) -> Self {
        Self { exec, refused: Default::default(), cache: Cache::default() }
    }

    /// The user's config file: ~/.ssh/config.
    pub fn user_config() -> Option<PathBuf> {
        // A development build can be pointed at a config of its own, as at
        // a data folder of its own (REACH_DEV_DATA_DIR), so testing never
        // reads the user's real hosts. Compiled out of release builds.
        #[cfg(debug_assertions)]
        if let Some(p) = std::env::var_os("REACH_DEV_SSH_CONFIG").filter(|p| !p.is_empty()) {
            return Some(PathBuf::from(p));
        }
        dirs::home_dir().map(|h| h.join(".ssh").join("config"))
    }

    /// The system-wide file ssh reads after the user's.
    pub fn system_config() -> PathBuf {
        #[cfg(debug_assertions)]
        if let Some(p) = std::env::var_os("REACH_DEV_SSH_SYSTEM_CONFIG").filter(|p| !p.is_empty()) {
            return PathBuf::from(p);
        }
        PathBuf::from(system_dir()).join("ssh_config")
    }
}

fn system_dir() -> String {
    #[cfg(windows)]
    {
        let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
        format!(r"{base}\ssh")
    }
    #[cfg(not(windows))]
    {
        "/etc/ssh".into()
    }
}

impl Env for SystemEnv {
    fn home(&self) -> String {
        self.cache.home.get_or_init(|| dirs::home_dir().map(|h| h.display().to_string()).unwrap_or_default()).clone()
    }

    fn local_user(&self) -> String {
        self.cache.user.get_or_init(|| whoami::username().unwrap_or_default()).clone()
    }

    fn uid(&self) -> String {
        #[cfg(unix)]
        {
            // SAFETY: getuid cannot fail and has no preconditions.
            unsafe { libc::getuid() }.to_string()
        }
        #[cfg(not(unix))]
        {
            // What Windows' own OpenSSH (System32\OpenSSH\ssh.exe, 9.5)
            // expands %i to: `ssh -G -o ControlPath=%i h` prints 1.
            "1".into()
        }
    }

    fn local_host(&self) -> String {
        self.cache.host.get_or_init(|| gethostname::gethostname().to_string_lossy().into_owned()).clone()
    }

    fn system_dir(&self) -> String {
        system_dir()
    }

    fn read(&self, path: &Path) -> Option<String> {
        if let Some(hit) = self.cache.files.borrow().get(path) {
            return hit.clone();
        }
        let text = std::fs::read(path).ok().map(|b| String::from_utf8_lossy(&b).into_owned());
        self.cache.files.borrow_mut().insert(path.to_path_buf(), text.clone());
        text
    }

    fn glob(&self, pattern: &str) -> Vec<PathBuf> {
        if let Some(hit) = self.cache.globs.borrow().get(pattern) {
            return hit.clone();
        }
        let found: Vec<PathBuf> = match glob::glob(pattern) {
            Ok(paths) => paths.filter_map(Result::ok).filter(|p| p.is_file()).collect(),
            Err(_) => Vec::new(),
        };
        self.cache.globs.borrow_mut().insert(pattern.to_string(), found.clone());
        found
    }

    fn getenv(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }

    fn local_addresses(&self) -> Vec<IpAddr> {
        self.cache.addrs.get_or_init(|| if_addrs::get_if_addrs().map(|v| v.into_iter().map(|i| i.ip()).collect()).unwrap_or_default()).clone()
    }

    fn exec(&self, command: &str) -> Result<bool, String> {
        let allowed = match &self.exec {
            ExecPolicy::Never => false,
            ExecPolicy::Approved(list) => list.iter().any(|c| c == command),
            #[cfg(test)]
            ExecPolicy::Any => true,
        };
        if !allowed {
            self.refused.borrow_mut().push(command.to_string());
            return Err("not approved".into());
        }
        run_shell(command)
    }

    fn resolve(&self, name: &str) -> Option<String> {
        use std::net::ToSocketAddrs;
        // The standard library resolves without reporting a CNAME; the
        // name is returned as is, so CanonicalizePermittedCNAMEs has
        // nothing to follow. Reach resolves CNAMEs itself when connecting.
        (name.trim_end_matches('.'), 22).to_socket_addrs().ok()?.next()?;
        Some(String::new())
    }
}

/// Run a command the way ssh does (`$SHELL -c`, or `sh`); its exit status
/// is the answer.
#[cfg(not(target_os = "android"))]
pub fn run_shell(command: &str) -> Result<bool, String> {
    #[cfg(windows)]
    let status = {
        use std::os::windows::process::CommandExt;
        // Raw, so cmd sees the command line as written.
        std::process::Command::new("cmd").arg("/C").raw_arg(command).status()
    };
    #[cfg(not(windows))]
    let status = {
        let shell = std::env::var("SHELL").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "/bin/sh".into());
        std::process::Command::new(shell).args(["-c", command]).stdin(std::process::Stdio::null()).status()
    };
    status.map(|s| s.success()).map_err(|e| format!("could not run \"{command}\": {e}"))
}

#[cfg(target_os = "android")]
pub fn run_shell(command: &str) -> Result<bool, String> {
    Err(format!("A phone cannot run \"{command}\""))
}
