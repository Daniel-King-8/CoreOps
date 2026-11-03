//! ControlMaster, ControlPath and ControlPersist: sessions to the same
//! ControlPath share one connection, as ssh's multiplexing does (mux.c).
//! The first connection becomes the master; later ones open their session
//! on it without a new handshake or login. Without ControlPersist the
//! master lasts while any session uses it; with it, it stays that long
//! after the last one closes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use super::client::SharedHandle;

/// ControlMaster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Master {
    No,
    Yes,
    Auto,
    Ask,
    AutoAsk,
}

#[derive(Debug, Clone)]
pub struct ControlPlan {
    /// ControlPath, expanded.
    pub path: String,
    pub master: Master,
    /// ControlPersist: `None` off, `Some(None)` forever, else how long.
    pub persist: Option<Option<Duration>>,
}

impl ControlPlan {
    /// From the resolved values; `None` when ControlPath is unset or none.
    pub fn from(path: Option<&str>, master: Option<&str>, persist: Option<&str>) -> Option<Self> {
        let path = path.filter(|p| !p.eq_ignore_ascii_case("none"))?.to_string();
        let master = match master {
            Some("yes") => Master::Yes,
            Some("auto") => Master::Auto,
            Some("ask") => Master::Ask,
            Some("autoask") => Master::AutoAsk,
            _ => Master::No,
        };
        let persist = match persist {
            None | Some("no" | "false") => None,
            Some("yes" | "true") => Some(None),
            Some(t) => match super::sshconf::value::convtime(t) {
                Some(0) => Some(None),
                Some(s) if s > 0 => Some(Some(Duration::from_secs(s as u64))),
                _ => None,
            },
        };
        Some(ControlPlan { path, master, persist })
    }

    /// ssh tries an existing master first unless ControlMaster is yes or
    /// ask (those always start a new one).
    pub fn may_use(&self) -> bool {
        !matches!(self.master, Master::Yes | Master::Ask)
    }

    /// Whether this connection becomes a master for later ones.
    pub fn may_serve(&self) -> bool {
        self.master != Master::No
    }
}

struct Entry {
    /// "user@host:port" the master logged in to: a session reuses it only
    /// for that, never because two hosts' ControlPath happen to match.
    target: String,
    handle: Weak<tokio::sync::Mutex<russh::client::Handle<super::client::SshClientHandler>>>,
    jumps: Vec<Weak<tokio::sync::Mutex<russh::client::Handle<super::client::SshClientHandler>>>>,
    /// ControlPersist: the master held open while idle.
    keep: Option<SharedHandle>,
    persist: Option<Duration>,
    idle_since: Option<Instant>,
    /// ControlMaster ask/autoask: each new session is confirmed.
    asks: bool,
}

fn masters() -> &'static Mutex<HashMap<String, Entry>> {
    static M: OnceLock<Mutex<HashMap<String, Entry>>> = OnceLock::new();
    M.get_or_init(Default::default)
}

/// A live master for `path`: its connection, its jump hosts' connections,
/// and whether it asks before each new session.
pub fn existing(path: &str, target: &str) -> Option<(SharedHandle, Vec<SharedHandle>, bool)> {
    let mut m = masters().lock().unwrap();
    let e = m.get_mut(path)?;
    if e.target != target {
        tracing::warn!("ControlPath {path} belongs to a connection to {}, not {target}; connecting on its own", e.target);
        return None;
    }
    let Some(h) = e.handle.upgrade() else {
        m.remove(path);
        return None;
    };
    let jumps: Option<Vec<SharedHandle>> = e.jumps.iter().map(Weak::upgrade).collect();
    let Some(jumps) = jumps else {
        m.remove(path);
        return None;
    };
    e.idle_since = None;
    Some((h, jumps, e.asks))
}

/// Makes a new connection the master for its ControlPath, unless a live
/// one is there already (ssh: the socket is in use).
/// `target` names what the connection logged in to (see `target`).
pub fn register(plan: &ControlPlan, handle: &SharedHandle, jumps: &[SharedHandle], target: &str) {
    if !plan.may_serve() {
        return;
    }
    let mut m = masters().lock().unwrap();
    if m.get(&plan.path).is_some_and(|e| e.handle.strong_count() > 0) {
        tracing::info!("ControlPath {} already has a master; this connection is not shared", plan.path);
        return;
    }
    m.insert(
        plan.path.clone(),
        Entry {
            target: target.to_string(),
            handle: Arc::downgrade(handle),
            jumps: jumps.iter().map(Arc::downgrade).collect(),
            keep: plan.persist.map(|_| handle.clone()),
            persist: plan.persist.flatten(),
            idle_since: None,
            asks: matches!(plan.master, Master::Ask | Master::AutoAsk),
        },
    );
    drop(m);
    if plan.persist.is_some() {
        start_reaper();
    }
    tracing::info!("ControlMaster: sessions to ControlPath {} share this connection", plan.path);
}

/// What a connection logged in to, as masters are matched by it.
pub fn target(user: &str, host: &str, port: u16) -> String {
    format!("{user}@{}:{port}", host.to_ascii_lowercase())
}

/// Ends persisted masters once idle longer than ControlPersist, and any
/// whose connection has closed.
fn start_reaper() {
    static STARTED: OnceLock<()> = OnceLock::new();
    if STARTED.set(()).is_err() {
        return;
    }
    tokio::spawn(async {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tick.tick().await;
            reap(Instant::now());
        }
    });
}

fn reap(now: Instant) {
    let mut m = masters().lock().unwrap();
    m.retain(|path, e| {
        let Some(keep) = e.keep.as_ref() else { return e.handle.strong_count() > 0 };
        if keep.try_lock().is_ok_and(|h| h.is_closed()) {
            return false;
        }
        // Only the entry holds it: no session uses the master.
        if Arc::strong_count(keep) == 1 {
            let since = *e.idle_since.get_or_insert(now);
            if e.persist.is_some_and(|p| now.duration_since(since) >= p) {
                tracing::info!("ControlPersist: closing the idle master for {path}");
                return false;
            }
        } else {
            e.idle_since = None;
        }
        true
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans() {
        assert!(ControlPlan::from(None, Some("auto"), None).is_none());
        assert!(ControlPlan::from(Some("none"), Some("auto"), None).is_none());
        let p = ControlPlan::from(Some("/tmp/cm"), Some("auto"), Some("10m")).unwrap();
        assert!(p.may_use() && p.may_serve());
        assert_eq!(p.persist, Some(Some(Duration::from_secs(600))));
        let p = ControlPlan::from(Some("/tmp/cm"), Some("yes"), Some("yes")).unwrap();
        assert!(!p.may_use() && p.may_serve());
        assert_eq!(p.persist, Some(None));
        let p = ControlPlan::from(Some("/tmp/cm"), None, Some("0")).unwrap();
        assert!(p.may_use() && !p.may_serve());
        assert_eq!(p.persist, Some(None));
        assert_eq!(ControlPlan::from(Some("/tmp/cm"), Some("ask"), Some("no")).unwrap().persist, None);
    }
}

/// A second session through a master, and ControlPersist closing it when
/// idle. REACH_SSH_TEST, REACH_SSH_KEYS (k_good).
#[cfg(test)]
#[tokio::test]
#[ignore = "needs an SSH server"]
async fn live_control_master() {
    use super::client::{AuthParams, HopOptions, KeyAuth, KeySource, SshClientHandler};
    use super::sshconf::session::SshOptions;
    let a = std::env::var("REACH_SSH_TEST").unwrap();
    let (host, port) = a.rsplit_once(':').unwrap();
    let port: u16 = port.parse().unwrap();
    let key = std::fs::read_to_string(std::path::Path::new(&std::env::var("REACH_SSH_KEYS").unwrap()).join("k_good")).unwrap();
    let kh = std::env::temp_dir().join(format!("reach-cm-kh-{}", std::process::id()));
    let o = SshOptions {
        lines: vec![
            format!("UserKnownHostsFile {}", kh.display().to_string().replace('\\', "/")),
            "StrictHostKeyChecking accept-new".into(),
            "ControlMaster auto".into(),
            "ControlPath ~/.ssh/cm-%C".into(),
            "ControlPersist 30".into(),
        ],
        ..Default::default()
    };
    let opts: HopOptions = super::sshconf::session::plan_for(Some(&o), host, port, "reach", false).into();
    let cp = opts.control.clone().unwrap();
    let me = target("reach", host, port);
    assert!(cp.path.contains("cm-") && !cp.path.contains('%'), "{}", cp.path);
    assert!(existing(&cp.path, &me).is_none());

    let stream = super::sshconf::net::connect(host, port, &opts.socket, false).await.unwrap();
    let handler = SshClientHandler::new(host, port, None).with_hostkeys(opts.hostkeys.clone());
    let mut handle = russh::client::connect_stream(opts.config.clone(), stream, handler).await.unwrap();
    let auth = AuthParams { key: Some(KeyAuth { source: KeySource::Material(key), passphrase: None }), password: None, allow_agent: false };
    super::client::login(&mut handle, "reach", &auth, &opts, None, host, port).await.unwrap().into_result().unwrap();
    let shared: SharedHandle = Arc::new(tokio::sync::Mutex::new(handle));
    register(&cp, &shared, &[], &me);
    // Another target with the same ControlPath never gets this connection.
    assert!(existing(&cp.path, &target("reach", "other-host", port)).is_none());
    drop(shared);

    // The master outlives its own session under ControlPersist, and a
    // second session runs on it without logging in again.
    let (h, _, asks) = existing(&cp.path, &me).expect("a master");
    assert!(!asks);
    let mut ch = h.lock().await.channel_open_session().await.unwrap();
    ch.exec(true, "echo shared-$PPID").await.unwrap();
    let mut out = String::new();
    while let Ok(Some(msg)) = tokio::time::timeout(Duration::from_secs(5), ch.wait()).await {
        match msg {
            russh::ChannelMsg::Data { data } => out.push_str(&String::from_utf8_lossy(&data)),
            russh::ChannelMsg::ExitStatus { .. } => break,
            _ => {}
        }
    }
    println!("second session: {out:?}");
    assert!(out.starts_with("shared-"));
    drop(ch);
    drop(h);

    // Idle past ControlPersist: the master is closed.
    // (Looking without existing(), which counts as a use.)
    let alive = |p: &str| masters().lock().unwrap().contains_key(p);
    let now = Instant::now();
    reap(now);
    assert!(alive(&cp.path), "still within ControlPersist");
    reap(now + Duration::from_secs(31));
    assert!(!alive(&cp.path), "closed after ControlPersist");
    assert!(existing(&cp.path, &me).is_none());
    std::fs::remove_file(&kh).ok();
}
