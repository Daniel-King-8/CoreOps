//! Hostbased authentication, as OpenSSH's ssh does it (sshconnect2.c
//! userauth_hostbased and ssh_keysign, ssh.c loading the host's public
//! keys, ssh-keysign.c; RFC 4252 section 9). The machine's host keys
//! vouch for the local user. Their private halves are readable by root
//! only, so the signature comes from the setuid helper ssh-keysign, which
//! is enabled by EnableSSHKeysign in the system's ssh_config (it reads that
//! file itself) and checks the request against the connection's socket:
//! the client host name it signs for is the name of the socket's local
//! address. So hostbased needs the TCP socket itself, on Unix: through a
//! ProxyCommand or a jump host Reach has no socket to show, and the method
//! is skipped.
#![cfg_attr(not(unix), allow(dead_code))]

use std::sync::{Arc, Mutex};

/// One hostbased try: signature algorithm, key type, key blob.
type Attempt = (String, String, Vec<u8>);

/// What a session needs for hostbased: the algorithms to try, the
/// connection's socket once connected, and the host keys not yet tried.
#[derive(Debug, Default)]
pub struct HostbasedContext {
    /// HostbasedAcceptedAlgorithms, assembled.
    pub algorithms: Vec<String>,
    #[cfg(unix)]
    socket: Mutex<Option<std::os::fd::OwnedFd>>,
    /// (signature algorithm, key type, key blob) still to offer; filled on
    /// first use.
    queue: Mutex<Option<std::collections::VecDeque<Attempt>>>,
}

/// OpenSSH's default HostbasedAcceptedAlgorithms (KEX_DEFAULT_PK_ALG), as
/// far as Reach knows the names.
pub const DEFAULT_ALGORITHMS: &[&str] = crate::ssh::sshconf::apply::DEFAULT_PUBKEY_ALGORITHMS;

impl HostbasedContext {
    /// From HostbasedAuthentication and HostbasedAcceptedAlgorithms; `None`
    /// when hostbased is off. SHA-1 RSA and DSA names stay out unless the
    /// weakening was approved.
    pub fn from_options(o: &crate::ssh::sshconf::resolve::Options, plan: &crate::ssh::sshconf::apply::Plan) -> Option<Arc<HostbasedContext>> {
        use crate::ssh::sshconf::keyword::Kw;
        if o.first(Kw::HostbasedAuthentication) != Some("yes") {
            return None;
        }
        let algorithms = match o.first(Kw::HostbasedAcceptedAlgorithms) {
            Some(spec) => {
                let (names, _) = crate::ssh::sshconf::apply::assemble(spec, DEFAULT_ALGORITHMS, crate::ssh::sshconf::value::algos::KEYS);
                let approved = plan.approved(o, Kw::HostbasedAcceptedAlgorithms, spec);
                names.into_iter().filter(|n| approved || !(n.starts_with("ssh-rsa") || n.starts_with("ssh-dss"))).collect()
            }
            None => DEFAULT_ALGORITHMS.iter().map(|s| s.to_string()).collect(),
        };
        Some(Arc::new(HostbasedContext { algorithms, ..Default::default() }))
    }
}

/// Keep a copy of the connection's socket for ssh-keysign. Only a direct
/// TCP connection has one.
pub fn remember_socket(policy: Option<&crate::ssh::userauth::AuthPolicy>, stream: &tokio::net::TcpStream) {
    let Some(ctx) = policy.and_then(|p| p.hostbased.as_ref()) else { return };
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        match stream.as_fd().try_clone_to_owned() {
            Ok(fd) => *ctx.socket.lock().unwrap() = Some(fd),
            Err(e) => tracing::warn!("hostbased: cannot keep the socket: {e}"),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (ctx, stream);
    }
}

/// sshkey_match_keyname_to_sigalgs for one algorithm: an RSA key goes with
/// any RSA signature algorithm, other keys with their own name.
fn key_fits(key_type: &str, alg: &str) -> bool {
    match key_type {
        "ssh-rsa" => matches!(alg, "ssh-rsa" | "rsa-sha2-256" | "rsa-sha2-512"),
        "ssh-rsa-cert-v01@openssh.com" => matches!(
            alg,
            "ssh-rsa-cert-v01@openssh.com" | "rsa-sha2-256-cert-v01@openssh.com" | "rsa-sha2-512-cert-v01@openssh.com"
        ),
        _ => key_type == alg,
    }
}

/// One public key file line: its type and decoded blob, when the blob says
/// the same type.
fn read_pub(path: &std::path::Path) -> Option<(String, Vec<u8>)> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut parts = text.split_whitespace();
    let ktype = parts.next()?.to_string();
    let blob = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, parts.next()?).ok()?;
    let len = u32::from_be_bytes(blob.get(..4)?.try_into().ok()?) as usize;
    (blob.get(4..4 + len)? == ktype.as_bytes()).then_some((ktype, blob))
}

/// The host's public keys in the order ssh.c loads them: certificates
/// first, then plain keys, each ECDSA, Ed25519, RSA, ML-DSA.
fn host_keys(dir: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    let names = ["ssh_host_ecdsa_key", "ssh_host_ed25519_key", "ssh_host_rsa_key", "ssh_host_mldsa44_ed25519_key"];
    let certs = names.iter().filter_map(|n| read_pub(&dir.join(format!("{n}-cert.pub"))));
    let plain = names.iter().filter_map(|n| read_pub(&dir.join(format!("{n}.pub"))));
    certs.chain(plain).collect()
}

/// userauth_hostbased's order: each algorithm in turn, each key that fits
/// it, every key used at most once.
fn attempts(algorithms: &[String], mut keys: Vec<Option<(String, Vec<u8>)>>) -> std::collections::VecDeque<Attempt> {
    let mut out = std::collections::VecDeque::new();
    for alg in algorithms {
        for slot in keys.iter_mut() {
            if slot.as_ref().is_some_and(|(t, _)| key_fits(t, alg)) {
                let (t, b) = slot.take().unwrap();
                out.push_back((alg.clone(), t, b));
            }
        }
    }
    out
}

/// _PATH_SSH_KEY_SIGN as the usual builds install it.
#[cfg(unix)]
const KEYSIGN_PATHS: &[&str] = &[
    "/usr/libexec/ssh-keysign",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/libexec/openssh/ssh-keysign",
    "/usr/lib/ssh/ssh-keysign",
    "/usr/local/libexec/ssh-keysign",
];

/// The next hostbased attempt: one signed request with the next host key.
/// `None` when no key is left (or hostbased cannot work here), as ssh's
/// "No more client hostkeys for hostbased authentication."
pub(crate) async fn next_attempt<H: russh::client::Handler>(
    handle: &mut russh::client::Handle<H>,
    user: &str,
    ctx: &HostbasedContext,
) -> Option<Result<russh::client::AuthResult, String>> {
    #[cfg(unix)]
    {
        let sock = match ctx.socket.lock().unwrap().as_ref().map(|s| s.try_clone()) {
            Some(Ok(s)) => s,
            _ => {
                tracing::info!("hostbased: no TCP socket to show ssh-keysign (a ProxyCommand or jump host); skipped");
                return None;
            }
        };
        let next = {
            let mut q = ctx.queue.lock().unwrap();
            let q = q.get_or_insert_with(|| {
                let keys = host_keys(std::path::Path::new("/etc/ssh"));
                if keys.is_empty() {
                    tracing::info!("HostbasedAuthentication enabled but no local public host keys could be loaded.");
                }
                attempts(&ctx.algorithms, keys.into_iter().map(Some).collect())
            });
            q.pop_front()
        };
        let Some((alg, ktype, blob)) = next else {
            tracing::info!("No more client hostkeys for hostbased authentication.");
            return None;
        };
        let Some(keysign) = KEYSIGN_PATHS.iter().find(|p| std::path::Path::new(p).exists()) else {
            tracing::warn!("hostbased: ssh-keysign is not installed");
            return None;
        };
        let lname = match local_name(&sock) {
            Ok(n) => n,
            Err(e) => return Some(Err(format!("cannot get local ipaddr/name: {e}"))),
        };
        let chost = format!("{lname}.");
        let cuser = match local_user() {
            Some(u) => u,
            None => return Some(Err("cannot tell the local user name".into())),
        };
        tracing::info!("hostbased: trying host key {ktype} with {alg} as {cuser}@{chost}");
        let mut signer = Keysign { program: keysign.to_string(), socket: sock };
        let r = handle.authenticate_hostbased_with(user, &alg, blob, &chost, &cuser, &mut signer).await;
        Some(r.map_err(|e| e.0))
    }
    #[cfg(not(unix))]
    {
        let _ = (handle, user, ctx);
        tracing::info!("hostbased authentication needs ssh-keysign, which only Unix systems have; skipped");
        None
    }
}

/// Why signing failed.
#[derive(Debug)]
pub(crate) struct SignError(pub String);

impl From<russh::SendError> for SignError {
    fn from(_: russh::SendError) -> Self {
        SignError("connection closed".into())
    }
}

/// ssh-keysign as the signer.
#[cfg(unix)]
struct Keysign {
    program: String,
    socket: std::os::fd::OwnedFd,
}

#[cfg(unix)]
impl russh::HostbasedSigner for Keysign {
    type Error = SignError;

    #[allow(clippy::manual_async_fn)]
    fn sign_hostbased(&mut self, data: Vec<u8>) -> impl std::future::Future<Output = Result<Vec<u8>, Self::Error>> + Send {
        let program = self.program.clone();
        let socket = self.socket.try_clone();
        async move {
            let socket = socket.map_err(|e| SignError(e.to_string()))?;
            tokio::task::spawn_blocking(move || keysign(&program, socket, &data))
                .await
                .map_err(|e| SignError(e.to_string()))?
                .map_err(SignError)
        }
    }
}

/// ssh_msg_send: length, the version as the first byte, then the body.
fn msg_frame(version: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 5);
    out.extend_from_slice(&((body.len() + 1) as u32).to_be_bytes());
    out.push(version);
    out.extend_from_slice(body);
    out
}

/// The request ssh_keysign sends: the socket's descriptor number in the
/// helper, then the data to sign.
fn keysign_request(fd: u32, data: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(data.len() + 8);
    body.extend_from_slice(&fd.to_be_bytes());
    body.extend_from_slice(&(data.len() as u32).to_be_bytes());
    body.extend_from_slice(data);
    msg_frame(2, &body)
}

/// The reply: version 2, then the signature as a string.
fn keysign_reply(msg: &[u8]) -> Result<Vec<u8>, String> {
    let (&version, rest) = msg.split_first().ok_or("empty reply")?;
    if version != 2 {
        return Err("bad version".into());
    }
    let len = u32::from_be_bytes(rest.get(..4).ok_or("short reply")?.try_into().map_err(|_| "short reply")?) as usize;
    rest.get(4..4 + len).map(<[u8]>::to_vec).ok_or_else(|| "short reply".into())
}

/// ssh_keysign(): run the helper with the socket as descriptor 3 (the one
/// after stderr), send version 2 with that number and the data, and read
/// the signature back.
#[cfg(unix)]
fn keysign(program: &str, socket: std::os::fd::OwnedFd, data: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    const SOCK: i32 = 3;
    let raw = socket.as_raw_fd();
    let mut cmd = std::process::Command::new(program);
    cmd.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null());
    // SAFETY: only async-signal-safe calls (dup2, fcntl) between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            if raw == SOCK {
                if libc::fcntl(SOCK, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            } else if libc::dup2(raw, SOCK) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().map_err(|e| format!("{program}: {e}"))?;
    drop(socket);
    let mut stdin = child.stdin.take().ok_or("no stdin")?;
    stdin.write_all(&keysign_request(SOCK as u32, data)).map_err(|e| format!("couldn't send request: {e}"))?;
    drop(stdin);
    let mut stdout = child.stdout.take().ok_or("no stdout")?;
    let mut len = [0u8; 4];
    let reply = stdout.read_exact(&mut len).and_then(|()| {
        let mut msg = vec![0u8; u32::from_be_bytes(len) as usize];
        stdout.read_exact(&mut msg).map(|()| msg)
    });
    let status = child.wait().map_err(|e| format!("waitpid: {e}"))?;
    let msg = reply.map_err(|_| "no reply".to_string())?;
    if !status.success() {
        return Err(format!("{program} exited with {status}"));
    }
    keysign_reply(&msg)
}

/// get_local_name(): the name of the socket's local address (a reverse
/// lookup that must succeed), else this machine's host name.
#[cfg(unix)]
fn local_name(sock: &std::os::fd::OwnedFd) -> std::io::Result<String> {
    use std::os::fd::AsRawFd;
    // SAFETY: sockaddr_storage is plain data and large enough for any
    // address getsockname returns; getnameinfo writes at most the given
    // lengths.
    unsafe {
        let mut addr: libc::sockaddr_storage = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        if libc::getsockname(sock.as_raw_fd(), (&mut addr as *mut libc::sockaddr_storage).cast(), &mut len) == 0 {
            // ipv64_normalise_mapped: a v4-mapped IPv6 address as IPv4.
            if addr.ss_family as i32 == libc::AF_INET6 {
                let a6 = &*(&addr as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>();
                let o = a6.sin6_addr.s6_addr;
                if o[..10].iter().all(|b| *b == 0) && o[10] == 0xff && o[11] == 0xff {
                    let mut a4: libc::sockaddr_in = std::mem::zeroed();
                    a4.sin_family = libc::AF_INET as libc::sa_family_t;
                    a4.sin_port = a6.sin6_port;
                    a4.sin_addr.s_addr = u32::from_ne_bytes([o[12], o[13], o[14], o[15]]);
                    std::ptr::write((&mut addr as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in>(), a4);
                    len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
                }
            }
            if matches!(addr.ss_family as i32, libc::AF_INET | libc::AF_INET6) {
                let mut host = [0 as libc::c_char; 1025];
                if libc::getnameinfo((&addr as *const libc::sockaddr_storage).cast(), len, host.as_mut_ptr(), host.len() as _, std::ptr::null_mut(), 0, libc::NI_NAMEREQD) == 0 {
                    return Ok(std::ffi::CStr::from_ptr(host.as_ptr()).to_string_lossy().into_owned());
                }
            }
        }
        let mut name = [0 as libc::c_char; 256];
        if libc::gethostname(name.as_mut_ptr(), name.len()) != 0 {
            return Ok("UNKNOWN".into());
        }
        Ok(std::ffi::CStr::from_ptr(name.as_ptr()).to_string_lossy().into_owned())
    }
}

/// The local user's name from the password database, as ssh-keysign
/// compares it (getpwuid(getuid())).
#[cfg(unix)]
fn local_user() -> Option<String> {
    // SAFETY: getpwuid's result is read at once, before any other call.
    unsafe {
        let pw = libc::getpwuid(libc::getuid());
        if pw.is_null() {
            return None;
        }
        Some(std::ffi::CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_follows_the_algorithms_and_uses_each_key_once() {
        let k = |t: &str| Some((t.to_string(), vec![]));
        let algs: Vec<String> = ["ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256", "ecdsa-sha2-nistp256"].iter().map(|s| s.to_string()).collect();
        let q = attempts(&algs, vec![k("ecdsa-sha2-nistp256"), k("ssh-ed25519"), k("ssh-rsa")]);
        let got: Vec<(String, String)> = q.into_iter().map(|(a, t, _)| (a, t)).collect();
        assert_eq!(
            got,
            vec![
                ("ssh-ed25519".into(), "ssh-ed25519".into()),
                ("rsa-sha2-512".into(), "ssh-rsa".into()),
                ("ecdsa-sha2-nistp256".into(), "ecdsa-sha2-nistp256".into()),
            ]
        );
    }

    #[test]
    fn keysign_messages() {
        let req = keysign_request(3, b"abc");
        assert_eq!(req, [0, 0, 0, 12, 2, 0, 0, 0, 3, 0, 0, 0, 3, b'a', b'b', b'c']);
        assert_eq!(keysign_reply(&[2, 0, 0, 0, 2, 9, 8]).unwrap(), vec![9, 8]);
        assert!(keysign_reply(&[1, 0, 0, 0, 0]).is_err());
        assert!(keysign_reply(&[2, 0, 0, 0, 5, 1]).is_err());
    }

    #[test]
    fn public_key_files() {
        let dir = std::env::temp_dir().join(format!("reach-hb-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let k = russh::keys::PrivateKey::from(russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[4; 32]));
        std::fs::write(dir.join("ssh_host_ed25519_key.pub"), k.public_key().to_openssh().unwrap() + " root@h\n").unwrap();
        std::fs::write(dir.join("ssh_host_rsa_key.pub"), "ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n").unwrap();
        let keys = host_keys(&dir);
        assert_eq!(keys.len(), 1, "a file whose blob names another type is ignored");
        assert_eq!(keys[0].0, "ssh-ed25519");
        assert_eq!(keys[0].1, k.public_key().to_bytes().unwrap());
        std::fs::remove_dir_all(&dir).ok();
    }
}
