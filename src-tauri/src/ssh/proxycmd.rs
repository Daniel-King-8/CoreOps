//! ProxyCommand: the connection to the server is a local program's stdin
//! and stdout, as sshconnect.c ssh_proxy_connect runs it (`exec command`
//! through the user's shell, `%h %k %n %p %r` expanded). With
//! ProxyUseFdpass the program instead hands back a connected socket over
//! a Unix socket pair (ssh_proxy_fdpass_connect).

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// What ssh_config set, approved by the user.
#[derive(Debug, Clone)]
pub struct ProxyCommand {
    pub command: String,
    pub use_fdpass: bool,
    /// %n: the host name as given (the Host alias).
    pub original_host: String,
    /// %k: HostKeyAlias or the alias.
    pub key_alias: String,
}

/// expand_proxy_command: only %h %k %n %p %r (and %%) are known; anything
/// else is an error, as in ssh.
pub fn expand(p: &ProxyCommand, host: &str, port: u16, user: &str) -> Result<String, String> {
    let mut out = String::new();
    let mut it = p.command.chars();
    while let Some(c) = it.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('%') => out.push('%'),
            Some('h') => out.push_str(host),
            Some('k') => out.push_str(&p.key_alias),
            Some('n') => out.push_str(&p.original_host),
            Some('p') => out.push_str(&port.to_string()),
            Some('r') => out.push_str(user),
            Some(t) => return Err(format!("ProxyCommand: unknown key %{t}")),
            None => return Err("ProxyCommand: invalid format".into()),
        }
    }
    Ok(out)
}

/// The proxy program, whose stdout and stdin are the connection. Killed
/// when the connection is dropped.
pub struct ProxyStream {
    _child: tokio::process::Child,
    stdout: tokio::process::ChildStdout,
    stdin: tokio::process::ChildStdin,
}

impl AsyncRead for ProxyStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stdout).poll_read(cx, buf)
    }
}

impl AsyncWrite for ProxyStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stdin).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stdin).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stdin).poll_shutdown(cx)
    }
}

#[cfg(not(target_os = "android"))]
fn shell_command(command: &str) -> tokio::process::Command {
    #[cfg(windows)]
    {
        // cmd parses its own command line: passed raw, as typed, so quotes
        // around a program path survive.
        let mut c = tokio::process::Command::new("cmd");
        c.arg("/C").raw_arg(command);
        c
    }
    #[cfg(not(windows))]
    {
        let shell = std::env::var("SHELL").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "/bin/sh".into());
        let mut c = tokio::process::Command::new(shell);
        // `exec` so the proxy is the shell's own process, as ssh does.
        c.args(["-c", &format!("exec {command}")]);
        c
    }
}

/// Start the proxy program; its stdio is the connection. Its stderr stays
/// with Reach's log, where ssh leaves it on the terminal.
#[cfg(not(target_os = "android"))]
pub fn spawn(command: &str) -> std::io::Result<ProxyStream> {
    let mut child = shell_command(command)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;
    let stdout = child.stdout.take().ok_or_else(|| std::io::Error::other("no stdout"))?;
    let stdin = child.stdin.take().ok_or_else(|| std::io::Error::other("no stdin"))?;
    Ok(ProxyStream { _child: child, stdout, stdin })
}

#[cfg(target_os = "android")]
pub fn spawn(command: &str) -> std::io::Result<ProxyStream> {
    Err(std::io::Error::other(format!("A phone cannot run ProxyCommand \"{command}\"")))
}

/// ProxyUseFdpass: the program writes a connected socket's descriptor to
/// its stdout, a Unix socket, with SCM_RIGHTS; that socket is the
/// connection.
#[cfg(all(unix, not(target_os = "android")))]
pub async fn fdpass(command: &str) -> std::io::Result<tokio::net::TcpStream> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let (ours, theirs) = std::os::unix::net::UnixStream::pair()?;
    let theirs_fd: OwnedFd = theirs.into();
    let stdout = std::process::Stdio::from(theirs_fd);
    let mut child = shell_command(command).stdin(std::process::Stdio::null()).stdout(stdout).spawn()?;
    let fd = tokio::task::spawn_blocking(move || -> std::io::Result<i32> {
        // mm_receive_fd: one byte of data and the descriptor in a
        // control message.
        let mut byte = [0u8; 1];
        let mut iov = libc::iovec { iov_base: byte.as_mut_ptr() as *mut _, iov_len: 1 };
        let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) } as usize;
        let mut cbuf = vec![0u8; space];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr() as *mut _;
        msg.msg_controllen = space as _;
        // SAFETY: msg points at buffers that live for the call.
        let n = unsafe { libc::recvmsg(ours.as_raw_fd(), &mut msg, 0) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: the control buffer was filled by recvmsg above.
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        if cmsg.is_null() {
            return Err(std::io::Error::other("ProxyUseFdpass: the proxy passed no descriptor"));
        }
        let (level, kind) = unsafe { ((*cmsg).cmsg_level, (*cmsg).cmsg_type) };
        if level != libc::SOL_SOCKET || kind != libc::SCM_RIGHTS {
            return Err(std::io::Error::other("ProxyUseFdpass: unexpected control message"));
        }
        let fd = unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(cmsg) as *const libc::c_int) };
        Ok(fd)
    })
    .await
    .map_err(std::io::Error::other)??;
    // The program's job is done once it has passed the socket.
    let _ = child.wait().await;
    // SAFETY: the descriptor was just received and is owned by nothing else.
    let std_stream = unsafe { std::net::TcpStream::from_raw_fd(fd) };
    std_stream.set_nonblocking(true)?;
    tokio::net::TcpStream::from_std(std_stream)
}

#[cfg(not(all(unix, not(target_os = "android"))))]
pub async fn fdpass(command: &str) -> std::io::Result<tokio::net::TcpStream> {
    Err(std::io::Error::other(format!("ProxyUseFdpass needs Unix descriptor passing, which this system has not (\"{command}\")")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(cmd: &str) -> ProxyCommand {
        ProxyCommand { command: cmd.into(), use_fdpass: false, original_host: "web".into(), key_alias: "web".into() }
    }

    #[test]
    fn tokens_are_sshs_five() {
        assert_eq!(expand(&p("nc %h %p # %r %n %k %%"), "10.0.0.1", 2222, "me").unwrap(), "nc 10.0.0.1 2222 # me web web %");
        assert!(expand(&p("nc %u"), "h", 22, "me").is_err());
    }
}
