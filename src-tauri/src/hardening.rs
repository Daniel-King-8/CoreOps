//! Keeping other programs out of Reach's memory.
//!
//! While the vault is unlocked its keys are in this process's memory, as they
//! must be to decrypt anything. What this module stops is another program
//! running as the same user reading that memory: a scraper, a debugger
//! attaching, a dump of the process. It is the same hardening KeePassXC does.
//!
//! - Windows: the process's access list is replaced so that other processes
//!   of the user may only see that it is running, wait for it and end it, and
//!   may not change the list back. Reading or writing its memory and starting
//!   threads in it are refused, and no crash dump can be taken. LocalSystem
//!   keeps just what Windows' OpenSSH agent needs to answer Reach.
//! - Linux and Android: the process is marked not dumpable, which refuses
//!   debugger attach and `/proc/<pid>/mem` to other processes of the same
//!   user, and writes no core dump. It is reset for programs Reach starts.
//! - macOS: debuggers are refused attach.
//!
//! None of this stops an administrator or the kernel, and none of it is
//! allowed to stop Reach: a call the system refuses is logged and Reach
//! carries on without that protection.

/// Apply the protection for this platform. Called once, first thing at start.
pub fn protect_process() {
    match platform::protect() {
        Ok(()) => tracing::info!("Process memory protected from other programs"),
        Err(e) => tracing::warn!("Process memory protection unavailable: {}", e),
    }
}

#[cfg(windows)]
mod platform {
    //! After KeePassXC's `createWindowsDACL` (src/core/Bootstrap.cpp), which
    //! has shipped for years: the same three entries, the same rights.
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::Authorization::{SetSecurityInfo, SE_KERNEL_OBJECT};
    use windows::Win32::Security::{
        AddAccessAllowedAce, CreateWellKnownSid, GetLengthSid, GetTokenInformation, InitializeAcl, IsValidSid,
        TokenUser, WinCreatorOwnerRightsSid, WinLocalSystemSid, ACCESS_ALLOWED_ACE, ACL, ACL_REVISION,
        DACL_SECURITY_INFORMATION, PSID, SECURITY_MAX_SID_SIZE, TOKEN_QUERY, TOKEN_USER,
    };
    use windows::Win32::System::Threading::{
        GetCurrentProcess, OpenProcessToken, PROCESS_DUP_HANDLE, PROCESS_QUERY_INFORMATION,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
    };

    /// The user: see that the process exists, wait for it, end it. The same
    /// rights a protected process leaves; reading memory is not among them.
    const USER: u32 = PROCESS_SYNCHRONIZE.0 | PROCESS_QUERY_LIMITED_INFORMATION.0 | PROCESS_TERMINATE.0;
    /// "Owner rights": read the access list, not rewrite it. Left out, the
    /// owner keeps full control of the list and could grant itself the rest.
    const OWNER: u32 = 0x0002_0000; // READ_CONTROL
    /// LocalSystem, which Windows' OpenSSH agent service runs as: just enough
    /// for it to serve Reach's key requests.
    const SYSTEM: u32 = PROCESS_QUERY_INFORMATION.0 | PROCESS_DUP_HANDLE.0;

    pub fn protect() -> Result<(), String> {
        // SAFETY: plain Win32 calls on this process's own token and handle.
        // Every buffer is sized from the API's own answer or its documented
        // maximum and outlives the calls that use it; the token is closed on
        // every path.
        unsafe {
            let mut token = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
                .map_err(|e| format!("OpenProcessToken: {e}"))?;
            let result = apply(token);
            let _ = CloseHandle(token);
            result
        }
    }

    unsafe fn well_known(kind: windows::Win32::Security::WELL_KNOWN_SID_TYPE) -> Result<Vec<u8>, String> {
        let mut sid = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut size = SECURITY_MAX_SID_SIZE;
        unsafe { CreateWellKnownSid(kind, None, Some(PSID(sid.as_mut_ptr().cast())), &mut size) }
            .map_err(|e| format!("CreateWellKnownSid: {e}"))?;
        Ok(sid)
    }

    unsafe fn apply(token: HANDLE) -> Result<(), String> {
        let mut needed = 0u32;
        let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };
        let mut user_buf = vec![0u8; needed as usize];
        unsafe { GetTokenInformation(token, TokenUser, Some(user_buf.as_mut_ptr().cast()), needed, &mut needed) }
            .map_err(|e| format!("GetTokenInformation: {e}"))?;
        let user = unsafe { (*(user_buf.as_ptr() as *const TOKEN_USER)).User.Sid };
        if !unsafe { IsValidSid(user) }.as_bool() {
            return Err("the process token has no valid user".into());
        }
        let mut system_buf = unsafe { well_known(WinLocalSystemSid) }?;
        let mut owner_buf = unsafe { well_known(WinCreatorOwnerRightsSid) }?;
        let system = PSID(system_buf.as_mut_ptr().cast());
        let owner = PSID(owner_buf.as_mut_ptr().cast());

        let ace = std::mem::size_of::<ACCESS_ALLOWED_ACE>() as u32;
        let acl_size = std::mem::size_of::<ACL>() as u32
            + ace + unsafe { GetLengthSid(user) }
            + ace + unsafe { GetLengthSid(system) }
            + ace + unsafe { GetLengthSid(owner) };
        // u32-aligned, as an ACL must be.
        let mut acl_buf = vec![0u32; (acl_size as usize).div_ceil(4)];
        let acl = acl_buf.as_mut_ptr() as *mut ACL;
        unsafe {
            InitializeAcl(acl, acl_size, ACL_REVISION).map_err(|e| format!("InitializeAcl: {e}"))?;
            AddAccessAllowedAce(acl, ACL_REVISION, USER, user).map_err(|e| format!("user entry: {e}"))?;
            AddAccessAllowedAce(acl, ACL_REVISION, OWNER, owner).map_err(|e| format!("owner entry: {e}"))?;
            AddAccessAllowedAce(acl, ACL_REVISION, SYSTEM, system).map_err(|e| format!("system entry: {e}"))?;
        }

        let status = unsafe {
            SetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, None, None, Some(acl), None)
        };
        if status.is_err() {
            return Err(format!("SetSecurityInfo: {:?}", status));
        }
        Ok(())
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod platform {
    //! As KeePassXC does on Linux: no core file, and not dumpable. (It leaves
    //! the second out of Snap builds, where it breaks desktop portals; Reach
    //! does not ship as a Snap.)
    pub fn protect() -> Result<(), String> {
        let no_core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: setrlimit reads the struct it is given; prctl takes integers.
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) } != 0 {
            return Err(format!("setrlimit(RLIMIT_CORE): {}", std::io::Error::last_os_error()));
        }
        let status = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if status == 0 {
            Ok(())
        } else {
            Err(format!("prctl(PR_SET_DUMPABLE): {}", std::io::Error::last_os_error()))
        }
    }
}

#[cfg(target_os = "macos")]
mod platform {
    pub fn protect() -> Result<(), String> {
        // SAFETY: PT_DENY_ATTACH takes no address or data.
        let status = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
        if status == 0 {
            Ok(())
        } else {
            Err(format!("ptrace(PT_DENY_ATTACH): {}", std::io::Error::last_os_error()))
        }
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "android", target_os = "macos")))]
mod platform {
    pub fn protect() -> Result<(), String> {
        Err("not supported on this platform".into())
    }
}

#[cfg(test)]
mod tests {
    //! The protection tried the way an attacker would: a second copy of the
    //! test program protects itself, and this one, running as the same user,
    //! tries to get at it.
    const CHILD: &str = "REACH_HARDENING_CHILD";

    /// Run in the second copy: protect, say so, then wait to be killed.
    #[test]
    fn protected_child() {
        if std::env::var_os(CHILD).is_none() {
            return;
        }
        super::platform::protect().expect("protect");
        println!("READY {}", std::process::id());
        std::thread::sleep(std::time::Duration::from_secs(60));
    }

    /// Start the second copy and wait until it says it is protected. Used by
    /// the tests that try to reach into it, which exist on Windows and Linux.
    #[cfg(any(windows, target_os = "linux"))]
    fn spawn_protected() -> (std::process::Child, u32) {
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};

        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["hardening::tests::protected_child", "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let pid = loop {
            let line = lines.next().expect("the child exited").unwrap();
            // The test runner prints its own label on the same line first.
            if let Some((_, pid)) = line.split_once("READY ") {
                break pid.trim().parse().unwrap();
            }
        };
        (child, pid)
    }

    /// Whether this process holds SeDebugPrivilege, switched on. With it, an
    /// administrator opens any process whatever its security descriptor says,
    /// as Windows intends; it is Windows' root. GitHub's Windows runners run
    /// as such an administrator.
    #[cfg(windows)]
    fn debug_privilege_enabled() -> bool {
        use windows::core::w;
        use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
        use windows::Win32::Security::{
            GetTokenInformation, LookupPrivilegeValueW, TokenPrivileges, SE_PRIVILEGE_ENABLED, TOKEN_PRIVILEGES,
            TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        // SAFETY: querying this process's own token into a buffer sized by
        // the first call and aligned for TOKEN_PRIVILEGES; the handle is closed.
        unsafe {
            let mut debug = LUID::default();
            if LookupPrivilegeValueW(None, w!("SeDebugPrivilege"), &mut debug).is_err() {
                return false;
            }
            let mut token = HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                return false;
            }
            let mut len = 0u32;
            let _ = GetTokenInformation(token, TokenPrivileges, None, 0, &mut len);
            let mut buf = vec![0u32; (len as usize).div_ceil(4)];
            let ok = GetTokenInformation(token, TokenPrivileges, Some(buf.as_mut_ptr().cast()), len, &mut len).is_ok();
            let _ = CloseHandle(token);
            if !ok {
                return false;
            }
            let privileges = &*(buf.as_ptr() as *const TOKEN_PRIVILEGES);
            std::slice::from_raw_parts(privileges.Privileges.as_ptr(), privileges.PrivilegeCount as usize)
                .iter()
                .any(|p| p.Luid == debug && p.Attributes.0 & SE_PRIVILEGE_ENABLED.0 != 0)
        }
    }

    #[cfg(windows)]
    #[test]
    fn another_program_cannot_read_or_unlock_its_memory() {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
        };
        const WRITE_DAC: PROCESS_ACCESS_RIGHTS = PROCESS_ACCESS_RIGHTS(0x0004_0000);

        // An administrator with the debug privilege on may open any process,
        // as root may on Linux, so there is nothing to show from one.
        if debug_privilege_enabled() {
            eprintln!("skipped: this process has SeDebugPrivilege enabled, which opens any process");
            return;
        }
        let (mut child, pid) = spawn_protected();
        // SAFETY: OpenProcess on a pid we started; every handle is closed.
        unsafe {
            assert!(OpenProcess(PROCESS_VM_READ, false, pid).is_err(), "memory could be read");
            assert!(OpenProcess(WRITE_DAC, false, pid).is_err(), "the protection could be undone");
            let seen = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).expect("not even visible");
            let _ = CloseHandle(seen);
        }
        let _ = child.kill();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn another_program_cannot_read_its_memory() {
        // Root may read any process whatever it asks for, as the kernel
        // intends, so there is nothing to show as root (a container, say).
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let (mut child, pid) = spawn_protected();
        assert!(std::fs::File::open(format!("/proc/{pid}/mem")).is_err(), "memory could be opened");
        let _ = child.kill();
    }

    #[test]
    fn protecting_never_fails_the_app() {
        // Whatever the platform allows, the public call only logs.
        super::protect_process();
    }
}
