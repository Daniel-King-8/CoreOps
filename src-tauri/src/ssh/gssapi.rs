//! gssapi-with-mic (RFC 4462) with Kerberos v5, as OpenSSH's ssh does it
//! (sshconnect2.c userauth_gssapi, gss-genr.c): the mechanism is tried
//! before it is offered, a fresh context is made once the server picks it,
//! mutual authentication and integrity are asked for, credentials are
//! delegated only with GSSAPIDelegateCredentials, and the exchange ends
//! with a MIC over the userauth data. The system's Kerberos does the work:
//! the GSSAPI library, loaded at run time, on Linux, macOS and the BSDs,
//! and SSPI on Windows.
//!
//! GSSAPIClientIdentity, GSSAPIServerIdentity and GSSAPITrustDns follow the
//! GSSAPI patch Debian and Fedora carry (openssh-gsskex), and so does
//! GSS-API key exchange (GSSAPIKeyExchange, GSSAPIKexAlgorithms,
//! GSSAPIRenewalForcesRekey; kexgssc.c, gss-genr.c): russh runs the
//! exchange, the contexts come from here.

use std::net::{IpAddr, ToSocketAddrs};

use russh::{GssapiAuthenticator, GssapiError, GssapiStep};
use russh::client::{AuthResult, Handle, Handler};

use super::client::SshError;

/// Kerberos v5, 1.2.840.113554.1.2.2, without its DER tag and length.
pub const KRB5_OID: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];

/// The mechanism as it goes on the wire: tag 06, length, then the OID.
pub fn krb5_mech() -> Vec<u8> {
    let mut v = vec![0x06, KRB5_OID.len() as u8];
    v.extend_from_slice(&KRB5_OID);
    v
}

/// What ssh_config says about GSSAPI logins.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GssapiPolicy {
    /// GSSAPIDelegateCredentials, once approved.
    pub delegate: bool,
    /// GSSAPIClientIdentity: the principal to log in as, instead of the
    /// default credentials.
    pub client_identity: Option<String>,
    /// GSSAPIServerIdentity: the host part of the server's name.
    pub server_identity: Option<String>,
    /// GSSAPITrustDns: the server's name from its address, checked both ways.
    pub trust_dns: bool,
    /// Through ProxyCommand or ProxyJump, where ssh has no address to look up.
    pub proxied: bool,
}

impl GssapiPolicy {
    pub fn from_options(o: &super::sshconf::resolve::Options) -> GssapiPolicy {
        use super::sshconf::keyword::Kw;
        let set = |kw: Kw| o.first(kw).filter(|v| !v.eq_ignore_ascii_case("none")).map(str::to_string);
        GssapiPolicy {
            delegate: o.first(Kw::GSSAPIDelegateCredentials) == Some("yes"),
            client_identity: set(Kw::GSSAPIClientIdentity),
            server_identity: set(Kw::GSSAPIServerIdentity),
            trust_dns: o.first(Kw::GSSAPITrustDns) == Some("yes"),
            proxied: set(Kw::ProxyJump).is_some() || set(Kw::ProxyCommand).is_some(),
        }
    }
}

/// GSSAPIKexAlgorithms when it is not set: GSS_KEX_DEFAULT_KEX in ssh-gss.h.
pub const DEFAULT_KEX_ALGORITHMS: &str =
    "gss-group14-sha256-,gss-group16-sha512-,gss-nistp256-sha256-,gss-curve25519-sha256-,gss-group14-sha1-,gss-gex-sha1-";

/// kex_gss_names_valid: every name up to the first empty one starts with
/// `gss-` and with one of the method prefixes.
pub fn kex_names_valid(names: &str) -> bool {
    !names.is_empty()
        && names.split(',').take_while(|p| !p.is_empty()).all(|p| {
            p.starts_with("gss-") && russh::kex::GSS_KEX_ALGORITHMS.iter().any(|(prefix, _)| p.starts_with(prefix))
        })
}

/// ssh_gssapi_kex_mechs for Kerberos v5: each name of the list with the
/// mechanism's suffix, in the list's order. A name that is more than a
/// prefix makes a method no server offers, so it is left out.
pub fn kex_algorithms(names: &str) -> Vec<russh::kex::Name> {
    names
        .split(',')
        .take_while(|p| !p.is_empty())
        .filter_map(|p| {
            let full = format!("{p}{}", russh::kex::gss::KRB5_SUFFIX);
            russh::kex::GSS_KEX_ALGORITHMS.iter().find(|(_, n)| n.as_ref() == full).map(|(_, n)| *n)
        })
        .collect()
}

/// GSSAPIKeyExchange yes, with what goes with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GssKexPolicy {
    /// The server's name, the client identity and delegation, as for
    /// gssapi-with-mic.
    pub gss: GssapiPolicy,
    /// GSSAPIKexAlgorithms, as method names.
    pub algorithms: Vec<russh::kex::Name>,
    /// GSSAPIRenewalForcesRekey.
    pub renewal_rekey: bool,
}

impl GssKexPolicy {
    pub fn from_options(o: &super::sshconf::resolve::Options) -> Option<GssKexPolicy> {
        use super::sshconf::keyword::Kw;
        if o.first(Kw::GSSAPIKeyExchange) != Some("yes") {
            return None;
        }
        Some(GssKexPolicy {
            gss: GssapiPolicy::from_options(o),
            algorithms: kex_algorithms(o.first(Kw::GSSAPIKexAlgorithms).unwrap_or(DEFAULT_KEX_ALGORITHMS)),
            renewal_rekey: o.first(Kw::GSSAPIRenewalForcesRekey) == Some("yes"),
        })
    }
}

/// The contexts of GSS-API key exchanges with one server, and the
/// credentials as they were at the last exchange (GSSAPIRenewalForcesRekey).
#[derive(Debug)]
pub(crate) struct KexProvider {
    host: String,
    client: Option<String>,
    delegate: bool,
    renewal: bool,
    state: std::sync::Mutex<Renewal>,
}

#[derive(Debug, Default)]
struct Renewal {
    /// The principal and the time its credentials end, after the last key
    /// exchange that delegated them.
    saved: Option<(String, u64)>,
    last_call: Option<std::time::Instant>,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

impl KexProvider {
    /// ssh_gssapi_credentials_updated(NULL): at most every 10 seconds, the
    /// same principal whose credentials now end more than 10 seconds later
    /// than at the last exchange.
    fn renewed(&self, now: u64, inquire: impl FnOnce() -> Result<(String, u64), String>) -> bool {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.last_call.is_some_and(|t| t.elapsed() < std::time::Duration::from_secs(10)) {
            return false;
        }
        st.last_call = Some(std::time::Instant::now());
        let Some((saved_name, saved_end)) = st.saved.clone() else { return false };
        match inquire() {
            Ok((name, lifetime)) => name == saved_name && saved_end < (lifetime + now).saturating_sub(10),
            Err(_) => false,
        }
    }
}

impl russh::kex::gss::GssKexProvider for KexProvider {
    fn context(&self) -> Result<Box<dyn russh::kex::gss::GssKexContext>, String> {
        Ok(Box::new(KexContext(sys::Context::new(&self.host, self.client.as_deref(), self.delegate)?)))
    }

    /// ssh_gssapi_credentials_updated(ctxt), called when credentials were
    /// delegated: the credentials as they now are.
    fn exchanged(&self) {
        if !self.delegate {
            return;
        }
        tracing::debug!("GSSAPI: rekey has happened - updating saved versions");
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Ok((name, lifetime)) = sys::inquire_cred() {
            st.saved = Some((name, lifetime + now_secs()));
        }
    }

    fn renewal_rekey(&self) -> bool {
        self.renewal
    }

    fn credentials_renewed(&self) -> bool {
        self.renewed(now_secs(), sys::inquire_cred)
    }
}

/// One key exchange's context.
struct KexContext(sys::Context);

impl russh::kex::gss::GssKexContext for KexContext {
    fn init(&mut self, input: Option<&[u8]>) -> Result<russh::kex::gss::GssKexStep, String> {
        let o = self.0.step(input)?;
        Ok(russh::kex::gss::GssKexStep { token: o.token, complete: o.complete, mutual: o.mutual, integ: o.integ })
    }

    fn verify_mic(&mut self, data: &[u8], mic: &[u8]) -> Result<(), String> {
        self.0.verify_mic(data, mic)
    }

    fn get_mic(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        self.0.mic(data)
    }
}

/// ssh_kex2's part of the GSSAPI patch: the server's name, then the
/// mechanism tried (ssh_gssapi_client_mechanisms); when it works, the
/// engine offers the GSS-API methods in front of its own and the `null`
/// host key last. `None` when it does not: then the key exchange is the
/// usual one.
pub(crate) async fn kex_config(base: &std::sync::Arc<russh::client::Config>, k: &GssKexPolicy, host: &str) -> Option<russh::client::Config> {
    if k.algorithms.is_empty() {
        tracing::warn!("SSH GSSAPI key exchange: GSSAPIKexAlgorithms names no method; not offered");
        return None;
    }
    let (h, policy) = (host.to_string(), k.gss.clone());
    let checked = tokio::task::spawn_blocking(move || {
        let target = target_host(&policy, &h);
        probe(&target, policy.client_identity.as_deref()).map(|_| target)
    })
    .await;
    let target = match checked {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            tracing::warn!("SSH GSSAPI key exchange: not offered: {e}");
            return None;
        }
        Err(e) => {
            tracing::warn!("SSH GSSAPI key exchange: {e}");
            return None;
        }
    };
    let names: Vec<&str> = k.algorithms.iter().map(|n| n.as_ref()).collect();
    tracing::info!("SSH: offering GSSAPI proposal: {} (Kerberos for host@{target})", names.join(","));
    let mut c = (**base).clone();
    let mut kex = k.algorithms.clone();
    kex.extend(c.preferred.kex.iter().filter(|n| !k.algorithms.contains(n)).copied());
    c.preferred.kex = std::borrow::Cow::Owned(kex);
    c.gss_kex = Some(std::sync::Arc::new(KexProvider {
        host: target,
        client: k.gss.client_identity.clone(),
        delegate: k.gss.delegate,
        renewal: k.renewal_rekey,
        state: Default::default(),
    }));
    Some(c)
}

/// The host in the server's name `host@<host>`: GSSAPIServerIdentity, else
/// with GSSAPITrustDns the name the server's address maps back to, else the
/// host name, lowercased as ssh does. Blocks on DNS.
pub fn target_host(p: &GssapiPolicy, host: &str) -> String {
    if let Some(s) = &p.server_identity {
        return s.clone();
    }
    let host = host.to_ascii_lowercase();
    if !p.trust_dns || p.proxied {
        return host;
    }
    // ssh asks the socket for the address it connected to; this is the
    // first address the name resolves to, which is the one tried first.
    match (host.as_str(), 0).to_socket_addrs().ok().and_then(|mut a| a.next()) {
        Some(addr) => remote_name(addr.ip(), reverse(addr.ip()), |name| {
            (name, 0).to_socket_addrs().map(|a| a.map(|s| s.ip()).collect()).unwrap_or_default()
        }),
        None => host,
    }
}

/// remote_hostname in canohost.c: the reverse name of `addr` when it maps
/// back to `addr`, else the address itself.
fn remote_name(addr: IpAddr, reverse: Option<String>, forward: impl Fn(&str) -> Vec<IpAddr>) -> String {
    let ntop = addr.to_string();
    let Some(name) = reverse else { return ntop };
    if name.parse::<IpAddr>().is_ok() {
        tracing::warn!("GSSAPITrustDns: nasty PTR record \"{name}\" is set up for {ntop}, ignoring");
        return ntop;
    }
    let name = name.to_ascii_lowercase();
    if forward(&name).contains(&addr) {
        name
    } else {
        tracing::warn!("GSSAPITrustDns: address {ntop} maps to {name}, but this does not map back to the address");
        ntop
    }
}

/// The name an address's PTR record gives, if it has one.
fn reverse(addr: IpAddr) -> Option<String> {
    let sa = socket2::SockAddr::from(std::net::SocketAddr::new(addr, 0));
    #[cfg(unix)]
    {
        let mut host = [0 as libc::c_char; 1025];
        // SAFETY: `sa` is a valid socket address of `sa.len()` bytes and
        // `host` is writable for its whole length.
        let r = unsafe {
            libc::getnameinfo(sa.as_ptr().cast(), sa.len(), host.as_mut_ptr(), host.len() as _, std::ptr::null_mut(), 0, libc::NI_NAMEREQD)
        };
        if r != 0 {
            return None;
        }
        // SAFETY: getnameinfo wrote a NUL-terminated string into `host`.
        let name = unsafe { std::ffi::CStr::from_ptr(host.as_ptr()) };
        Some(name.to_string_lossy().into_owned())
    }
    #[cfg(windows)]
    {
        use windows::Win32::Networking::WinSock::{socklen_t, GetNameInfoW, NI_NAMEREQD, SOCKADDR};
        let mut host = [0u16; 1025];
        // SAFETY: as above; Winsock is started, the name was just resolved.
        let r = unsafe { GetNameInfoW(sa.as_ptr().cast::<SOCKADDR>(), socklen_t(sa.len()), Some(&mut host), None, NI_NAMEREQD as i32) };
        if r != 0 {
            return None;
        }
        let end = host.iter().position(|&c| c == 0).unwrap_or(host.len());
        Some(String::from_utf16_lossy(&host[..end]))
    }
}

/// The server's choice must be the mechanism offered. A badly encoded OID
/// makes ssh move on to the next method; a different one is fatal there.
pub fn check_selected(oid: &[u8]) -> Result<(), String> {
    if oid.len() <= 2 || oid[0] != 0x06 || oid[1] as usize != oid.len() - 2 {
        return Err("badly encoded mechanism OID received".into());
    }
    if oid[2..] != KRB5_OID {
        return Err("server returned a different OID than offered".into());
    }
    Ok(())
}

/// One step of the context: the token to send, and whether it is complete
/// with integrity protection (a MIC follows) or without.
#[cfg_attr(target_os = "android", allow(dead_code))]
pub(crate) struct Out {
    pub token: Vec<u8>,
    pub complete: bool,
    pub mutual: bool,
    pub integ: bool,
}

/// ssh_gssapi_check_mechanism: a first context, made and thrown away, so
/// the method is offered only when there is a ticket for the server.
pub(crate) fn probe(host: &str, client: Option<&str>) -> Result<(), String> {
    let mut c = sys::Context::new(host, client, false)?;
    c.step(None).map(|_| ())
}

#[derive(Debug)]
pub(crate) enum GssFail {
    Send,
    Gss(String),
}

impl From<russh::SendError> for GssFail {
    fn from(_: russh::SendError) -> Self {
        GssFail::Send
    }
}

/// The client side of one exchange, with Kerberos v5.
pub(crate) struct Krb5 {
    host: String,
    policy: GssapiPolicy,
    ctx: Option<sys::Context>,
}

/// process_gssapi_token: one call to the context; once complete, the MIC
/// when integrity was granted, else exchange-complete.
fn advance(ctx: &mut sys::Context, input: Option<&[u8]>, mic_data: &[u8]) -> Result<GssapiStep, String> {
    let out = ctx.step(input)?;
    if !out.complete {
        return Ok(GssapiStep::Continue { token: out.token });
    }
    let token = (!out.token.is_empty()).then_some(out.token);
    let mic = if out.integ { Some(ctx.mic(mic_data)?) } else { None };
    Ok(GssapiStep::Complete { token, mic })
}

impl GssapiAuthenticator for Krb5 {
    type Error = GssFail;

    #[allow(clippy::manual_async_fn)]
    fn gssapi_step(
        &mut self,
        selected_mechanism: Option<Vec<u8>>,
        input_token: Option<Vec<u8>>,
        mic_data: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<GssapiStep, Self::Error>> + Send {
        async move {
            if let Some(oid) = &selected_mechanism {
                check_selected(oid).map_err(GssFail::Gss)?;
                self.ctx = None;
            }
            let ctx = self.ctx.take();
            let (host, client, delegate) = (self.host.clone(), self.policy.client_identity.clone(), self.policy.delegate);
            // The library blocks on the KDC; keep it off the async threads.
            let (ctx, r) = tokio::task::spawn_blocking(move || {
                let mut ctx = match ctx {
                    Some(c) => c,
                    None => match sys::Context::new(&host, client.as_deref(), delegate) {
                        Ok(c) => c,
                        Err(e) => return (None, Err(e)),
                    },
                };
                let r = advance(&mut ctx, input_token.as_deref(), &mic_data);
                (Some(ctx), r)
            })
            .await
            .map_err(|e| GssFail::Gss(e.to_string()))?;
            self.ctx = ctx;
            r.map_err(GssFail::Gss)
        }
    }

    fn gssapi_error(&mut self, error: GssapiError) -> impl std::future::Future<Output = ()> + Send {
        match error {
            GssapiError::Status { message, .. } => tracing::info!("SSH gssapi-with-mic: server GSSAPI error: {message}"),
            GssapiError::ErrorToken(t) => tracing::info!("SSH gssapi-with-mic: server sent an error token ({} bytes)", t.len()),
        }
        async {}
    }
}

/// One gssapi-with-mic attempt, as userauth_gssapi makes it. `None` when
/// the mechanism cannot be used here (no library, no ticket for the
/// server), so it is not offered, or when the exchange failed part way and
/// ssh would go on with the next method.
pub(crate) async fn authenticate<H: Handler>(
    handle: &mut Handle<H>,
    user: &str,
    host: &str,
    p: &GssapiPolicy,
) -> Result<Option<AuthResult>, SshError> {
    let (h, policy) = (host.to_string(), p.clone());
    let checked = tokio::task::spawn_blocking(move || {
        let target = target_host(&policy, &h);
        probe(&target, policy.client_identity.as_deref()).map(|_| target)
    })
    .await;
    let target = match checked {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            tracing::warn!("SSH gssapi-with-mic: not offered: {e}");
            return Ok(None);
        }
        Err(e) => {
            tracing::warn!("SSH gssapi-with-mic: {e}");
            return Ok(None);
        }
    };
    tracing::info!("SSH gssapi-with-mic: Kerberos for host@{target}{}", if p.delegate { ", delegating credentials" } else { "" });
    let mut k = Krb5 { host: target, policy: p.clone(), ctx: None };
    match handle.authenticate_gssapi_with_mic(user, vec![krb5_mech()], &mut k).await {
        Ok(r) => Ok(Some(r)),
        Err(GssFail::Send) => Err(SshError::ConnectionFailed("Auth error: connection closed".into())),
        Err(GssFail::Gss(e)) => {
            tracing::warn!("SSH gssapi-with-mic: {e}");
            Ok(None)
        }
    }
}

/// The GSSAPI library (MIT Kerberos, Heimdal, or Apple's GSS framework),
/// loaded when first needed so Reach does not depend on it to start.
#[cfg(all(unix, not(target_os = "android")))]
mod sys {
    use std::ffi::c_void;
    use std::ptr::null_mut;
    use std::sync::OnceLock;

    use super::Out;

    type Om = u32;
    type Name = *mut c_void;
    type Ctx = *mut c_void;
    type Cred = *mut c_void;

    // gssapi.h packs its structs to 2 bytes on x86_64 macOS, both Apple's
    // and MIT's, for compatibility with the old Kerberos framework.
    #[cfg_attr(all(target_os = "macos", target_arch = "x86_64"), repr(C, packed(2)))]
    #[cfg_attr(not(all(target_os = "macos", target_arch = "x86_64")), repr(C))]
    struct Buffer {
        length: usize,
        value: *mut c_void,
    }

    #[cfg_attr(all(target_os = "macos", target_arch = "x86_64"), repr(C, packed(2)))]
    #[cfg_attr(not(all(target_os = "macos", target_arch = "x86_64")), repr(C))]
    struct Oid {
        length: u32,
        elements: *mut c_void,
    }

    #[cfg_attr(all(target_os = "macos", target_arch = "x86_64"), repr(C, packed(2)))]
    #[cfg_attr(not(all(target_os = "macos", target_arch = "x86_64")), repr(C))]
    struct OidSet {
        count: usize,
        elements: *mut Oid,
    }

    /// GSS_C_NT_HOSTBASED_SERVICE, 1.2.840.113554.1.2.1.4.
    static NT_HOSTBASED_SERVICE: [u8; 10] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x04];
    /// GSS_C_NT_USER_NAME, 1.2.840.113554.1.2.1.1.
    static NT_USER_NAME: [u8; 10] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x01];

    const DELEG_FLAG: Om = 1;
    const MUTUAL_FLAG: Om = 2;
    const INTEG_FLAG: Om = 32;
    const CONTINUE_NEEDED: Om = 1;
    const GSS_CODE: i32 = 1;
    const MECH_CODE: i32 = 2;
    const C_INITIATE: i32 = 1;
    const S_NO_CRED: Om = 7 << 16;
    const S_CREDENTIALS_EXPIRED: Om = 11 << 16;

    fn is_error(major: Om) -> bool {
        major & 0xffff_0000 != 0
    }

    fn oid(bytes: &'static [u8]) -> Oid {
        Oid { length: bytes.len() as u32, elements: bytes.as_ptr() as *mut c_void }
    }

    type ImportName = unsafe extern "C" fn(*mut Om, *mut Buffer, *mut Oid, *mut Name) -> Om;
    type InitSecContext = unsafe extern "C" fn(
        *mut Om,
        Cred,
        *mut Ctx,
        Name,
        *mut Oid,
        Om,
        Om,
        *mut c_void,
        *mut Buffer,
        *mut *mut Oid,
        *mut Buffer,
        *mut Om,
        *mut Om,
    ) -> Om;
    type GetMic = unsafe extern "C" fn(*mut Om, Ctx, Om, *mut Buffer, *mut Buffer) -> Om;
    type DeleteSecContext = unsafe extern "C" fn(*mut Om, *mut Ctx, *mut Buffer) -> Om;
    type ReleaseName = unsafe extern "C" fn(*mut Om, *mut Name) -> Om;
    type ReleaseBuffer = unsafe extern "C" fn(*mut Om, *mut Buffer) -> Om;
    type DisplayStatus = unsafe extern "C" fn(*mut Om, Om, i32, *mut Oid, *mut Om, *mut Buffer) -> Om;
    type AcquireCred = unsafe extern "C" fn(*mut Om, Name, Om, *mut OidSet, i32, *mut Cred, *mut *mut OidSet, *mut Om) -> Om;
    type ReleaseCred = unsafe extern "C" fn(*mut Om, *mut Cred) -> Om;
    type VerifyMic = unsafe extern "C" fn(*mut Om, Ctx, *mut Buffer, *mut Buffer, *mut Om) -> Om;
    type InquireCred = unsafe extern "C" fn(*mut Om, Cred, *mut Name, *mut Om, *mut i32, *mut *mut OidSet) -> Om;
    type DisplayName = unsafe extern "C" fn(*mut Om, Name, *mut Buffer, *mut *mut Oid) -> Om;

    struct Lib {
        /// Never unloaded: the function pointers below point into it.
        _lib: libloading::Library,
        import_name: ImportName,
        init_sec_context: InitSecContext,
        get_mic: GetMic,
        delete_sec_context: DeleteSecContext,
        release_name: ReleaseName,
        release_buffer: ReleaseBuffer,
        display_status: DisplayStatus,
        acquire_cred: AcquireCred,
        release_cred: ReleaseCred,
        verify_mic: VerifyMic,
        inquire_cred: InquireCred,
        display_name: DisplayName,
    }

    #[cfg(target_os = "macos")]
    const CANDIDATES: &[&str] = &["/System/Library/Frameworks/GSS.framework/GSS", "libgssapi_krb5.dylib"];
    #[cfg(target_os = "linux")]
    const CANDIDATES: &[&str] = &["libgssapi_krb5.so.2", "libgssapi_krb5.so", "libgssapi.so.3"];
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    const CANDIDATES: &[&str] = &["libgssapi_krb5.so.2", "libgssapi_krb5.so", "libgssapi.so.3", "libgssapi.so.10", "libgssapi.so"];

    impl Lib {
        /// # Safety
        /// `lib` must be a GSSAPI library: the symbols are taken to have
        /// the types RFC 2744 gives them.
        unsafe fn from(lib: libloading::Library) -> Result<Lib, libloading::Error> {
            unsafe {
                Ok(Lib {
                    import_name: *lib.get(b"gss_import_name\0")?,
                    init_sec_context: *lib.get(b"gss_init_sec_context\0")?,
                    get_mic: *lib.get(b"gss_get_mic\0")?,
                    delete_sec_context: *lib.get(b"gss_delete_sec_context\0")?,
                    release_name: *lib.get(b"gss_release_name\0")?,
                    release_buffer: *lib.get(b"gss_release_buffer\0")?,
                    display_status: *lib.get(b"gss_display_status\0")?,
                    acquire_cred: *lib.get(b"gss_acquire_cred\0")?,
                    release_cred: *lib.get(b"gss_release_cred\0")?,
                    verify_mic: *lib.get(b"gss_verify_mic\0")?,
                    inquire_cred: *lib.get(b"gss_inquire_cred\0")?,
                    display_name: *lib.get(b"gss_display_name\0")?,
                    _lib: lib,
                })
            }
        }

        /// A buffer the library allocated, copied out and released.
        fn take(&self, b: &mut Buffer) -> Vec<u8> {
            let (len, ptr) = (b.length, b.value);
            if ptr.is_null() {
                return Vec::new();
            }
            // SAFETY: the library filled `b` with `len` bytes at `ptr`.
            let v = unsafe { std::slice::from_raw_parts(ptr as *const u8, len) }.to_vec();
            let mut minor = 0;
            // SAFETY: released once; the library resets the buffer.
            unsafe { (self.release_buffer)(&mut minor, b) };
            v
        }

        /// gss_display_status for one code, every message it has.
        fn status(&self, code: Om, kind: i32) -> String {
            let mut parts = Vec::new();
            let mut more: Om = 0;
            let mut mech = oid(&super::KRB5_OID);
            for _ in 0..8 {
                let mut minor = 0;
                let mut b = Buffer { length: 0, value: null_mut() };
                let mech_ptr = if kind == MECH_CODE { &mut mech as *mut Oid } else { null_mut() };
                // SAFETY: valid out-pointers; `b` is released by `take`.
                let major = unsafe { (self.display_status)(&mut minor, code, kind, mech_ptr, &mut more, &mut b) };
                let text = self.take(&mut b);
                if is_error(major) {
                    break;
                }
                parts.push(String::from_utf8_lossy(&text).into_owned());
                if more == 0 {
                    break;
                }
            }
            parts.join("; ")
        }

        fn describe(&self, major: Om, minor: Om) -> String {
            let mut text = self.status(major, GSS_CODE);
            if minor != 0 {
                let m = self.status(minor, MECH_CODE);
                if !m.is_empty() {
                    text = format!("{text}: {m}");
                }
            }
            let routine = major & 0x00ff_0000;
            if routine == S_NO_CRED || routine == S_CREDENTIALS_EXPIRED {
                format!("no Kerberos ticket; run kinit ({text})")
            } else {
                text
            }
        }

        fn import(&self, name: &str, kind: &'static [u8]) -> Result<Name, String> {
            let mut b = Buffer { length: name.len(), value: name.as_ptr() as *mut c_void };
            let mut t = oid(kind);
            let mut out: Name = null_mut();
            let mut minor = 0;
            // SAFETY: the library reads `b` and `t` and writes `out`.
            let major = unsafe { (self.import_name)(&mut minor, &mut b, &mut t, &mut out) };
            if is_error(major) {
                return Err(format!("{name}: {}", self.describe(major, minor)));
            }
            Ok(out)
        }
    }

    fn lib() -> Result<&'static Lib, String> {
        static LIB: OnceLock<Result<Lib, String>> = OnceLock::new();
        LIB.get_or_init(|| {
            for name in CANDIDATES {
                // SAFETY: a system GSSAPI library; its initialisers are the
                // library's own.
                let Ok(l) = (unsafe { libloading::Library::new(name) }) else { continue };
                // SAFETY: the library is one of the GSSAPI libraries above.
                match unsafe { Lib::from(l) } {
                    Ok(lib) => {
                        tracing::info!("GSSAPI: using {name}");
                        return Ok(lib);
                    }
                    Err(e) => tracing::info!("GSSAPI: {name}: {e}"),
                }
            }
            Err("no GSSAPI library found; install MIT Kerberos (libgssapi-krb5-2 or krb5-libs)".into())
        })
        .as_ref()
        .map_err(Clone::clone)
    }

    /// A security context for `host@<host>`, with what it owns.
    pub struct Context {
        lib: &'static Lib,
        name: Name,
        cred: Cred,
        ctx: Ctx,
        /// Kept at a fixed address while the context lives.
        mech: Box<Oid>,
        flags: Om,
    }

    // SAFETY: GSSAPI handles may be used from any thread, one at a time;
    // `Context` is only ever used through `&mut`.
    unsafe impl Send for Context {}

    impl Context {
        pub fn new(host: &str, client: Option<&str>, delegate: bool) -> Result<Context, String> {
            let lib = lib()?;
            let mut c = Context {
                lib,
                name: null_mut(),
                cred: null_mut(),
                ctx: null_mut(),
                mech: Box::new(oid(&super::KRB5_OID)),
                flags: MUTUAL_FLAG | INTEG_FLAG | if delegate { DELEG_FLAG } else { 0 },
            };
            c.name = lib.import(&format!("host@{host}"), &NT_HOSTBASED_SERVICE)?;
            if let Some(principal) = client {
                let user = lib.import(principal, &NT_USER_NAME).map_err(|e| format!("GSSAPIClientIdentity {e}"))?;
                let mut set = OidSet { count: 1, elements: &mut *c.mech };
                let mut minor = 0;
                // SAFETY: valid handles and out-pointers; `user` is released
                // right after, the credential with the context.
                let major = unsafe {
                    (lib.acquire_cred)(&mut minor, user, 0, &mut set, C_INITIATE, &mut c.cred, null_mut(), null_mut())
                };
                let mut user = user;
                let mut m2 = 0;
                // SAFETY: `user` came from gss_import_name and is released once.
                unsafe { (lib.release_name)(&mut m2, &mut user) };
                if is_error(major) {
                    return Err(format!("GSSAPIClientIdentity {principal}: {}", lib.describe(major, minor)));
                }
            }
            Ok(c)
        }

        pub fn step(&mut self, input: Option<&[u8]>) -> Result<Out, String> {
            let lib = self.lib;
            let mut in_buf = input.map(|t| Buffer { length: t.len(), value: t.as_ptr() as *mut c_void });
            let in_ptr = in_buf.as_mut().map_or(null_mut(), |b| b as *mut Buffer);
            let mut out = Buffer { length: 0, value: null_mut() };
            let (mut minor, mut ret_flags) = (0, 0);
            // SAFETY: every pointer is valid for the call; the input token
            // outlives it and the library only reads it.
            let major = unsafe {
                (lib.init_sec_context)(
                    &mut minor,
                    self.cred,
                    &mut self.ctx,
                    self.name,
                    &mut *self.mech,
                    self.flags,
                    0,
                    null_mut(),
                    in_ptr,
                    null_mut(),
                    &mut out,
                    &mut ret_flags,
                    null_mut(),
                )
            };
            let token = lib.take(&mut out);
            if is_error(major) {
                return Err(lib.describe(major, minor));
            }
            Ok(Out {
                token,
                complete: major & CONTINUE_NEEDED == 0,
                mutual: ret_flags & MUTUAL_FLAG != 0,
                integ: ret_flags & INTEG_FLAG != 0,
            })
        }

        /// gss_verify_mic: `mic` over `data`.
        pub fn verify_mic(&mut self, data: &[u8], mic: &[u8]) -> Result<(), String> {
            let lib = self.lib;
            let mut msg = Buffer { length: data.len(), value: data.as_ptr() as *mut c_void };
            let mut tok = Buffer { length: mic.len(), value: mic.as_ptr() as *mut c_void };
            let (mut minor, mut qop) = (0, 0);
            // SAFETY: an established context; both buffers are only read.
            let major = unsafe { (lib.verify_mic)(&mut minor, self.ctx, &mut msg, &mut tok, &mut qop) };
            if is_error(major) {
                return Err(lib.describe(major, minor));
            }
            Ok(())
        }

        pub fn mic(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
            let lib = self.lib;
            let mut msg = Buffer { length: data.len(), value: data.as_ptr() as *mut c_void };
            let mut tok = Buffer { length: 0, value: null_mut() };
            let mut minor = 0;
            // SAFETY: an established context; `msg` is only read.
            let major = unsafe { (lib.get_mic)(&mut minor, self.ctx, 0, &mut msg, &mut tok) };
            let mic = lib.take(&mut tok);
            if is_error(major) {
                return Err(lib.describe(major, minor));
            }
            Ok(mic)
        }
    }

    /// gss_inquire_cred on the default credentials: the principal and the
    /// seconds they have left.
    pub fn inquire_cred() -> Result<(String, u64), String> {
        let lib = lib()?;
        let (mut minor, mut name, mut lifetime): (Om, Name, Om) = (0, null_mut(), 0);
        // SAFETY: GSS_C_NO_CREDENTIAL and valid out-pointers; `name` is
        // released below.
        let major = unsafe { (lib.inquire_cred)(&mut minor, null_mut(), &mut name, &mut lifetime, null_mut(), null_mut()) };
        if is_error(major) {
            return Err(lib.describe(major, minor));
        }
        let mut b = Buffer { length: 0, value: null_mut() };
        // SAFETY: `name` came from gss_inquire_cred; `b` is released by `take`.
        let major = unsafe { (lib.display_name)(&mut minor, name, &mut b, null_mut()) };
        let text = lib.take(&mut b);
        let mut m2 = 0;
        // SAFETY: released once.
        unsafe { (lib.release_name)(&mut m2, &mut name) };
        if is_error(major) {
            return Err(lib.describe(major, minor));
        }
        Ok((String::from_utf8_lossy(&text).into_owned(), u64::from(lifetime)))
    }

    impl Drop for Context {
        fn drop(&mut self) {
            let lib = self.lib;
            let mut minor = 0;
            // SAFETY: each handle is released once and set to null by the
            // library; null ones were never made.
            unsafe {
                if !self.ctx.is_null() {
                    (lib.delete_sec_context)(&mut minor, &mut self.ctx, null_mut());
                }
                if !self.name.is_null() {
                    (lib.release_name)(&mut minor, &mut self.name);
                }
                if !self.cred.is_null() {
                    (lib.release_cred)(&mut minor, &mut self.cred);
                }
            }
        }
    }
}

/// SSPI's Kerberos package, which uses the Windows account's tickets.
#[cfg(windows)]
mod sys {
    use std::ffi::c_void;

    use windows::core::{HRESULT, PCWSTR};
    use windows::Win32::Foundation::{
        SEC_E_NO_AUTHENTICATING_AUTHORITY, SEC_E_NO_CREDENTIALS, SEC_E_OK, SEC_E_TARGET_UNKNOWN, SEC_I_COMPLETE_AND_CONTINUE,
        SEC_I_COMPLETE_NEEDED, SEC_I_CONTINUE_NEEDED,
    };
    use windows::Win32::Security::Authentication::Identity::{
        AcquireCredentialsHandleW, CompleteAuthToken, DeleteSecurityContext, FreeContextBuffer, FreeCredentialsHandle,
        InitializeSecurityContextW, MakeSignature, QueryContextAttributesW, QueryCredentialsAttributesW, SecBuffer,
        SecBufferDesc, SecPkgContext_Sizes, SecPkgCredentials_NamesW, VerifySignature, ISC_REQ_ALLOCATE_MEMORY,
        ISC_REQ_DELEGATE, ISC_REQ_FLAGS, ISC_REQ_INTEGRITY, ISC_REQ_MUTUAL_AUTH, ISC_RET_INTEGRITY, ISC_RET_MUTUAL_AUTH,
        SECBUFFER_DATA, SECBUFFER_TOKEN, SECBUFFER_VERSION, SECPKG_ATTR_SIZES, SECPKG_CRED_ATTR_NAMES, SECPKG_CRED_OUTBOUND,
        SECURITY_NATIVE_DREP,
    };
    use windows::Win32::Security::Credentials::SecHandle;

    use super::Out;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn describe(code: HRESULT) -> String {
        let text = windows::core::Error::from(code).message();
        if code == SEC_E_NO_CREDENTIALS || code == SEC_E_NO_AUTHENTICATING_AUTHORITY {
            format!("no Kerberos ticket: this Windows account has no Kerberos credentials for the realm ({text})")
        } else if code == SEC_E_TARGET_UNKNOWN {
            format!("the KDC does not know the server's principal ({text})")
        } else {
            text
        }
    }

    pub struct Context {
        cred: SecHandle,
        ctx: SecHandle,
        has_ctx: bool,
        /// `host/<host>`, the SPN form of `host@<host>`.
        target: Vec<u16>,
        flags: ISC_REQ_FLAGS,
    }

    impl Context {
        pub fn new(host: &str, client: Option<&str>, delegate: bool) -> Result<Context, String> {
            let principal = client.map(wide);
            let package = wide("Kerberos");
            let mut cred = SecHandle::default();
            // SAFETY: the strings are NUL-terminated and outlive the call.
            let r = unsafe {
                AcquireCredentialsHandleW(
                    principal.as_ref().map_or(PCWSTR::null(), |p| PCWSTR(p.as_ptr())),
                    PCWSTR(package.as_ptr()),
                    SECPKG_CRED_OUTBOUND,
                    None,
                    None,
                    None,
                    None,
                    &mut cred,
                    None,
                )
            };
            if let Err(e) = r {
                return Err(match client {
                    Some(p) => format!("GSSAPIClientIdentity {p}: this Windows account holds no Kerberos credentials for it ({})", e.message()),
                    None => describe(e.code()),
                });
            }
            let mut flags = ISC_REQ_MUTUAL_AUTH | ISC_REQ_INTEGRITY;
            if delegate {
                flags |= ISC_REQ_DELEGATE;
            }
            Ok(Context { cred, ctx: SecHandle::default(), has_ctx: false, target: wide(&format!("host/{host}")), flags })
        }

        pub fn step(&mut self, input: Option<&[u8]>) -> Result<Out, String> {
            let mut in_buf = SecBuffer { cbBuffer: 0, BufferType: SECBUFFER_TOKEN, pvBuffer: std::ptr::null_mut() };
            if let Some(t) = input {
                in_buf = SecBuffer { cbBuffer: t.len() as u32, BufferType: SECBUFFER_TOKEN, pvBuffer: t.as_ptr() as *mut c_void };
            }
            let in_desc = SecBufferDesc { ulVersion: SECBUFFER_VERSION, cBuffers: 1, pBuffers: &mut in_buf };
            let mut out_buf = SecBuffer { cbBuffer: 0, BufferType: SECBUFFER_TOKEN, pvBuffer: std::ptr::null_mut() };
            let mut out_desc = SecBufferDesc { ulVersion: SECBUFFER_VERSION, cBuffers: 1, pBuffers: &mut out_buf };
            let mut attrs = 0u32;
            let old = self.has_ctx.then_some(&self.ctx as *const SecHandle);
            // SAFETY: the handles and buffers are valid for the call; the
            // input token outlives it and is only read.
            let hr = unsafe {
                InitializeSecurityContextW(
                    Some(&self.cred),
                    old,
                    Some(self.target.as_ptr()),
                    self.flags | ISC_REQ_ALLOCATE_MEMORY,
                    0,
                    SECURITY_NATIVE_DREP,
                    input.map(|_| &in_desc as *const SecBufferDesc),
                    0,
                    Some(&mut self.ctx),
                    Some(&mut out_desc),
                    &mut attrs,
                    None,
                )
            };
            let ok = [SEC_E_OK, SEC_I_CONTINUE_NEEDED, SEC_I_COMPLETE_NEEDED, SEC_I_COMPLETE_AND_CONTINUE].contains(&hr);
            if ok {
                self.has_ctx = true;
            }
            let mut completed = Ok(());
            if ok && (hr == SEC_I_COMPLETE_NEEDED || hr == SEC_I_COMPLETE_AND_CONTINUE) {
                // SAFETY: the context and the token just made.
                completed = unsafe { CompleteAuthToken(&self.ctx, &out_desc) };
            }
            let token = if out_buf.pvBuffer.is_null() {
                Vec::new()
            } else {
                // SAFETY: SSPI allocated `cbBuffer` bytes there; freed once.
                let v = unsafe { std::slice::from_raw_parts(out_buf.pvBuffer as *const u8, out_buf.cbBuffer as usize) }.to_vec();
                // SAFETY: allocated by SSPI (ISC_REQ_ALLOCATE_MEMORY).
                let _ = unsafe { FreeContextBuffer(out_buf.pvBuffer) };
                v
            };
            if !ok {
                return Err(describe(hr));
            }
            completed.map_err(|e| describe(e.code()))?;
            let complete = hr == SEC_E_OK || hr == SEC_I_COMPLETE_NEEDED;
            Ok(Out { token, complete, mutual: attrs & ISC_RET_MUTUAL_AUTH != 0, integ: attrs & ISC_RET_INTEGRITY != 0 })
        }

        /// VerifySignature, SSPI's gss_verify_mic.
        pub fn verify_mic(&mut self, data: &[u8], mic: &[u8]) -> Result<(), String> {
            let mut msg = data.to_vec();
            let mut sig = mic.to_vec();
            let mut bufs = [
                SecBuffer { cbBuffer: msg.len() as u32, BufferType: SECBUFFER_DATA, pvBuffer: msg.as_mut_ptr() as *mut c_void },
                SecBuffer { cbBuffer: sig.len() as u32, BufferType: SECBUFFER_TOKEN, pvBuffer: sig.as_mut_ptr() as *mut c_void },
            ];
            let desc = SecBufferDesc { ulVersion: SECBUFFER_VERSION, cBuffers: 2, pBuffers: bufs.as_mut_ptr() };
            // SAFETY: an established context; both buffers are ours.
            unsafe { VerifySignature(&self.ctx, &desc, 0) }.map_err(|e| describe(e.code()))?;
            Ok(())
        }

        pub fn mic(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
            let mut sizes = SecPkgContext_Sizes::default();
            // SAFETY: an established context; `sizes` is the attribute's type.
            unsafe { QueryContextAttributesW(&self.ctx, SECPKG_ATTR_SIZES, &mut sizes as *mut _ as *mut c_void) }
                .map_err(|e| describe(e.code()))?;
            let mut msg = data.to_vec();
            let mut sig = vec![0u8; sizes.cbMaxSignature as usize];
            let mut bufs = [
                SecBuffer { cbBuffer: msg.len() as u32, BufferType: SECBUFFER_DATA, pvBuffer: msg.as_mut_ptr() as *mut c_void },
                SecBuffer { cbBuffer: sig.len() as u32, BufferType: SECBUFFER_TOKEN, pvBuffer: sig.as_mut_ptr() as *mut c_void },
            ];
            let desc = SecBufferDesc { ulVersion: SECBUFFER_VERSION, cBuffers: 2, pBuffers: bufs.as_mut_ptr() };
            // SAFETY: both buffers are ours and as long as they claim.
            unsafe { MakeSignature(&self.ctx, 0, &desc, 0) }.map_err(|e| describe(e.code()))?;
            sig.truncate(bufs[1].cbBuffer as usize);
            Ok(sig)
        }
    }

    /// The Windows account's Kerberos credentials: the principal and the
    /// seconds until they end.
    pub fn inquire_cred() -> Result<(String, u64), String> {
        let package = wide("Kerberos");
        let mut cred = SecHandle::default();
        let mut expiry = 0i64;
        // SAFETY: the package name is NUL-terminated and outlives the call.
        unsafe {
            AcquireCredentialsHandleW(PCWSTR::null(), PCWSTR(package.as_ptr()), SECPKG_CRED_OUTBOUND, None, None, None, None, &mut cred, Some(&mut expiry))
        }
        .map_err(|e| describe(e.code()))?;
        let mut names = SecPkgCredentials_NamesW::default();
        // SAFETY: a valid credentials handle; `names` is the attribute's type.
        let r = unsafe { QueryCredentialsAttributesW(&cred, SECPKG_CRED_ATTR_NAMES, &mut names as *mut _ as *mut c_void) };
        let name = if r.is_ok() && !names.sUserName.is_null() {
            // SAFETY: SSPI returned a NUL-terminated string, freed once.
            let n = unsafe { PCWSTR(names.sUserName).to_string() }.unwrap_or_default();
            let _ = unsafe { FreeContextBuffer(names.sUserName as *mut c_void) };
            n
        } else {
            String::new()
        };
        // SAFETY: released once.
        let _ = unsafe { FreeCredentialsHandle(&cred) };
        r.map_err(|e| describe(e.code()))?;
        // A FILETIME in local time; the clock's own offset cancels out.
        let now = {
            let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
            d.as_secs() as i64 + 11_644_473_600
        };
        let left = (expiry / 10_000_000 - now).max(0) as u64;
        Ok((name, left))
    }

    impl Drop for Context {
        fn drop(&mut self) {
            // SAFETY: each handle is released once; the context only if made.
            unsafe {
                if self.has_ctx {
                    let _ = DeleteSecurityContext(&self.ctx);
                }
                let _ = FreeCredentialsHandle(&self.cred);
            }
        }
    }
}

/// No system Kerberos on Android.
#[cfg(target_os = "android")]
mod sys {
    use super::Out;

    pub enum Context {}

    impl Context {
        pub fn new(_host: &str, _client: Option<&str>, _delegate: bool) -> Result<Context, String> {
            Err("GSSAPI is not available on Android".into())
        }

        pub fn step(&mut self, _input: Option<&[u8]>) -> Result<Out, String> {
            match *self {}
        }

        pub fn mic(&mut self, _data: &[u8]) -> Result<Vec<u8>, String> {
            match *self {}
        }

        pub fn verify_mic(&mut self, _data: &[u8], _mic: &[u8]) -> Result<(), String> {
            match *self {}
        }
    }

    pub fn inquire_cred() -> Result<(String, u64), String> {
        Err("GSSAPI is not available on Android".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn krb5_mechanism_on_the_wire() {
        assert_eq!(krb5_mech(), [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02]);
    }

    #[test]
    fn server_must_select_krb5() {
        assert!(check_selected(&krb5_mech()).is_ok());
        // SPNEGO, which RFC 4462 forbids.
        assert!(check_selected(&[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]).unwrap_err().contains("different"));
        // Without the tag, as some old servers sent it.
        assert!(check_selected(&KRB5_OID).unwrap_err().contains("badly"));
        assert!(check_selected(&[0x06, 0x0a, 0x2a]).unwrap_err().contains("badly"));
        assert!(check_selected(&[0x06]).is_err());
    }

    #[test]
    fn target_name() {
        let p = GssapiPolicy::default();
        assert_eq!(target_host(&p, "Server.Example.COM"), "server.example.com");
        let p = GssapiPolicy { server_identity: Some("Gate.Example.com".into()), trust_dns: true, ..Default::default() };
        assert_eq!(target_host(&p, "10.1.2.3"), "Gate.Example.com");
        // Through a proxy there is no address to look up: the host as given.
        let p = GssapiPolicy { trust_dns: true, proxied: true, ..Default::default() };
        assert_eq!(target_host(&p, "Box"), "box");
    }

    #[test]
    fn trust_dns_checks_both_ways() {
        let a: IpAddr = "192.0.2.7".parse().unwrap();
        let fwd = |n: &str| if n == "host.example.com" { vec!["192.0.2.7".parse().unwrap()] } else { vec![] };
        assert_eq!(remote_name(a, Some("Host.Example.COM".into()), fwd), "host.example.com");
        assert_eq!(remote_name(a, None, fwd), "192.0.2.7");
        assert_eq!(remote_name(a, Some("other.example.com".into()), fwd), "192.0.2.7");
        assert_eq!(remote_name(a, Some("192.0.2.9".into()), fwd), "192.0.2.7");
    }

    #[test]
    fn policy_from_config() {
        let src = crate::ssh::sshconf::resolve::Source {
            path: "c".into(),
            text: Some("GSSAPIDelegateCredentials yes\nGSSAPIClientIdentity alice@EXAMPLE.COM\nGSSAPIServerIdentity gw.example.com\nGSSAPITrustDns yes\n".into()),
            user: true,
        };
        let env = crate::ssh::sshconf::env::SystemEnv::new(crate::ssh::sshconf::env::ExecPolicy::Never);
        let q = crate::ssh::sshconf::resolve::Query { host: "h".into(), ..Default::default() };
        let r = crate::ssh::sshconf::resolve::resolve(&[src], &q, &env);
        let p = GssapiPolicy::from_options(&r.options);
        assert_eq!(
            p,
            GssapiPolicy {
                delegate: true,
                client_identity: Some("alice@EXAMPLE.COM".into()),
                server_identity: Some("gw.example.com".into()),
                trust_dns: true,
                proxied: false
            }
        );
    }

    #[test]
    fn kex_names_as_the_patch_takes_them() {
        assert!(kex_names_valid(DEFAULT_KEX_ALGORITHMS));
        assert!(kex_names_valid("gss-curve25519-sha256-"));
        // A prefix match, as kex_alg_by_name makes it for GSS names.
        assert!(kex_names_valid("gss-group14-sha256-anything"));
        assert!(!kex_names_valid("curve25519-sha256"));
        assert!(!kex_names_valid("gss-group18-sha512-"));
        assert!(!kex_names_valid(""));
        // strsep stops at an empty name.
        assert!(kex_names_valid("gss-gex-sha1-,,bogus"));
        let algorithms = kex_algorithms(DEFAULT_KEX_ALGORITHMS);
        let names: Vec<&str> = algorithms.iter().map(|n| n.as_ref()).collect();
        assert_eq!(
            names,
            [
                "gss-group14-sha256-toWM5Slw5Ew8Mqkay+al2g==",
                "gss-group16-sha512-toWM5Slw5Ew8Mqkay+al2g==",
                "gss-nistp256-sha256-toWM5Slw5Ew8Mqkay+al2g==",
                "gss-curve25519-sha256-toWM5Slw5Ew8Mqkay+al2g==",
                "gss-group14-sha1-toWM5Slw5Ew8Mqkay+al2g==",
                "gss-gex-sha1-toWM5Slw5Ew8Mqkay+al2g==",
            ]
        );
        assert!(kex_algorithms("gss-group14-sha256-anything").is_empty());
    }

    /// The method name suffix is the base64 of the MD5 of this OID
    /// (ssh_gssapi_kex_mechs); russh holds both.
    #[test]
    fn kex_names_are_for_this_mechanism() {
        assert_eq!(russh::kex::gss::KRB5_MECH.as_slice(), krb5_mech().as_slice());
        assert_eq!(russh::kex::gss::KRB5_SUFFIX, "toWM5Slw5Ew8Mqkay+al2g==");
    }

    #[test]
    fn renewal_is_the_same_principal_lasting_longer() {
        let p = KexProvider { host: "h".into(), client: None, delegate: true, renewal: true, state: Default::default() };
        // Nothing saved: no exchange delegated anything yet.
        assert!(!p.renewed(1000, || Ok(("a@R".into(), 100))));
        let check = |saved: (&str, u64), now: u64, cur: Result<(String, u64), String>| {
            let p = KexProvider { host: "h".into(), client: None, delegate: true, renewal: true, state: Default::default() };
            p.state.lock().unwrap().saved = Some((saved.0.into(), saved.1));
            p.renewed(now, || cur)
        };
        // Ends at 2000; now 1000 with 2000 s left ends at 3000: renewed.
        assert!(check(("a@R", 2000), 1000, Ok(("a@R".into(), 2000))));
        // Within the 10 s slack: not renewed.
        assert!(!check(("a@R", 2000), 1000, Ok(("a@R".into(), 1005))));
        // Someone else's credentials now.
        assert!(!check(("a@R", 2000), 1000, Ok(("b@R".into(), 9000))));
        // Expired or unreadable.
        assert!(!check(("a@R", 2000), 1000, Err("expired".into())));
        // At most every 10 seconds.
        let p2 = KexProvider { host: "h".into(), client: None, delegate: true, renewal: true, state: Default::default() };
        p2.state.lock().unwrap().saved = Some(("a@R".into(), 2000));
        assert!(p2.renewed(1000, || Ok(("a@R".into(), 2000))));
        assert!(!p2.renewed(1000, || Ok(("a@R".into(), 2000))));
    }

    /// readconf.c's error for a list kex_gss_names_valid refuses.
    #[test]
    fn bad_kex_algorithms_is_a_config_error() {
        use crate::ssh::sshconf::resolve::{resolve, Query, Source};
        let env = crate::ssh::sshconf::env::SystemEnv::new(crate::ssh::sshconf::env::ExecPolicy::Never);
        let src = Source { path: "c".into(), text: Some("GSSAPIKexAlgorithms curve25519-sha256
".into()), user: true };
        let mut r = resolve(&[src], &Query { host: "h".into(), ..Default::default() }, &env);
        let errors = r.finish(&env);
        let all = format!("{errors:?} {:?}", r.notes);
        assert!(r.has_errors() || !errors.is_empty(), "{all}");
        assert!(all.contains("Bad GSSAPI KexAlgorithms 'curve25519-sha256'."), "{all}");
        let src = Source { path: "c".into(), text: Some("GSSAPIKexAlgorithms gss-curve25519-sha256-
".into()), user: true };
        let mut r = resolve(&[src], &Query { host: "h".into(), ..Default::default() }, &env);
        assert!(r.finish(&env).is_empty() && !r.has_errors());
    }

    /// No ticket for a server no KDC knows: a clean error, on every system.
    #[test]
    fn unknown_server_is_a_clean_error() {
        let e = probe("reach-gss-test.invalid", None).unwrap_err();
        println!("{e}");
        assert!(!e.is_empty());
        let e = probe("reach-gss-test.invalid", Some("nobody@REACH-GSS-TEST.INVALID")).unwrap_err();
        println!("{e}");
        assert!(!e.is_empty());
    }
}

#[cfg(test)]
#[path = "gssapi_live_tests.rs"]
mod live;

#[cfg(test)]
#[path = "gssapi_kex_live_tests.rs"]
mod live_kex;
