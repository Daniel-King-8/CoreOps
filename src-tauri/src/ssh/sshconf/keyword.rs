//! Every keyword `ssh_config(5)` knows, under the name its manual gives it,
//! with the aliases, deprecated and unsupported names of readconf.c, and
//! the vendor extensions (Apple's, Debian's and Red Hat's) that configs in
//! the wild carry.

macro_rules! keywords {
    ($($kw:ident => $name:literal),* $(,)?) => {
        /// A keyword, by its manual name.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
        pub enum Kw { $($kw),* }

        impl Kw {
            pub const ALL: &'static [Kw] = &[$(Kw::$kw),*];

            /// The name the manual gives it, e.g. `ServerAliveInterval`.
            pub fn name(self) -> &'static str {
                match self { $(Kw::$kw => $name),* }
            }
        }
    };
}

keywords! {
    // Structure.
    Host => "Host",
    Match => "Match",
    Include => "Include",
    // The rest of ssh_config(5), in the manual's order.
    AddKeysToAgent => "AddKeysToAgent",
    AddressFamily => "AddressFamily",
    BatchMode => "BatchMode",
    BindAddress => "BindAddress",
    BindInterface => "BindInterface",
    CanonicalDomains => "CanonicalDomains",
    CanonicalizeFallbackLocal => "CanonicalizeFallbackLocal",
    CanonicalizeHostname => "CanonicalizeHostname",
    CanonicalizeMaxDots => "CanonicalizeMaxDots",
    CanonicalizePermittedCNAMEs => "CanonicalizePermittedCNAMEs",
    CASignatureAlgorithms => "CASignatureAlgorithms",
    CertificateFile => "CertificateFile",
    ChannelTimeout => "ChannelTimeout",
    CheckHostIP => "CheckHostIP",
    Ciphers => "Ciphers",
    ClearAllForwardings => "ClearAllForwardings",
    Compression => "Compression",
    ConnectionAttempts => "ConnectionAttempts",
    ConnectTimeout => "ConnectTimeout",
    ControlMaster => "ControlMaster",
    ControlPath => "ControlPath",
    ControlPersist => "ControlPersist",
    DynamicForward => "DynamicForward",
    EnableEscapeCommandline => "EnableEscapeCommandline",
    EnableSSHKeysign => "EnableSSHKeysign",
    EscapeChar => "EscapeChar",
    ExitOnForwardFailure => "ExitOnForwardFailure",
    FingerprintHash => "FingerprintHash",
    ForkAfterAuthentication => "ForkAfterAuthentication",
    ForwardAgent => "ForwardAgent",
    ForwardX11 => "ForwardX11",
    ForwardX11Timeout => "ForwardX11Timeout",
    ForwardX11Trusted => "ForwardX11Trusted",
    GatewayPorts => "GatewayPorts",
    GlobalKnownHostsFile => "GlobalKnownHostsFile",
    GSSAPIAuthentication => "GSSAPIAuthentication",
    GSSAPIDelegateCredentials => "GSSAPIDelegateCredentials",
    HashKnownHosts => "HashKnownHosts",
    HostbasedAcceptedAlgorithms => "HostbasedAcceptedAlgorithms",
    HostbasedAuthentication => "HostbasedAuthentication",
    HostKeyAlgorithms => "HostKeyAlgorithms",
    HostKeyAlias => "HostKeyAlias",
    Hostname => "Hostname",
    IdentitiesOnly => "IdentitiesOnly",
    IdentityAgent => "IdentityAgent",
    IdentityFile => "IdentityFile",
    IgnoreUnknown => "IgnoreUnknown",
    IPQoS => "IPQoS",
    KbdInteractiveAuthentication => "KbdInteractiveAuthentication",
    KbdInteractiveDevices => "KbdInteractiveDevices",
    KexAlgorithms => "KexAlgorithms",
    KnownHostsCommand => "KnownHostsCommand",
    LocalCommand => "LocalCommand",
    LocalForward => "LocalForward",
    LogLevel => "LogLevel",
    LogVerbose => "LogVerbose",
    MACs => "MACs",
    NoHostAuthenticationForLocalhost => "NoHostAuthenticationForLocalhost",
    NumberOfPasswordPrompts => "NumberOfPasswordPrompts",
    ObscureKeystrokeTiming => "ObscureKeystrokeTiming",
    PasswordAuthentication => "PasswordAuthentication",
    PermitLocalCommand => "PermitLocalCommand",
    PermitRemoteOpen => "PermitRemoteOpen",
    PKCS11Provider => "PKCS11Provider",
    Port => "Port",
    PreferredAuthentications => "PreferredAuthentications",
    ProxyCommand => "ProxyCommand",
    ProxyJump => "ProxyJump",
    ProxyUseFdpass => "ProxyUseFdpass",
    PubkeyAcceptedAlgorithms => "PubkeyAcceptedAlgorithms",
    PubkeyAuthentication => "PubkeyAuthentication",
    RefuseConnection => "RefuseConnection",
    RekeyLimit => "RekeyLimit",
    RemoteCommand => "RemoteCommand",
    RemoteForward => "RemoteForward",
    RequestTTY => "RequestTTY",
    RequiredRSASize => "RequiredRSASize",
    RevokedHostKeys => "RevokedHostKeys",
    SecurityKeyProvider => "SecurityKeyProvider",
    SendEnv => "SendEnv",
    ServerAliveCountMax => "ServerAliveCountMax",
    ServerAliveInterval => "ServerAliveInterval",
    SessionType => "SessionType",
    SetEnv => "SetEnv",
    StdinNull => "StdinNull",
    StreamLocalBindMask => "StreamLocalBindMask",
    StreamLocalBindUnlink => "StreamLocalBindUnlink",
    StrictHostKeyChecking => "StrictHostKeyChecking",
    SyslogFacility => "SyslogFacility",
    TCPKeepAlive => "TCPKeepAlive",
    Tag => "Tag",
    Tunnel => "Tunnel",
    TunnelDevice => "TunnelDevice",
    UpdateHostKeys => "UpdateHostKeys",
    User => "User",
    UserKnownHostsFile => "UserKnownHostsFile",
    VerifyHostKeyDNS => "VerifyHostKeyDNS",
    VersionAddendum => "VersionAddendum",
    VisualHostKey => "VisualHostKey",
    WarnWeakCrypto => "WarnWeakCrypto",
    XAuthLocation => "XAuthLocation",
    // Vendor extensions: not upstream, but shipped by macOS and by the
    // Debian/Ubuntu and Fedora/RHEL builds of OpenSSH.
    UseKeychain => "UseKeychain",
    GSSAPIKeyExchange => "GSSAPIKeyExchange",
    GSSAPIClientIdentity => "GSSAPIClientIdentity",
    GSSAPIServerIdentity => "GSSAPIServerIdentity",
    GSSAPIRenewalForcesRekey => "GSSAPIRenewalForcesRekey",
    GSSAPITrustDns => "GSSAPITrustDns",
    GSSAPIKexAlgorithms => "GSSAPIKexAlgorithms",
}

/// How a keyword name read from a file is treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup {
    Known(Kw),
    /// `Protocol`: accepted and ignored without a word.
    Ignored,
    /// Accepted with a note that it no longer does anything.
    Deprecated,
    /// Named by OpenSSH but refused with an error ("Unsupported option").
    Unsupported,
    /// Not a keyword at all.
    Unknown,
}

impl Kw {
    /// True for keywords outside upstream OpenSSH.
    pub fn is_extension(self) -> bool {
        matches!(
            self,
            Kw::UseKeychain
                | Kw::GSSAPIKeyExchange
                | Kw::GSSAPIClientIdentity
                | Kw::GSSAPIServerIdentity
                | Kw::GSSAPIRenewalForcesRekey
                | Kw::GSSAPITrustDns
                | Kw::GSSAPIKexAlgorithms
        )
    }
}

/// Look a keyword up as readconf.c's `parse_token` does: case-insensitively,
/// with the aliases it maps.
pub fn lookup(word: &str) -> Lookup {
    let w = word.to_ascii_lowercase();
    match w.as_str() {
        "protocol" => return Lookup::Ignored,
        "cipher" | "fallbacktorsh" | "globalknownhostsfile2" | "rhostsauthentication" | "userknownhostsfile2"
        | "useroaming" | "usersh" | "useprivilegedport" => return Lookup::Deprecated,
        "afstokenpassing" | "kerberosauthentication" | "kerberostgtpassing" | "rsaauthentication"
        | "rhostsrsaauthentication" | "compressionlevel" => return Lookup::Unsupported,
        // Aliases.
        "challengeresponseauthentication" | "skeyauthentication" | "tisauthentication" => {
            return Lookup::Known(Kw::KbdInteractiveAuthentication)
        }
        "dsaauthentication" => return Lookup::Known(Kw::PubkeyAuthentication),
        "identityfile2" => return Lookup::Known(Kw::IdentityFile),
        "keepalive" => return Lookup::Known(Kw::TCPKeepAlive),
        // Debian's name for it.
        "protocolkeepalives" => return Lookup::Known(Kw::ServerAliveInterval),
        "hostbasedkeytypes" => return Lookup::Known(Kw::HostbasedAcceptedAlgorithms),
        "pubkeyacceptedkeytypes" => return Lookup::Known(Kw::PubkeyAcceptedAlgorithms),
        "smartcarddevice" => return Lookup::Known(Kw::PKCS11Provider),
        _ => {}
    }
    Kw::ALL
        .iter()
        .find(|k| k.name().eq_ignore_ascii_case(&w))
        .map_or(Lookup::Unknown, |k| Lookup::Known(*k))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_manual_keyword_is_known() {
        // The 104 `.It Cm` entries of ssh_config.5 (OpenSSH, September 2026).
        let manual = "Host Match Include AddKeysToAgent AddressFamily BatchMode BindAddress BindInterface \
            CanonicalDomains CanonicalizeFallbackLocal CanonicalizeHostname CanonicalizeMaxDots \
            CanonicalizePermittedCNAMEs CASignatureAlgorithms CertificateFile ChannelTimeout CheckHostIP \
            Ciphers ClearAllForwardings Compression ConnectionAttempts ConnectTimeout ControlMaster \
            ControlPath ControlPersist DynamicForward EnableEscapeCommandline EnableSSHKeysign EscapeChar \
            ExitOnForwardFailure FingerprintHash ForkAfterAuthentication ForwardAgent ForwardX11 \
            ForwardX11Timeout ForwardX11Trusted GatewayPorts GlobalKnownHostsFile GSSAPIAuthentication \
            GSSAPIDelegateCredentials HashKnownHosts HostbasedAcceptedAlgorithms HostbasedAuthentication \
            HostKeyAlgorithms HostKeyAlias Hostname IdentitiesOnly IdentityAgent IdentityFile IgnoreUnknown \
            IPQoS KbdInteractiveAuthentication KbdInteractiveDevices KexAlgorithms KnownHostsCommand \
            LocalCommand LocalForward LogLevel LogVerbose MACs NoHostAuthenticationForLocalhost \
            NumberOfPasswordPrompts ObscureKeystrokeTiming PasswordAuthentication PermitLocalCommand \
            PermitRemoteOpen PKCS11Provider Port PreferredAuthentications ProxyCommand ProxyJump \
            ProxyUseFdpass PubkeyAcceptedAlgorithms PubkeyAuthentication RefuseConnection RekeyLimit \
            RemoteCommand RemoteForward RequestTTY RequiredRSASize RevokedHostKeys SecurityKeyProvider \
            SendEnv ServerAliveCountMax ServerAliveInterval SessionType SetEnv StdinNull StreamLocalBindMask \
            StreamLocalBindUnlink StrictHostKeyChecking SyslogFacility TCPKeepAlive Tag Tunnel TunnelDevice \
            UpdateHostKeys User UserKnownHostsFile VerifyHostKeyDNS VersionAddendum VisualHostKey \
            WarnWeakCrypto XAuthLocation";
        let names: Vec<&str> = manual.split_whitespace().collect();
        assert_eq!(names.len(), 104);
        for n in &names {
            match lookup(n) {
                Lookup::Known(k) => assert_eq!(k.name(), *n),
                other => panic!("{n}: {other:?}"),
            }
        }
        let upstream = Kw::ALL.iter().filter(|k| !k.is_extension()).count();
        assert_eq!(upstream, 104);
    }

    #[test]
    fn aliases_and_case() {
        assert_eq!(lookup("HOSTNAME"), Lookup::Known(Kw::Hostname));
        assert_eq!(lookup("ChallengeResponseAuthentication"), Lookup::Known(Kw::KbdInteractiveAuthentication));
        assert_eq!(lookup("PubkeyAcceptedKeyTypes"), Lookup::Known(Kw::PubkeyAcceptedAlgorithms));
        assert_eq!(lookup("Protocol"), Lookup::Ignored);
        assert_eq!(lookup("UseRoaming"), Lookup::Deprecated);
        assert_eq!(lookup("CompressionLevel"), Lookup::Unsupported);
        assert_eq!(lookup("Bogus"), Lookup::Unknown);
    }
}
