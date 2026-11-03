//! VerifyHostKeyDNS: the host key checked against the host's SSHFP
//! records (RFC 4255, RFC 6594), as dns.c verify_host_key_dns does. ssh
//! trusts the resolver's AD bit for "secure"; Reach validates the DNSSEC
//! chain itself from the root, so a resolver on the path cannot vouch for
//! a forged record.

use std::time::Duration;

use hickory_resolver::proto::dnssec::Proof;
use hickory_resolver::proto::rr::{RData, RecordType};
use sha2::Digest;

/// dns.c's DNS_VERIFY_FOUND, _MATCH and _SECURE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DnsVerdict {
    pub found: bool,
    pub matched: bool,
    pub secure: bool,
}

/// One SSHFP record: key algorithm, fingerprint type, fingerprint.
pub type Sshfp = (u8, u8, Vec<u8>);

/// The SSHFP algorithm number of a key (dns_read_key): 0 for types SSHFP
/// has no number for.
fn key_algorithm(key: &russh::keys::PublicKey) -> u8 {
    use russh::keys::Algorithm;
    match key.algorithm() {
        Algorithm::Rsa { .. } => 1,
        Algorithm::Ecdsa { .. } => 3,
        Algorithm::Ed25519 => 4,
        _ => 0,
    }
}

/// The verdict for a key and its host's records, or `None` where ssh
/// gives up on DNS: a key or fingerprint type it cannot compute.
pub fn judge(key: &russh::keys::PublicKey, records: &[Sshfp], secure: bool) -> Option<DnsVerdict> {
    let blob = key.to_bytes().ok()?;
    let alg = key_algorithm(key);
    let mut v = DnsVerdict { found: !records.is_empty(), secure, ..Default::default() };
    let mut failed = false;
    for (ralg, rtype, fp) in records {
        let digest: Vec<u8> = match rtype {
            1 => sha1::Sha1::digest(&blob).to_vec(),
            2 => sha2::Sha256::digest(&blob).to_vec(),
            _ => return None,
        };
        if alg == 0 {
            return None;
        }
        if *ralg == alg && digest.len() == fp.len() {
            // Constant time, as timingsafe_bcmp.
            if digest.iter().zip(fp).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0 {
                v.matched = true;
            } else {
                failed = true;
            }
        }
    }
    // Any record of the key's type that disagrees spoils the match.
    if failed {
        v.matched = false;
    }
    Some(v)
}

/// Looks up `host`'s SSHFP records. `None` for a numeric host and when the
/// lookup fails, including DNSSEC that does not validate (ssh: "DNS lookup
/// error", then no DNS verdict).
pub async fn check(host: &str, key: &russh::keys::PublicKey) -> Option<DnsVerdict> {
    if host.trim_start_matches('[').trim_end_matches(']').parse::<std::net::IpAddr>().is_ok() {
        tracing::debug!("VerifyHostKeyDNS: skipped DNS lookup for numerical hostname");
        return None;
    }
    let mut builder = match hickory_resolver::Resolver::builder_tokio() {
        Ok(b) => b,
        Err(e) => {
            tracing::info!("VerifyHostKeyDNS: no DNS configuration: {e}");
            return None;
        }
    };
    builder.options_mut().validate = true;
    let resolver = builder.build().ok()?;
    // The name as given, never through the search list (ssh's
    // getrrsetbyname uses res_query): a search domain must not answer for it.
    let fqdn = if host.ends_with('.') { host.to_string() } else { format!("{host}.") };
    let lookup = match tokio::time::timeout(Duration::from_secs(10), resolver.lookup(fqdn.as_str(), RecordType::SSHFP)).await {
        Ok(Ok(l)) => l,
        Ok(Err(e)) if e.is_no_records_found() => return judge(key, &[], false),
        Ok(Err(e)) => {
            tracing::info!("VerifyHostKeyDNS: DNS lookup error: {e}");
            return None;
        }
        Err(_) => {
            tracing::info!("VerifyHostKeyDNS: DNS lookup timed out");
            return None;
        }
    };
    let mut records = Vec::new();
    let mut secure = true;
    for r in lookup.answers() {
        // Every record on the way counts, CNAMEs too: an unsigned alias
        // into a signed zone proves nothing about this host.
        secure &= r.proof == Proof::Secure;
        if let RData::SSHFP(s) = &r.data {
            records.push((u8::from(s.algorithm), u8::from(s.fingerprint_type), s.fingerprint.clone()));
        }
    }
    let secure = secure && !records.is_empty();
    tracing::debug!("VerifyHostKeyDNS: found {} {} fingerprints in DNS", records.len(), if secure { "secure" } else { "insecure" });
    judge(key, &records, secure)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> russh::keys::PublicKey {
        russh::keys::PublicKey::from_openssh("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl").unwrap()
    }

    #[test]
    fn matches_sha256_and_sha1() {
        let k = key();
        let blob = k.to_bytes().unwrap();
        let s256 = sha2::Sha256::digest(&blob).to_vec();
        let s1 = sha1::Sha1::digest(&blob).to_vec();
        let v = judge(&k, &[(4, 2, s256.clone())], true).unwrap();
        assert_eq!(v, DnsVerdict { found: true, matched: true, secure: true });
        assert!(judge(&k, &[(4, 1, s1)], false).unwrap().matched);
        // Another key type's record neither matches nor spoils.
        assert!(judge(&k, &[(1, 2, vec![0; 32]), (4, 2, s256.clone())], true).unwrap().matched);
        // A wrong record of the same type spoils the match.
        assert!(!judge(&k, &[(4, 2, vec![0; 32]), (4, 2, s256)], true).unwrap().matched);
    }

    #[test]
    fn nothing_found_and_unknown_types() {
        let k = key();
        assert_eq!(judge(&k, &[], false).unwrap(), DnsVerdict::default());
        assert!(judge(&k, &[(4, 3, vec![0; 48])], true).is_none());
    }
}

/// Real hosts: REACH_DNS_HOSTS (comma separated), each key from
/// ssh-keyscan checked against the host's SSHFP records.
#[cfg(test)]
#[tokio::test]
#[ignore = "needs DNS and ssh-keyscan"]
async fn live_sshfp() {
    let hosts = std::env::var("REACH_DNS_HOSTS").unwrap();
    let mut secure_matches = 0;
    for h in hosts.split(',') {
        let out = std::process::Command::new("ssh-keyscan").args(["-T", "5", h]).output().unwrap();
        for line in String::from_utf8_lossy(&out.stdout).lines().filter(|l| !l.starts_with('#')) {
            let Some((_, k)) = line.split_once(' ') else { continue };
            let Ok(key) = russh::keys::PublicKey::from_openssh(k) else { continue };
            let v = check(h, &key).await;
            println!("{h} {}: {v:?}", key.algorithm().as_str());
            if v.is_some_and(|v| v.matched && v.secure) {
                secure_matches += 1;
            }
        }
    }
    assert!(secure_matches > 0);
    // Some other key: found, secure, no match.
    let other = russh::keys::PublicKey::from_openssh("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl").unwrap();
    let h = hosts.split(',').next().unwrap();
    let v = check(h, &other).await.unwrap();
    println!("{h} other key: {v:?}");
    assert!(v.found && !v.matched);
}
