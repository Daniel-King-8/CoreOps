//! Pattern matching as OpenSSH's match.c does it: `*` and `?` wildcards,
//! comma-separated lists where `!` negates, and CIDR lists for addresses.

use std::net::IpAddr;

/// `match_pattern`: `*` matches any run of characters, `?` exactly one.
/// Case-sensitive, as OpenSSH's is.
pub fn match_pattern(s: &str, pattern: &str) -> bool {
    let s: Vec<char> = s.chars().collect();
    let p: Vec<char> = pattern.chars().collect();
    // Iterative glob with backtracking to the last `*`.
    let (mut si, mut pi) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while si < s.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == s[si]) {
            si += 1;
            pi += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Result of matching against a pattern list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListMatch {
    /// A negated pattern matched: the list says no, whatever else matched.
    Negative,
    NoMatch,
    Match,
}

/// `match_pattern_list`: a comma-separated list; a `!` pattern that matches
/// makes the whole list a refusal. `lower` lowercases the patterns (the
/// string is lowercased by the caller where OpenSSH does so).
pub fn match_pattern_list(s: &str, list: &str, lower: bool) -> ListMatch {
    let mut got_positive = false;
    for part in list.split(',') {
        let (negated, pat) = match part.strip_prefix('!') {
            Some(p) => (true, p),
            None => (false, part),
        };
        // OpenSSH gives up on a sub-pattern of 1023 bytes or more.
        if pat.len() >= 1023 {
            return ListMatch::NoMatch;
        }
        let pat = if lower { pat.to_ascii_lowercase() } else { pat.to_string() };
        if match_pattern(s, &pat) {
            if negated {
                return ListMatch::Negative;
            }
            got_positive = true;
        }
    }
    if got_positive { ListMatch::Match } else { ListMatch::NoMatch }
}

/// `match_hostname`: the host lowercased, the patterns too.
pub fn match_hostname(host: &str, list: &str) -> ListMatch {
    match_pattern_list(&host.to_ascii_lowercase(), list, true)
}

/// A network from a `Match localnetwork` list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Cidr> {
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = a.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            Some(p) => {
                if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                let n: u8 = p.parse().ok()?;
                if n > max {
                    return None;
                }
                n
            }
            None => max,
        };
        // OpenSSH refuses a network with host bits set ("10.0.0.1/8").
        let c = Cidr { addr, prefix };
        if c.network() != addr {
            return None;
        }
        Some(c)
    }

    fn network(&self) -> IpAddr {
        mask(self.addr, self.prefix)
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        ip.is_ipv4() == self.addr.is_ipv4() && mask(ip, self.prefix) == self.network()
    }
}

fn mask(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v) => {
            let m = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix as u32) };
            IpAddr::V4((u32::from(v) & m).into())
        }
        IpAddr::V6(v) => {
            let m = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix as u32) };
            IpAddr::V6((u128::from(v) & m).into())
        }
    }
}

/// Parse a comma-separated CIDR list, as `addr_match_cidr_list(NULL, …)`
/// validates one. Negation is not allowed in it.
pub fn parse_cidr_list(list: &str) -> Result<Vec<Cidr>, String> {
    list.split(',')
        .map(|s| Cidr::parse(s).ok_or_else(|| format!("invalid network \"{s}\"")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards() {
        assert!(match_pattern("web1.lan", "web?.lan"));
        assert!(match_pattern("web1.lan", "*.lan"));
        assert!(match_pattern("x", "*"));
        assert!(match_pattern("", "*"));
        assert!(!match_pattern("web.lan", "web?.lan"));
        assert!(!match_pattern("Web", "web"));
        assert!(match_pattern("aXbXc", "a*b*c"));
        assert!(!match_pattern("abc", "a*d"));
        assert!(match_pattern("", ""));
    }

    #[test]
    fn lists_and_negation() {
        assert_eq!(match_pattern_list("web", "db,web", false), ListMatch::Match);
        assert_eq!(match_pattern_list("web", "*,!web", false), ListMatch::Negative);
        assert_eq!(match_pattern_list("x", "!web", false), ListMatch::NoMatch);
        assert_eq!(match_hostname("WEB.Lan", "*.LAN"), ListMatch::Match);
    }

    #[test]
    fn networks() {
        let n = Cidr::parse("192.168.1.0/24").unwrap();
        assert!(n.contains("192.168.1.70".parse().unwrap()));
        assert!(!n.contains("192.168.2.1".parse().unwrap()));
        assert!(Cidr::parse("10.0.0.1/8").is_none());
        assert!(Cidr::parse("fd00::/8").unwrap().contains("fd12::1".parse().unwrap()));
        assert!(parse_cidr_list("10.0.0.0/8,bad").is_err());
    }
}
