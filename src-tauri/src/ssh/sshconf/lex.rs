//! Splitting a config line the way OpenSSH's readconf.c does: the keyword by
//! `strdelim` (whitespace or one `=`), the arguments by `argv_split` (quotes,
//! the four escapes, `#` ends the line outside quotes).

const WHITESPACE: &[char] = &[' ', '\t', '\r', '\n'];

/// A line split into its keyword and what follows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// As written; matched case-insensitively.
    pub keyword: String,
    /// The rest of the line after the keyword and its separator, as written.
    /// Commands (ProxyCommand, LocalCommand…) take this whole, quotes and all.
    pub rest: String,
}

/// The keyword and the rest of a line, or `None` for a blank line or a
/// comment. Trailing whitespace (and a form feed) is dropped first, as
/// OpenSSH does.
pub fn split_keyword(raw: &str) -> Option<Line> {
    let line = raw.trim_end_matches([' ', '\t', '\r', '\n', '\u{c}']);
    let line = line.trim_start_matches(WHITESPACE);
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    // strdelim: the token ends at whitespace, a quote or `=`. A quoted
    // keyword is not something OpenSSH documents; it still parses one, so
    // the quotes are taken off here too.
    let (keyword, after) = if let Some(stripped) = line.strip_prefix('"') {
        match stripped.find('"') {
            Some(end) => (stripped[..end].to_string(), &stripped[end + 1..]),
            None => (stripped.to_string(), ""),
        }
    } else {
        let end = line.find(|c: char| WHITESPACE.contains(&c) || c == '"' || c == '=').unwrap_or(line.len());
        (line[..end].to_string(), &line[end..])
    };
    // Skip whitespace, then at most one `=`, then whitespace again.
    let mut rest = after.trim_start_matches(WHITESPACE);
    if let Some(r) = rest.strip_prefix('=') {
        rest = r.trim_start_matches(WHITESPACE);
    }
    Some(Line { keyword, rest: rest.to_string() })
}

/// OpenSSH's `argv_split(s, …, terminate_on_comment = 1)`.
pub fn argv_split(s: &str) -> Result<Vec<String>, String> {
    split(s, true)
}

/// `argv_split(s, …, terminate_on_comment = 0)`, as commands are split.
pub fn argv_split_keep_comments(s: &str) -> Result<Vec<String>, String> {
    split(s, false)
}

fn split(s: &str, comments: bool) -> Result<Vec<String>, String> {
    let chars: Vec<char> = s.chars().collect();
    let mut args = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == ' ' || chars[i] == '\t' {
            i += 1;
            continue;
        }
        if comments && chars[i] == '#' {
            break;
        }
        let mut quote: Option<char> = None;
        let mut arg = String::new();
        while i < chars.len() {
            let c = chars[i];
            if c == '\\' {
                let next = chars.get(i + 1).copied();
                match next {
                    Some('\'') | Some('"') | Some('\\') => {
                        i += 1;
                        arg.push(chars[i]);
                    }
                    Some(' ') if quote.is_none() => {
                        i += 1;
                        arg.push(' ');
                    }
                    _ => arg.push('\\'),
                }
            } else if quote.is_none() && (c == ' ' || c == '\t') {
                break;
            } else if quote.is_none() && (c == '"' || c == '\'') {
                quote = Some(c);
            } else if quote == Some(c) {
                quote = None;
            } else {
                arg.push(c);
            }
            i += 1;
        }
        if quote.is_some() {
            return Err("invalid quotes".into());
        }
        args.push(arg);
    }
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kw(s: &str) -> (String, String) {
        let l = split_keyword(s).unwrap();
        (l.keyword, l.rest)
    }

    #[test]
    fn keyword_separators() {
        assert_eq!(kw("Port 22"), ("Port".into(), "22".into()));
        assert_eq!(kw("Port=22"), ("Port".into(), "22".into()));
        assert_eq!(kw("  Port = 22  "), ("Port".into(), "22".into()));
        assert_eq!(kw("Port\t22\r\n"), ("Port".into(), "22".into()));
        assert!(split_keyword("   # comment").is_none());
        assert!(split_keyword("\t\r\n").is_none());
    }

    #[test]
    fn only_one_equals_is_a_separator() {
        assert_eq!(kw("SetEnv =A=b"), ("SetEnv".into(), "A=b".into()));
        assert_eq!(kw("SetEnv==x"), ("SetEnv".into(), "=x".into()));
    }

    #[test]
    fn quotes_escapes_and_comments() {
        assert_eq!(argv_split(r#"a "b c" 'd e'"#).unwrap(), ["a", "b c", "d e"]);
        assert_eq!(argv_split(r"a\ b c").unwrap(), ["a b", "c"]);
        assert_eq!(argv_split(r#"x\"y \\z \q"#).unwrap(), ["x\"y", "\\z", "\\q"]);
        assert_eq!(argv_split("a # b").unwrap(), ["a"]);
        assert_eq!(argv_split("a#b").unwrap(), ["a#b"]);
        assert_eq!(argv_split(r#""a # b""#).unwrap(), ["a # b"]);
        assert_eq!(argv_split(r#""""#).unwrap(), [""]);
        assert!(argv_split(r#""open"#).is_err());
    }
}
