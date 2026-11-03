use super::*;
use chrono::TimeZone;

fn at(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> chrono::DateTime<chrono::Local> {
    chrono::Local.with_ymd_and_hms(y, mo, d, h, mi, s).single().expect("a valid local time")
}

fn cfg(folder: &Path, mode: LogMode, name: &str, append: bool, header: bool) -> SessionLogConfig {
    SessionLogConfig { mode, folder: folder.display().to_string(), name: name.into(), append, header }
}

/// Waits for the writer thread, which owns the file, to have written `want`.
fn read_when(path: &Path, want: impl Fn(&str) -> bool) -> String {
    for _ in 0..200 {
        if let Ok(s) = std::fs::read_to_string(path) {
            if want(&s) {
                return s;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    std::fs::read_to_string(path).unwrap_or_default()
}

/// A folder of its own per test, removed afterwards.
struct Temp(PathBuf);

impl Temp {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temp() -> Temp {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let p = std::env::temp_dir().join(format!("reach-log-test-{}-{}", std::process::id(), n));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("a temp dir");
    Temp(p)
}

/// The example in PuTTY's manual (4.2.1), character for character.
#[test]
fn putty_manual_example() {
    let now = at(2001, 5, 28, 11, 8, 59);
    assert_eq!(
        expand_name("log-&h-&y&m&d-&t.dat", "server1.example.com", 22, &now),
        "log-server1.example.com-20010528-110859.dat"
    );
}

#[test]
fn placeholders_are_case_insensitive_and_port_works() {
    let now = at(2026, 10, 2, 7, 5, 3);
    assert_eq!(expand_name("&H_&P_&Y-&M-&D_&T", "box", 2222, &now), "box_2222_2026-10-02_070503");
}

/// PuTTY: `&&` is a literal `&`, an unknown `&x` stays as typed, and a
/// trailing `&` expands to nothing.
#[test]
fn ampersand_rules_match_putty() {
    let now = at(2026, 1, 1, 0, 0, 0);
    assert_eq!(expand_name("a&&b", "h", 1, &now), "a&b");
    assert_eq!(expand_name("a&xb", "h", 1, &now), "a&xb");
    assert_eq!(expand_name("ab&", "h", 1, &now), "ab");
}

/// What a host inserts can never be a separator or a drive colon: an IPv6
/// address, or a hostile name, stays one file name inside the folder.
#[test]
fn inserted_text_cannot_make_a_path() {
    let now = at(2026, 1, 1, 0, 0, 0);
    assert_eq!(expand_name("&h.log", "fe80::1", 22, &now), "fe80..1.log");
    let evil = expand_name("&h.log", "../../etc/passwd", 22, &now);
    assert!(!evil.contains('/') && !evil.contains('\\'), "{evil}");
    assert_eq!(expand_name("&h", "C:\\x|y?*<>\"\n", 22, &now), "C..x.y......");

    let dir = temp();
    let c = cfg(dir.path(), LogMode::Printable, "&h", true, false);
    for host in ["..", ".", "../..", "/etc/passwd", "C:\\Windows"] {
        if let Ok(p) = resolve_path(&c, host, 22, &now) {
            assert!(p.starts_with(dir.path()), "{host} escaped to {}", p.display());
            assert_ne!(p, dir.path().to_path_buf());
        }
    }
}

/// The user's own name may use sub-folders, never `..` or a full path.
#[test]
fn literal_name_may_have_subfolders_but_not_escape() {
    let now = at(2026, 1, 1, 0, 0, 0);
    let dir = temp();
    let ok = cfg(dir.path(), LogMode::Printable, "&h/&y.log", true, false);
    assert_eq!(resolve_path(&ok, "box", 22, &now).unwrap(), dir.path().join("box").join("2026.log"));
    for bad in ["../x.log", "a/../../x.log"] {
        let c = cfg(dir.path(), LogMode::Printable, bad, true, false);
        assert!(resolve_path(&c, "box", 22, &now).is_err(), "{bad} was accepted");
    }
    let abs = if cfg!(windows) { "C:\\x.log" } else { "/tmp/x.log" };
    assert!(resolve_path(&cfg(dir.path(), LogMode::Printable, abs, true, false), "b", 22, &now).is_err());
}

#[test]
fn relative_folder_is_refused_and_empty_values_use_defaults() {
    let now = at(2026, 1, 1, 0, 0, 0);
    let rel = SessionLogConfig { mode: LogMode::All, folder: "logs".into(), name: "x".into(), append: true, header: true };
    assert!(resolve_path(&rel, "h", 22, &now).is_err());

    let empty = SessionLogConfig { mode: LogMode::All, folder: String::new(), name: "  ".into(), append: true, header: true };
    let p = resolve_path(&empty, "h", 22, &now).unwrap();
    assert!(p.starts_with(default_dir()));
    assert_eq!(p.file_name().unwrap(), "h-20260101-000000.log");
    assert!(default_dir().is_absolute());
}

/// PuTTY's header, with Reach's name.
#[test]
fn header_matches_putty_format() {
    assert_eq!(
        header_line(&at(2026, 10, 2, 1, 30, 0)),
        "=~=~=~=~=~=~=~=~=~=~=~= Reach log 2026.10.02 01:30:00 =~=~=~=~=~=~=~=~=~=~=~=\r\n"
    );
}

/// Printable output: colours, titles and cursor movement go; text, CR, LF,
/// tab and non-ASCII text stay. A sequence split across two packets is still
/// recognised, which is why a real parser is used.
#[test]
fn printable_drops_control_sequences_even_when_split() {
    let dir = temp();
    let mut log = SessionLog::open(&cfg(dir.path(), LogMode::Printable, "p.log", true, false), "h", 22).unwrap();
    log.push("\x1b]0;user@box: ~\x07\x1b[01;32muser@box\x1b[00m:\x1b[01;34m~\x1b[00m$ ls\r\n");
    log.push("a\tb κόσμος\x1b[");
    log.push("2Kdone\x1b[?2004h\x07\x08\r\n");
    let path = log.path().to_path_buf();
    drop(log);
    let text = read_when(&path, |s| s.ends_with("done\r\n"));
    assert_eq!(text, "user@box:~$ ls\r\na\tb κόσμοςdone\r\n");
}

/// All session output: exactly what was sent to the terminal.
#[test]
fn all_output_is_byte_for_byte() {
    let dir = temp();
    let raw = "\x1b[31mred\x1b[0m\r\n\x07κ";
    let mut log = SessionLog::open(&cfg(dir.path(), LogMode::All, "a.log", true, false), "h", 22).unwrap();
    log.push(raw);
    let path = log.path().to_path_buf();
    drop(log);
    assert_eq!(read_when(&path, |s| s.ends_with('κ')), raw);
}

/// Append keeps what was there; overwrite replaces it; the header comes
/// first when asked for.
#[test]
fn append_keeps_and_overwrite_replaces() {
    let dir = temp();
    let path = dir.path().join("same.log");
    std::fs::write(&path, "earlier session\n").unwrap();

    let mut log = SessionLog::open(&cfg(dir.path(), LogMode::All, "same.log", true, true), "h", 22).unwrap();
    log.push("new\r\n");
    drop(log);
    let text = read_when(&path, |s| s.ends_with("new\r\n"));
    assert!(text.starts_with("earlier session\n=~=~=~=~=~=~=~=~=~=~=~= Reach log "), "{text}");

    let mut log = SessionLog::open(&cfg(dir.path(), LogMode::All, "same.log", false, false), "h", 22).unwrap();
    log.push("only this");
    drop(log);
    assert_eq!(read_when(&path, |s| s == "only this"), "only this");
}

/// Missing folders are made; a log that cannot be written is an error the
/// caller sees, never a silent nothing.
#[test]
fn creates_folders_and_reports_failure() {
    let dir = temp();
    let log = SessionLog::open(&cfg(&dir.path().join("a").join("b"), LogMode::All, "x.log", true, true), "h", 22).unwrap();
    assert!(log.path().exists());
    drop(log);

    let file = dir.path().join("not-a-folder");
    std::fs::write(&file, "x").unwrap();
    assert!(SessionLog::open(&cfg(&file, LogMode::All, "x.log", true, true), "h", 22).is_err());
}

/// Logs hold whatever the server printed, so only their owner may read them.
#[cfg(unix)]
#[test]
fn new_logs_and_folders_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp();
    let sub = dir.path().join("logs");
    let log = SessionLog::open(&cfg(&sub, LogMode::All, "x.log", true, true), "h", 22).unwrap();
    assert_eq!(std::fs::metadata(log.path()).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::metadata(&sub).unwrap().permissions().mode() & 0o777, 0o700);
}

/// What the frontend sends deserialises, and leaving out the optional
/// fields gives append with a header, PuTTY's safe choices.
#[test]
fn config_from_frontend() {
    let c: SessionLogConfig = serde_json::from_str(r#"{"mode":"printable","name":"&H.log"}"#).unwrap();
    assert_eq!(c.mode, LogMode::Printable);
    assert!(c.append && c.header && c.folder.is_empty());
    let c: SessionLogConfig =
        serde_json::from_str(r#"{"mode":"all","folder":"/x","name":"n","append":false,"header":false}"#).unwrap();
    assert_eq!(c.mode, LogMode::All);
    assert!(!c.append && !c.header);
    assert!(serde_json::from_str::<SessionLogConfig>(r#"{"mode":"packets","name":"n"}"#).is_err());
}
