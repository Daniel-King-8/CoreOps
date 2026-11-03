use super::*;
use std::time::Duration;
use crate::vault::types::{VaultHeader, VaultType};

// Leaving Reach open long enough used to stop it reading anything, from
// the server or the cache, until it was closed and reopened: a remote
// vault kept one connection forever, and libsql cannot recover a stream
// whose baton the server expired. These cover when that connection is
// given up.

#[test]
fn idleness_never_troubles_a_local_vault() {
    // No stream, nothing to time out — reconnecting an idle local handle
    // would only cost time.
    assert!(!should_reconnect(false, Duration::from_secs(0), Duration::from_secs(0)));
    assert!(!should_reconnect(false, Duration::from_secs(3600), Duration::from_secs(1)));
}

#[test]
fn a_local_connection_is_not_kept_for_the_whole_session() {
    // The fear worth having: a connection held open all day that quietly
    // goes bad. A local handle cannot expire, but an I/O error — a laptop
    // waking up, a synced folder, a disk hiccup — can leave it failing
    // every query when a fresh one would work. Nothing about that is
    // idleness, so without an age bound it would be kept until Reach was
    // restarted, which is the bug we started from wearing a different
    // hat.
    assert!(should_reconnect(
        false,
        Duration::from_millis(1),
        STREAM_MAX_AGE + Duration::from_millis(1)
    ));
    assert!(should_reconnect(false, Duration::from_secs(0), Duration::from_secs(3600)));
}

#[test]
fn back_to_back_work_reuses_one_connection() {
    // Reading twelve sessions is twelve operations a few milliseconds
    // apart. Reconnecting for each one measurably slowed the session
    // list down, which is why this matters.
    assert!(!should_reconnect(true, Duration::from_millis(5), Duration::from_secs(1)));
    assert!(!should_reconnect(true, STREAM_IDLE_GRACE, Duration::from_secs(1)));
}

#[test]
fn an_idle_connection_is_given_up() {
    assert!(should_reconnect(
        true,
        STREAM_IDLE_GRACE + Duration::from_millis(1),
        Duration::from_secs(1)
    ));
}

#[test]
fn a_busy_connection_is_still_given_up_eventually() {
    // The one that nearly got away. A connection can die from something
    // other than idleness — a network blip, a token refresh, a server
    // restart — and steady use keeps refreshing the idle clock, so
    // idleness alone would pin a dead connection for as long as someone
    // kept hitting retry. Age is what breaks that.
    assert!(!should_reconnect(true, Duration::from_millis(1), STREAM_MAX_AGE));
    assert!(should_reconnect(
        true,
        Duration::from_millis(1),
        STREAM_MAX_AGE + Duration::from_millis(1)
    ));
}

#[test]
fn no_connection_outlives_the_age_bound_however_it_is_used() {
    // Whatever the vault is and whatever the pattern of use, a connection
    // that has gone bad is replaced within a minute rather than lasting
    // until the app is closed and reopened.
    for is_remote in [true, false] {
        for idle_ms in [0u64, 1, 4_000, 60_000] {
            assert!(
                should_reconnect(
                    is_remote,
                    Duration::from_millis(idle_ms),
                    STREAM_MAX_AGE + Duration::from_millis(1)
                ),
                "remote={is_remote} idle={idle_ms}ms should have been given up"
            );
        }
    }
}

/// Build a vault backed by a real local database, so the retry path can
/// be exercised rather than reasoned about.
async fn local_vault(name: &str) -> (VaultConnection, PathBuf) {
    let path = std::env::temp_dir().join(format!(
        "reach-conn-test-{}-{}-{:?}.db",
        name,
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&path);
    let db = crate::vault::sync::create_replica(&path, None).await.unwrap();
    let conn = db.connect().unwrap();
    let vault = VaultConnection {
        db,
        conn: std::sync::Mutex::new(CachedConnection {
            conn,
            last_used: std::time::Instant::now(),
            opened: std::time::Instant::now(),
            retired: false,
        }),
        header: VaultHeader {
            id: "test".into(),
            name: name.into(),
            salt: [0u8; 32],
            user_uuid: "test-user".into(),
            created_at: 0,
            vault_type: VaultType::Private,
        },
        master_dek: None,
        sync_url: None,
        auth_token: None,
        cache: None,
    };
    (vault, path)
}

#[tokio::test]
async fn a_retired_connection_is_replaced_and_the_data_is_still_there() {
    // The cure, against a real database: throwing the connection away
    // mid-life must not lose the vault, and the replacement must see
    // everything the old one wrote.
    let (vault, path) = local_vault("retire").await;
    vault
        .execute("CREATE TABLE t (id TEXT PRIMARY KEY, v TEXT)", ())
        .await
        .unwrap();
    vault
        .execute("INSERT OR REPLACE INTO t (id, v) VALUES (?, ?)", ("a", "first"))
        .await
        .unwrap();

    vault.retire();

    let mut rows = vault.query("SELECT v FROM t WHERE id = ?", ["a"]).await.unwrap();
    let v: String = rows.next().await.unwrap().unwrap().get(0).unwrap();
    assert_eq!(v, "first", "the replacement connection must see the old writes");

    // And the vault keeps working afterwards, rather than being retired
    // once and left broken.
    vault
        .execute("INSERT OR REPLACE INTO t (id, v) VALUES (?, ?)", ("b", "second"))
        .await
        .unwrap();
    let mut rows = vault.query("SELECT COUNT(*) FROM t", ()).await.unwrap();
    let n: i64 = rows.next().await.unwrap().unwrap().get(0).unwrap();
    assert_eq!(n, 2);

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn a_statement_that_is_simply_wrong_still_fails() {
    // Retrying must not turn a broken query into a hang or a false
    // success — a bad statement fails on both attempts and reports it.
    let (vault, path) = local_vault("bad-sql").await;
    assert!(vault.query("SELECT * FROM nope", ()).await.is_err());
    // And the vault is still usable after that failure, even though the
    // retry retired the connection on the way through.
    vault.execute("CREATE TABLE t (id TEXT)", ()).await.unwrap();
    let _ = std::fs::remove_file(&path);
}

#[test]
fn the_grace_is_shorter_than_the_lifetime() {
    // Otherwise the age bound would be the only rule in force and idle
    // streams would go unnoticed.
    assert!(STREAM_IDLE_GRACE < STREAM_MAX_AGE);
}

/// Issue #77: a Turso request that is never answered must fail, not hang.
/// The server here takes the connection and then says nothing at all, the
/// way a dropped connection behind a firewall or proxy looks. Opening a
/// synced vault with no cache yet reads its header from Turso; that read,
/// and its one retry, now give up after `REMOTE_TIMEOUT` each.
#[tokio::test]
async fn a_turso_that_never_answers_fails_instead_of_hanging() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming().flatten() {
            held.push(stream); // accepted, never read from or written to
        }
    });

    let dir = std::env::temp_dir().join(format!("reach-silent-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut mgr = VaultManager::new(dir.clone());
    let url = format!("http://127.0.0.1:{port}");

    let started = std::time::Instant::now();
    let opened = tokio::time::timeout(
        REMOTE_TIMEOUT * 4,
        mgr.open_vault("silent-vault", Some(&url), Some("token")),
    )
    .await
    .expect("opening a vault against a silent server hung");
    assert!(opened.is_err(), "a server that never answered cannot have opened a vault");
    assert!(started.elapsed() < REMOTE_TIMEOUT * 4);
    let _ = std::fs::remove_dir_all(&dir);
}
