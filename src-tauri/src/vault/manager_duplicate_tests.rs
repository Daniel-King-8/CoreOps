use super::*;

fn vault(id: &str, url: Option<&str>) -> StoredVaultRef {
    StoredVaultRef {
        id: id.into(),
        name: "PegasusAC".into(),
        vault_type: "shared".into(),
        sync_url: url.map(Into::into),
        sync_token: Some("t".into()),
    }
}

#[test]
fn the_same_database_written_differently_is_the_same() {
    assert!(same_database(Some("libsql://team-x.turso.io"), Some("https://TEAM-X.turso.io/")));
    assert!(!same_database(Some("libsql://team-x.turso.io"), Some("libsql://team-y.turso.io")));
    // Local vaults have no database to share.
    assert!(!same_database(None, None));
    assert!(!same_database(Some(""), Some("")));
}

#[test]
fn entries_over_one_database_are_grouped() {
    let vaults = [
        vault("first", Some("libsql://team-x.turso.io")),
        vault("local-a", None),
        vault("local-b", None),
        vault("other", Some("libsql://team-y.turso.io")),
        vault("second", Some("https://team-x.turso.io")),
        vault("third", Some("libsql://team-x.turso.io/")),
    ];
    assert_eq!(duplicate_groups(&vaults), [vec!["first", "second", "third"]]);
}

#[test]
fn no_duplicates_no_groups() {
    let vaults = [vault("a", Some("libsql://team-x.turso.io")), vault("b", None), vault("c", None)];
    assert!(duplicate_groups(&vaults).is_empty());
}
