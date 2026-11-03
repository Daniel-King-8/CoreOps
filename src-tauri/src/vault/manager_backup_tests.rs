use super::*;

fn tmp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("reach-backup-test-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A backup gives back every secret exactly as it went in, byte for byte.
/// Keys above all: one that came back changed (a line end, a space, an
/// encoding) would be a different key, refused by every server that trusted
/// the original. The texts here are the awkward ones a key file can hold:
/// Windows line ends, trailing spaces, a byte order mark, non-ASCII.
#[tokio::test]
async fn a_backup_restores_every_secret_byte_for_byte() {
    let texts: Vec<(&str, Vec<u8>)> = vec![
        ("lf", b"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n".to_vec()),
        ("crlf", b"-----BEGIN OPENSSH PRIVATE KEY-----\r\nAAAA\r\n-----END OPENSSH PRIVATE KEY-----\r\n".to_vec()),
        ("trailing spaces", b"-----BEGIN RSA PRIVATE KEY-----  \nAAAA \t\n-----END RSA PRIVATE KEY-----".to_vec()),
        ("bom", "\u{feff}PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n".as_bytes().to_vec()),
        ("non-ascii", "κλειδί 🔑 \u{0}\u{7f}".as_bytes().to_vec()),
        ("json-looking", br#"{"private_key":"-----BEGIN\r\n","passphrase":"p\"q"}"#.to_vec()),
    ];

    let source = tmp_dir("source");
    let mut mgr = VaultManager::new(source.clone());
    mgr.init_identity("backup-test-pass").await.unwrap();
    // The keys vault the app uses: the internal one made with the identity,
    // found by name as ssh_key_import's ensure_vault finds it.
    let vault_id = mgr.get_vault_id_by_name(SSH_KEYS_VAULT).expect("the identity makes the keys vault");
    for (name, bytes) in &texts {
        mgr.create_secret_with_id(&vault_id, name, name, SecretCategory::SshKey, SecretBox::new(Box::new(bytes.clone())))
            .await
            .unwrap();
    }
    let backup = mgr.export_full_backup("export-pass").await.unwrap();

    // Another machine: nothing but the backup file.
    let target = tmp_dir("target");
    let mut restored = VaultManager::new(target.clone());
    restored.import_full_backup(&backup, "export-pass", "backup-test-pass").await.unwrap();
    // As the app does after a restore.
    restored.unlock("backup-test-pass").await.unwrap();
    let vault_id = restored.get_vault_id_by_name(SSH_KEYS_VAULT).expect("the keys vault came back");
    for (name, bytes) in &texts {
        let back = restored.read_secret(&vault_id, name).await.unwrap();
        assert_eq!(back.expose_secret(), bytes, "{name} changed in the backup");
    }

    // The test identity's key went into the OS keychain twice (made, then
    // restored); it is the same entry, and it goes.
    let uuid = restored.user_uuid.clone().unwrap();
    let _ = delete_key_from_keychain(&uuid);
    let _ = std::fs::remove_dir_all(&source);
    let _ = std::fs::remove_dir_all(&target);
}
