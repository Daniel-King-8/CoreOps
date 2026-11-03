use super::*;

#[test]
fn the_unlock_file_survives_a_round_trip_and_removal() {
    let dir = std::env::temp_dir().join(format!("reach-unlock-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    assert!(load(&dir).is_none());
    let mut unlockers = Unlockers::new("u");
    let seal = unlockers.seal_for_test(FIDO2, &[1u8; 32], b"secret");
    unlockers.add(seal);
    save(&dir, &unlockers).unwrap();
    let back = load(&dir).unwrap();
    assert_eq!(back.user_uuid, "u");
    assert_eq!(back.list().len(), 1);
    assert!(!back.proven);
    remove(&dir).unwrap();
    remove(&dir).unwrap();
    assert!(load(&dir).is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn each_seal_opens_only_with_its_own_key_user_and_kind() {
    let mut alice = Unlockers::new("alice");
    let yubikey = alice.seal_for_test(FIDO2, &[1u8; 32], b"vault key");
    let backup = alice.seal_for_test(FIDO2, &[2u8; 32], b"vault key");
    let (yubikey_id, backup_id) = (yubikey.id.clone(), backup.id.clone());
    alice.add(yubikey);
    alice.add(backup);

    assert_eq!(&*alice.open_for_test(&[1u8; 32], &yubikey_id).unwrap(), b"vault key");
    assert_eq!(&*alice.open_for_test(&[2u8; 32], &backup_id).unwrap(), b"vault key");
    // One key never opens the other's seal.
    assert!(alice.open_for_test(&[1u8; 32], &backup_id).is_err());

    // Bound to the user: the same seal under another user does not open.
    let mut bob = alice.clone();
    bob.user_uuid = "bob".into();
    assert!(bob.open_for_test(&[1u8; 32], &yubikey_id).is_err());

    // Bound to the kind: relabelled as Windows Hello, it does not open.
    let mut relabelled = alice.clone();
    relabelled.seals[0].kind = WINDOWS_HELLO.into();
    assert!(relabelled.open_for_test(&[1u8; 32], &yubikey_id).is_err());
}

#[test]
fn windows_hello_has_one_seal_and_keys_many() {
    let mut u = Unlockers::new("u");
    u.add(u.seal_for_test(WINDOWS_HELLO, &[1u8; 32], b"s"));
    u.add(u.seal_for_test(WINDOWS_HELLO, &[2u8; 32], b"s"));
    u.add(u.seal_for_test(FIDO2, &[3u8; 32], b"s"));
    u.add(u.seal_for_test(FIDO2, &[4u8; 32], b"s"));
    assert_eq!(u.list().iter().filter(|s| s.kind == WINDOWS_HELLO).count(), 1);
    assert_eq!(u.list().iter().filter(|s| s.kind == FIDO2).count(), 2);
    let id = u.list()[0].id.clone();
    assert!(u.remove(&id).is_some());
    assert!(u.remove(&id).is_none());
}

#[test]
fn the_seal_key_from_a_security_key_is_derived_not_raw() {
    let output = [5u8; 32];
    assert_ne!(*fido_key(&output), output);
    assert_eq!(*fido_key(&output), *fido_key(&output));
}

/// Asks the real platform; run by hand: `cargo test hello_probe -- --ignored --nocapture`.
#[test]
#[ignore]
fn hello_probe() {
    let t = std::time::Instant::now();
    println!(
        "platform={:?} available={} fido2={} in {:?}",
        platform_method(),
        platform_available(),
        fido2::supported(),
        t.elapsed()
    );
}
