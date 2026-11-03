//! Known answers recorded with the crypto crates the vault was first written
//! with. Vaults, backups and shared-vault keys already on people's disks were
//! made by those crates, so whatever the crates become, these must still open.
//! A crypto dependency upgrade that fails here would lock people out of their
//! data.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use secrecy::ExposeSecret;

use super::crypto::{decrypt_secret, unwrap_dek, unwrap_dek_with_key};
use super::export::{unseal_bundle, ExportBundle};
use super::kdf::derive_kek;
use super::sharing::{decrypt_identity_key, unwrap_dek_for_member};
use super::types::{Dek, EncryptedPayload, Kek, UserIdentity, WrappedDek};

const PASSWORD: &[u8] = b"correct horse battery staple";
const SALT: [u8; 32] = [7; 32];
const DEK: [u8; 32] = [0x42; 32];
const MASTER: [u8; 32] = [0x24; 32];
const IDENTITY: [u8; 32] = [0x11; 32];
const SECRET: &[u8] = b"the vault's contents";
const BACKUP_PASSWORD: &str = "backup-password";

fn wrapped(b64: &str) -> WrappedDek {
    let bytes = B64.decode(b64).unwrap();
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&bytes[..24]);
    WrappedDek { nonce, ciphertext: bytes[24..].to_vec() }
}

fn flat(w: &WrappedDek) -> String {
    B64.encode([&w.nonce[..], &w.ciphertext[..]].concat())
}

fn bundle() -> ExportBundle {
    serde_json::from_value(serde_json::json!({
        "version": 1,
        "exported_at": 0,
        "identity": {
            "user_uuid": "u", "salt": "s", "encrypted_key": "k", "nonce": "n", "public_key": "p"
        },
        "vaults": []
    }))
    .unwrap()
}

// Recorded by print_known_answers with aes-gcm 0.10, argon2 0.5,
// chacha20poly1305 0.10, hkdf 0.12, sha2 0.10 and x25519-dalek 2.
const KEK: &str = "9wtX71MKMpJ/jlSzBSEvNf4zGIM5UBBJqdWv0Ghfj0k=";
const WRAPPED_BY_KEK: &str = "FtOUItZeup1rhjzkk+6EWYvy+Cn584N6gbMHnMWjax3PrTf+GdlenQD2/bsHPTO0397AZ+IHK5C2Mxi0i62oDMPxuudMqLH6";
const WRAPPED_BY_KEY: &str = "J6AVRP5dfYwNHDmE1oPdPDeR7hD1U7NZnVnB5zj1/DqjQb1Zk9kNWyTruDK9Czj1NQXq5boh/tdKbSNGsAtQjDNSmndkNgoF";
const PAYLOAD: &str = "eyJub25jZSI6WzUsOTcsNzEsNTgsMTQzLDExNCwxNzQsMjE3LDExNCwyOCwxMzYsMTEwLDgyLDEzOCwyMjcsMTYzLDE4OSwxMTUsMjExLDE1OSwxOCwyNDQsMTkzLDk1XSwiY2lwaGVydGV4dCI6WzE0MywyNDMsMTQ1LDIzLDU2LDc3LDM0LDQyLDU2LDE0OCwxNDAsMTY0LDEyMCw2OCw2OSwyMjAsMTc1LDIzLDYxLDE0NiwxNzUsMjEzLDEzMyw2NCwxNywxODIsMTI0LDIxNSw5NywxNzIsMjU0LDEzOSw4MCw0LDExMywxNTNdLCJ3cmFwcGVkX2RlayI6eyJub25jZSI6WzE0LDgxLDIwMSwxMDQsOTYsNjYsMTg1LDIwOCwxMDMsMTE5LDIzOCwxOTcsNTcsNDYsNjQsMTQzLDIzLDY1LDgwLDEzOCw1Nyw1OSwxNDYsOTddLCJjaXBoZXJ0ZXh0IjpbOTIsMjU1LDEyMiwxOTUsODUsMzAsMTYxLDEyOCwxMCwxMDEsMTg2LDI0NCwyNyw4MiwyNywxMTIsOTAsMjYsNTIsMiwxMTUsOCwzOSwxNjIsMTgyLDk1LDE5LDUzLDcyLDgsMjQ1LDIwMywxNTUsMjQ5LDEzNSwxOTIsMTg3LDIyOCwyMzIsMjAsNDcsMTcxLDc2LDIxMCw2OSwxMCw3NSw2N119fQ==";
const IDENTITY_KEY: &str = "IyL0RgXfFmZXTP5Vopr80xMaoTEaoxjkiyQacfL7fFzdzR1LtQ10aoBqDcFRwsAW";
const IDENTITY_NONCE: &str = "DngJpA5Q8ASXDZolCcbfbGgOEGmkjd9b";
const FOR_MEMBER: &str = "p5yxsSMckoeSceTGFFm1yjQUVwZHnzP+TNRgJ5MihhHQN5fLunrbFa1RY/PV0WkaNNT2qXWjpV4LJ3LKW46RAs/5AvmN/g2YXq9DBSY275Qj+hkY6m1YTIPKA9YizziF1If2ioN2QdE=";
const BACKUP: &str = "UkVBQ0hCQUsBACFuiZOwduBiGNcBgPImsWUVouZyeAjIfIHpgpfEfbPjsGXclXxNCkIfmNaLG0i1Fnc31fTiEzpFuwAAAIXeFcFzeKAg1Tt0558g0CnYbLYz07hVbmZh6QhLGRfcse9MIbo2OcxMw7r6CB2vFhOMn+KBnibvm103qa9ZPgTGkAycrT1vpr7Mo9IVNjVcSweURlvVjyWWQ+wkRnpJftI/SH4Chu5CdOhYquyI1eJnHGkdZtCUeuFE/6h8djkwB4XmYFQFWh0+QErKwW5uOFvqnKtgCz1SryAoSXKK7hzi61Au9b1DkXy1xJCchuDzgqarw+4hM8QtI9Avq432PDuQVyYu1+YCv0qa";

#[test]
fn a_password_still_derives_the_same_key() {
    let kek = derive_kek(PASSWORD, &SALT).unwrap();
    assert_eq!(kek.with_key(|k| B64.encode(k)), KEK);
}

#[test]
fn keys_wrapped_before_still_unwrap() {
    let kek = Kek::new(B64.decode(KEK).unwrap().try_into().unwrap());
    assert_eq!(unwrap_dek(&kek, &wrapped(WRAPPED_BY_KEK)).unwrap().with_key(|k| *k), DEK);
    assert_eq!(unwrap_dek_with_key(&DEK, &wrapped(WRAPPED_BY_KEY)).unwrap().with_key(|k| *k), MASTER);
}

#[test]
fn secrets_encrypted_before_still_decrypt() {
    let payload: EncryptedPayload = serde_json::from_slice(&B64.decode(PAYLOAD).unwrap()).unwrap();
    let plain = decrypt_secret(&Dek::new(MASTER), &payload).unwrap();
    assert_eq!(plain.expose_secret().as_slice(), SECRET);
}

#[test]
fn a_stored_identity_and_a_shared_vault_key_still_open() {
    let kek = derive_kek(PASSWORD, &SALT).unwrap();
    let nonce: [u8; 24] = B64.decode(IDENTITY_NONCE).unwrap().try_into().unwrap();
    let secret = kek.with_key(|k| decrypt_identity_key(k, &B64.decode(IDENTITY_KEY).unwrap(), &nonce)).unwrap();
    assert_eq!(secret.to_bytes(), IDENTITY);

    let identity = UserIdentity::new("u".into(), secret);
    assert_eq!(unwrap_dek_for_member(&identity, &wrapped(FOR_MEMBER)).unwrap().with_key(|k| *k), DEK);
}

#[test]
fn a_backup_made_before_still_restores() {
    let restored = unseal_bundle(&B64.decode(BACKUP).unwrap(), BACKUP_PASSWORD).unwrap();
    assert_eq!(restored.identity.user_uuid, "u");
}

/// Prints the values above. Run it only on the crates the answers came from.
#[test]
#[ignore]
fn print_known_answers() {
    use super::crypto::{encrypt_secret, wrap_dek, wrap_dek_with_key};
    use super::export::seal_bundle;
    use super::sharing::{encrypt_identity_key, wrap_dek_for_member};

    let kek = derive_kek(PASSWORD, &SALT).unwrap();
    println!("KEK {}", kek.with_key(|k| B64.encode(k)));
    println!("WRAPPED_BY_KEK {}", flat(&wrap_dek(&kek, &Dek::new(DEK)).unwrap()));
    println!("WRAPPED_BY_KEY {}", flat(&wrap_dek_with_key(&DEK, &Dek::new(MASTER)).unwrap()));
    let payload = encrypt_secret(&Dek::new(MASTER), SECRET).unwrap();
    println!("PAYLOAD {}", B64.encode(serde_json::to_vec(&payload).unwrap()));
    let identity = x25519_dalek::StaticSecret::from(IDENTITY);
    let (ct, nonce) = kek.with_key(|k| encrypt_identity_key(k, &identity)).unwrap();
    println!("IDENTITY_KEY {} {}", B64.encode(ct), B64.encode(nonce));
    let public = x25519_dalek::PublicKey::from(&identity);
    println!("FOR_MEMBER {}", flat(&wrap_dek_for_member(&Dek::new(DEK), public.as_bytes()).unwrap()));
    println!("BACKUP {}", B64.encode(seal_bundle(&bundle(), BACKUP_PASSWORD).unwrap()));
}
