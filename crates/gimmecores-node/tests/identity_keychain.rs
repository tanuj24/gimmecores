//! The device key moves from its file into the macOS login Keychain, once, and never back.
//! Runs only with GMC_TEST_KEYCHAIN=1 (it creates and then deletes a real Keychain item).
#![allow(clippy::unwrap_used)]
#![cfg(target_os = "macos")]

use gimmecores_node::identity::{self, FileKeyStore, IdentityStore, KEYCHAIN_SERVICE, KeyStore};
use gimmecores_node::paths::Paths;

#[test]
fn the_key_moves_into_the_keychain_once_and_never_back() {
    if std::env::var_os("GMC_TEST_KEYCHAIN").is_none() {
        eprintln!("set GMC_TEST_KEYCHAIN=1 to run (uses the real login Keychain)");
        return;
    }
    let home = tempfile::Builder::new()
        .prefix("gmc")
        .tempdir_in("/tmp")
        .unwrap();
    let paths = Paths::at(home.path());
    paths.ensure().unwrap();
    let account = std::fs::canonicalize(home.path())
        .unwrap()
        .to_string_lossy()
        .into_owned();
    struct Cleanup(String);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ =
                security_framework::passwords::delete_generic_password(KEYCHAIN_SERVICE, &self.0);
        }
    }
    let _cleanup = Cleanup(account);

    let before = FileKeyStore::new(paths.identity_key())
        .load_or_create()
        .unwrap()
        .public();
    assert_eq!(identity::current_store(&paths), IdentityStore::File);

    identity::prepare(&paths, IdentityStore::Keychain).unwrap();
    assert_eq!(identity::current_store(&paths), IdentityStore::Keychain);
    assert!(!paths.identity_key().exists(), "the key file is gone");
    assert_eq!(
        identity::load(&paths).unwrap().public(),
        before,
        "same identity"
    );

    let err = identity::prepare(&paths, IdentityStore::File).unwrap_err();
    assert!(format!("{err:#}").contains("never moved out"), "{err:#}");
    assert!(!paths.identity_key().exists(), "no file was written");

    identity::prepare(&paths, IdentityStore::Keychain).unwrap();
    assert_eq!(identity::load(&paths).unwrap().public(), before);
}

#[test]
fn a_marker_without_a_keychain_item_is_an_error_not_a_new_identity() {
    let home = tempfile::Builder::new()
        .prefix("gmc")
        .tempdir_in("/tmp")
        .unwrap();
    let paths = Paths::at(home.path());
    paths.ensure().unwrap();
    std::fs::write(home.path().join("identity.keychain"), KEYCHAIN_SERVICE).unwrap();
    if std::env::var_os("GMC_TEST_KEYCHAIN").is_none() {
        return;
    }
    let err = identity::load(&paths).unwrap_err();
    assert!(format!("{err:#}").contains("missing"), "{err:#}");
    assert!(!paths.identity_key().exists(), "no new key file");
}
