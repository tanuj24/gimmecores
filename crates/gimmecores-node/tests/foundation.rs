#![allow(clippy::unwrap_used)] // test helpers outside #[test] fns

use gimmecores_core::PeerKey;
use gimmecores_node::identity::{FileKeyStore, KeyStore};
use gimmecores_node::paths::Paths;
use gimmecores_node::trust::TrustList;

fn temp_home() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("gmc")
        .tempdir_in("/tmp")
        .unwrap()
}

#[cfg(unix)]
fn mode(p: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn identity_is_created_once_and_owner_only() {
    let home = temp_home();
    let paths = Paths::at(home.path());
    paths.ensure().unwrap();
    let store = FileKeyStore::new(paths.identity_key());
    let k1 = store.load_or_create().unwrap();
    let k2 = store.load_or_create().unwrap();
    assert_eq!(k1.public(), k2.public(), "key must persist");
    #[cfg(unix)]
    {
        assert_eq!(mode(&paths.identity_key()), 0o600);
        assert_eq!(mode(paths.root()), 0o700);
    }
}

#[cfg(unix)]
#[test]
fn identity_readable_by_others_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let home = temp_home();
    let paths = Paths::at(home.path());
    paths.ensure().unwrap();
    let store = FileKeyStore::new(paths.identity_key());
    store.load_or_create().unwrap();
    std::fs::set_permissions(paths.identity_key(), std::fs::Permissions::from_mode(0o644)).unwrap();
    let err = store.load_or_create().unwrap_err().to_string();
    assert!(err.contains("accessible by other users"), "{err}");
}

#[test]
fn trust_list_persists_and_flags_name_reuse() {
    let home = temp_home();
    let paths = Paths::at(home.path());
    paths.ensure().unwrap();
    let maya = PeerKey([1; 32]);
    let impostor = PeerKey([2; 32]);
    {
        let mut t = TrustList::load(paths.peers_file()).unwrap();
        t.add(maya, "Maya's MacBook".into(), 100).unwrap();
    }
    let mut t = TrustList::load(paths.peers_file()).unwrap();
    assert!(t.is_paired(&maya));
    assert!(!t.is_paired(&impostor));
    assert_eq!(t.find("Maya's MacBook"), Some(maya));
    assert_eq!(t.find(&maya.fingerprint()), Some(maya));
    assert!(t.name_used_by_other_key("Maya's MacBook", &impostor));
    assert!(!t.name_used_by_other_key("Maya's MacBook", &maya));
    assert!(t.remove(&maya).unwrap());
    assert!(
        !TrustList::load(paths.peers_file())
            .unwrap()
            .is_paired(&maya)
    );
    #[cfg(unix)]
    assert_eq!(mode(&paths.peers_file()), 0o600);
}
