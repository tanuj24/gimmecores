//! Stable-toolchain smoke fuzzing: every decoder that reads bytes another device controls gets
//! valid inputs, mutations of them and random bytes, and must not panic (the deeper,
//! coverage-guided runs are in `fuzz/`, on nightly). Deterministic: a failure repeats.
#![allow(clippy::unwrap_used)]

use gimmecores_node::fuzzing;
use gimmecores_proto::peer::v1 as pb;
use prost::Message;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn frame(msg: &pb::PeerMessage) -> Vec<u8> {
    let body = msg.encode_to_vec();
    let mut v = (body.len() as u32).to_be_bytes().to_vec();
    v.extend(body);
    v
}

fn seeds() -> Vec<Vec<u8>> {
    let hello = pb::PeerMessage {
        body: Some(pb::peer_message::Body::Hello(pb::Hello {
            device_name: "Laptop\u{202E}".into(),
            ..Default::default()
        })),
    };
    let submit = pb::PeerMessage {
        body: Some(pb::peer_message::Body::SubmitTask(pb::SubmitTask {
            task_id: vec![1; 16],
            grant_id: vec![2; 16],
            output_paths: vec!["out".into(), "../x".into()],
            ..Default::default()
        })),
    };
    let dir = pb::Directory {
        files: vec![pb::FileNode {
            name: "a.txt".into(),
            digest: Some(pb::Digest {
                hash: vec![3; 32],
                size_bytes: 10,
                function: pb::DigestFunction::Sha256 as i32,
            }),
            executable: false,
        }],
        directories: vec![pb::DirectoryNode {
            name: "out".into(),
            digest: Some(pb::Digest {
                hash: vec![4; 32],
                size_bytes: 77,
                function: pb::DigestFunction::Sha256 as i32,
            }),
        }],
    };
    let grant = pb::SignedGrant {
        grant: pb::Grant {
            lender_key: vec![7; 32],
            borrower_key: vec![9; 32],
            ..Default::default()
        }
        .encode_to_vec(),
        signature: vec![0; 64],
    };
    let (_, _, real_grant) = fuzzing::signed_grant_seed();
    let mut frames = frame(&hello);
    frames.extend(frame(&submit));
    vec![
        frames,
        dir.encode_to_vec(),
        grant.encode_to_vec(),
        real_grant.encode_to_vec(),
        b"pkg/__init__.py,sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,12\n\"a,\"\"b\",sha256=x,\n"
            .to_vec(),
        format!("gmc1:{}@127.0.0.1:4433,[::1]:1", "ab".repeat(32)).into_bytes(),
        format!("abcd\n{}\nLaptop\u{200B}\n", "ab".repeat(32)).into_bytes(),
        "-----BEGIN PRIVATE KEY----- AKIA https://u:p@x\u{202E}".as_bytes().to_vec(),
    ]
}

fn mutate(rng: &mut Rng, seed: &[u8], other: &[u8]) -> Vec<u8> {
    let mut v = seed.to_vec();
    for _ in 0..1 + rng.below(4) {
        match rng.below(6) {
            0 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] ^= 1 << rng.below(8);
            }
            1 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] = [0, 0xff, 0x7f, 0x80, b'/', b'.'][rng.below(6)];
            }
            2 => v.truncate(rng.below(v.len() + 1)),
            3 => {
                let i = rng.below(v.len() + 1);
                let n = rng.below(16);
                let bytes: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
                v.splice(i..i, bytes);
            }
            4 if !other.is_empty() => {
                let i = rng.below(v.len() + 1);
                let j = rng.below(other.len());
                v.splice(i..i, other[j..].iter().copied().take(64));
            }
            _ => {
                // A length prefix claiming a huge frame.
                v.splice(0..0, u32::MAX.to_be_bytes());
            }
        }
    }
    v
}

#[test]
fn decoders_survive_random_and_mutated_input() {
    let seeds = seeds();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for (name, f) in fuzzing::ALL {
        for s in &seeds {
            f(s);
        }
        for i in 0..4000 {
            let input = if i % 4 == 0 {
                let n = rng.below(256);
                (0..n).map(|_| rng.next() as u8).collect()
            } else {
                let a = &seeds[rng.below(seeds.len())];
                let b = &seeds[rng.below(seeds.len())];
                mutate(&mut rng, a, b)
            };
            let r = std::panic::catch_unwind(|| f(&input));
            assert!(r.is_ok(), "{name} panicked on {input:?}");
        }
    }
}

#[test]
fn the_grant_target_is_not_vacuous() {
    let (lender, me, real) = fuzzing::signed_grant_seed();
    let key = gimmecores_core::PeerKey(*lender.public().as_bytes());
    assert!(gimmecores_node::grants_flow::verify_signed(&real, &key, &me).is_ok());
    let mut changed = real.clone();
    let last = changed.grant.len() - 1;
    changed.grant[last] ^= 1;
    assert!(gimmecores_node::grants_flow::verify_signed(&changed, &key, &me).is_err());
}

/// Writes the seed inputs into fuzz/corpus/<target>/ (cargo-fuzz starts from them; a signed
/// grant cannot be found by mutation alone). Run before fuzzing:
/// `cargo test -p gimmecores-node --test fuzz_smoke write_fuzz_seeds -- --ignored`
#[test]
#[ignore]
fn write_fuzz_seeds() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus");
    for (name, _) in fuzzing::ALL {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        for (i, s) in seeds().iter().enumerate() {
            std::fs::write(dir.join(format!("seed-{i}")), s).unwrap();
        }
    }
}
