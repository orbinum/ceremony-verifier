//! Oracle tests: snarkjs-produced fixtures only verify if the reproduction is bit-exact.

// Tests and their helpers fail by panicking; fixture sizes always fit u32.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

#[path = "../support/mod.rs"]
mod support;

use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use orbinum_ceremony_verifier::compat::{
    beacon_key, contribution_hash, expected_transcript, hash_to_g2,
};
use orbinum_ceremony_verifier::formats::{EntryKind, Zkey};
use support::fixture;

/// `h_k` by index from `verify.log` (the `snarkjs zkey verify` output for the fixtures).
fn snarkjs_hashes() -> Vec<(usize, String)> {
    let log = String::from_utf8(fixture("verify.log")).unwrap();
    let lines: Vec<&str> = log.lines().collect();
    lines
        .iter()
        .enumerate()
        .filter_map(|(i, l)| {
            let n = l
                .split("contribution #")
                .nth(1)?
                .split_whitespace()
                .next()?
                .parse()
                .ok()?;
            let hex: String = lines[i + 1..i + 5].concat().split_whitespace().collect();
            Some((n, hex))
        })
        .collect()
}

fn same_ratio(a1: G1Affine, b1: G1Affine, a2: G2Affine, b2: G2Affine) -> bool {
    Bn254::pairing(a1, b2) == Bn254::pairing(b1, a2)
}

#[test]
fn hash_to_g2_reproduces_snarkjs_so_every_proof_of_knowledge_verifies() {
    let bytes = fixture("multiplier_final.zkey");
    let zkey = Zkey::parse(&bytes).unwrap();
    assert_eq!(zkey.entries.len(), 3);
    for e in &zkey.entries {
        let g2_sp = hash_to_g2(&e.transcript);
        assert!(!g2_sp.is_zero());
        assert!(
            same_ratio(e.g1_s, e.g1_sx, g2_sp, e.g2_spx),
            "PoK does not verify"
        );
    }
}

#[test]
fn transcripts_and_contribution_hashes_match_snarkjs() {
    let bytes = fixture("multiplier_final.zkey");
    let zkey = Zkey::parse(&bytes).unwrap();
    for (i, e) in zkey.entries.iter().enumerate() {
        assert_eq!(
            expected_transcript(&zkey.cs_hash, &zkey.entries[..i], e),
            e.transcript
        );
    }
    let ours: Vec<String> = zkey
        .entries
        .iter()
        .map(|e| orbinum_ceremony_verifier::report::hex(&contribution_hash(e)))
        .collect();
    for (n, theirs) in snarkjs_hashes() {
        assert_eq!(ours[n - 1], theirs, "h_{n}");
    }
}

#[test]
fn beacon_key_is_rederived_from_its_public_parameters() {
    let bytes = fixture("multiplier_final.zkey");
    let zkey = Zkey::parse(&bytes).unwrap();
    let beacon = zkey.entries.last().unwrap();
    assert_eq!(beacon.kind, EntryKind::Beacon);
    let (g1_s, g1_sx) = beacon_key(
        beacon.beacon_hash.as_ref().unwrap(),
        beacon.num_iterations_exp.unwrap(),
    )
    .unwrap();
    assert_eq!((g1_s, g1_sx), (beacon.g1_s, beacon.g1_sx));
}
