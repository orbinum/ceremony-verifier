//! The verifier against honest keys and crafted attacks (byte-level, on snarkjs fixtures).

// Tests and their helpers fail by panicking; fixture sizes always fit u32.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

#[path = "../support/mod.rs"]
mod support;

use std::fs;
use std::time::{Duration, Instant};

use ark_bn254::{g2, Fq, Fq2, Fr, G2Affine};
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ff::{Field, PrimeField, UniformRand};
use orbinum_ceremony_verifier::checks::{verify, Expectations};
use orbinum_ceremony_verifier::formats::{section, Zkey};
use rand::rngs::OsRng;
use support::*;

fn verify_final(key: &[u8]) -> orbinum_ceremony_verifier::report::Verdict {
    verify(&fixture("multiplier_0.zkey"), key, &announced())
}

#[test]
fn accepts_the_honest_final_key_and_reports_snarkjs_h_k() {
    let v = verify_final(&fixture("multiplier_final.zkey"));
    assert!(v.ok, "{:?}", failed(&v));
    assert_eq!(v.entries.len(), 3);
    assert_eq!(v.entries[2].kind, "beacon");
    let ids: Vec<&str> = v.checks.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "well-formed",
            "genesis-start",
            "unchanged",
            "policy",
            "chain",
            "final-delta",
            "scaled-sections"
        ]
    );
}

#[test]
fn rejects_a_key_with_zero_contributions_even_though_snarkjs_accepts_it() {
    let v = verify_final(&fixture("multiplier_beacon_only.zkey"));
    assert_eq!(failed(&v), ["policy"]);
}

#[test]
fn rejects_a_beacon_other_than_the_announced_one() {
    let other = Expectations {
        beacon: Some((vec![9; 32], 10)),
        ..announced()
    };
    let v = verify(
        &fixture("multiplier_0.zkey"),
        &fixture("multiplier_final.zkey"),
        &other,
    );
    assert_eq!(failed(&v), ["policy"]);
}

#[test]
fn rejects_an_l_point_replaced_by_another_valid_point() {
    let mut key = fixture("multiplier_final.zkey");
    let (l, h) = (offset(&key, section::L), offset(&key, section::H));
    let valid_other: Vec<u8> = key[h..h + 64].to_vec();
    key[l..l + 64].copy_from_slice(&valid_other);
    assert_eq!(failed(&verify_final(&key)), ["scaled-sections"]);
}

#[test]
fn rejects_a_forged_proof_of_knowledge() {
    // Replace entry 1's g2_spx by β2 (a valid G2 point): the PoK and the δ update break.
    let mut key = fixture("multiplier_final.zkey");
    let hdr = offset(&key, section::GROTH16);
    let beta2_at = hdr + 4 + 32 + 4 + 32 + 12 + 64 + 64;
    let beta2: Vec<u8> = key[beta2_at..beta2_at + 128].to_vec();
    let g2_spx_at = entry_offset(&key, 0) + 3 * 64;
    key[g2_spx_at..g2_spx_at + 128].copy_from_slice(&beta2);
    let v = verify_final(&key);
    assert!(failed(&v).contains(&"chain"));
    assert!(
        detail(&v, "final-delta").contains("chain is broken"),
        "{:?}",
        v.checks
    );
}

#[test]
fn rejects_a_non_canonical_field_element() {
    // α1.x replaced by q itself: the same residue as 0, written out of range.
    let mut key = fixture("multiplier_final.zkey");
    let at = offset(&key, section::GROTH16) + 4 + 32 + 4 + 32 + 12;
    let mut q = [0u8; 32];
    for (i, limb) in Fq::MODULUS.0.iter().enumerate() {
        q[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    key[at..at + 32].copy_from_slice(&q);
    assert_malformed(&verify_final(&key));
}

#[test]
fn rejects_a_g2_point_on_the_curve_but_outside_the_subgroup() {
    let p = loop {
        let x = Fq2::rand(&mut OsRng);
        if let Some(y) = (x.square() * x + g2::Config::COEFF_B).sqrt() {
            let p = G2Affine::new_unchecked(x, y);
            if !p.is_in_correct_subgroup_assuming_on_curve() {
                break p;
            }
        }
    };
    let mut key = fixture("multiplier_final.zkey");
    let delta2_at =
        offset(&key, section::GROTH16) + 4 + 32 + 4 + 32 + 12 + 64 + 64 + 128 + 128 + 64;
    key[delta2_at..delta2_at + 128].copy_from_slice(&g2_lem(&p));
    let v = verify_final(&key);
    assert_malformed(&v);
    assert!(detail(&v, "well-formed").contains("subgroup"));
}

#[test]
fn rejects_changes_to_the_delta_free_sections() {
    // Swap the first A point with the first B1 point: both valid, the circuit is different.
    let mut key = fixture("multiplier_final.zkey");
    let (a, b1) = (offset(&key, section::A), offset(&key, section::B1));
    let (pa, pb): (Vec<u8>, Vec<u8>) = (key[a..a + 64].to_vec(), key[b1..b1 + 64].to_vec());
    key[a..a + 64].copy_from_slice(&pb);
    key[b1..b1 + 64].copy_from_slice(&pa);
    assert!(failed(&verify_final(&key)).contains(&"unchanged"));
}

#[test]
fn rejects_a_genesis_that_is_not_a_genesis() {
    let v = verify(
        &fixture("multiplier_1.zkey"),
        &fixture("multiplier_final.zkey"),
        &announced(),
    );
    assert!(failed(&v).contains(&"genesis-start"));
}

#[test]
fn rejects_trailing_bytes_and_section_bombs() {
    let mut padded = fixture("multiplier_final.zkey");
    padded.extend_from_slice(&[0, 0]);
    assert_malformed(&verify_final(&padded));

    let mut bomb = b"zkey".to_vec();
    bomb.extend_from_slice(&1u32.to_le_bytes());
    bomb.extend_from_slice(&100_000u32.to_le_bytes());
    bomb.resize(12 + 100_000 * 12, 0);
    assert_malformed(&verify_final(&bomb));
}

/// A contribution with secret 1: valid proof of knowledge, δ unchanged, counted all the same.
#[test]
fn rejects_a_no_op_contribution() {
    let key = fixture("multiplier_final.zkey");
    let zkey = Zkey::parse(&key).unwrap();
    let noop = contribution(
        &zkey.cs_hash,
        &zkey.entries[..2],
        &zkey.entries[1],
        Fr::from(1u64),
    );
    let forged = with_entries(
        &key,
        &[
            entry_bytes(&key, 0),
            entry_bytes(&key, 1),
            encode_entry(&noop),
        ],
    );
    let v = verify_final(&forged);
    assert!(detail(&v, "chain").contains("no-op"), "{:?}", v.checks);
}

/// x then 1/x: each entry changes δ, but the second brings it back to the genesis δ, so the
/// beacon alone would decide the final δ.
#[test]
fn rejects_a_delta_that_returns_to_an_earlier_value() {
    let key = fixture("multiplier_final.zkey");
    let zkey = Zkey::parse(&key).unwrap();
    let x = Fr::rand(&mut OsRng);
    let first = contribution(&zkey.cs_hash, &[], &zkey.entries[0], x);
    let back = contribution(
        &zkey.cs_hash,
        std::slice::from_ref(&first),
        &zkey.entries[1],
        x.inverse().unwrap(),
    );
    let forged = with_entries(&key, &[encode_entry(&first), encode_entry(&back)]);
    let v = verify_final(&forged);
    assert!(detail(&v, "chain").contains("repeats"), "{:?}", v.checks);
}

#[test]
fn rejects_a_container_other_than_the_one_snarkjs_writes() {
    let honest = fixture("multiplier_final.zkey");
    let sections = sections_of(&honest);

    let other_version = binfile(*b"zkey", 2, &sections);
    let mut padded_header = sections.clone();
    padded_header[0].1.extend_from_slice(&[0; 4]);
    let mut reordered = sections.clone();
    reordered.swap(2, 3);
    for (what, key) in [
        ("version", other_version),
        ("section 1 size", binfile(*b"zkey", 1, &padded_header)),
        ("section order", binfile(*b"zkey", 1, &reordered)),
    ] {
        eprintln!("{what}");
        assert_malformed(&verify_final(&key));
    }
    assert!(verify_final(&binfile(*b"zkey", 1, &sections)).ok);
}

/// A key that does not parse still gets every check id, so the caller sees the real cause.
#[test]
fn reports_every_check_when_a_key_does_not_parse() {
    let honest = fixture("multiplier_final.zkey");
    let v = verify_final(&honest[..1000]);
    assert_eq!(v.checks.len(), 7);
    assert!(detail(&v, "well-formed").contains("final"));
    assert!(detail(&v, "chain").contains("not run"));
}

#[test]
fn rejects_a_genesis_whose_gamma_is_not_the_generator() {
    let mut genesis = fixture("multiplier_0.zkey");
    let hdr = offset(&genesis, section::GROTH16) + 4 + 32 + 4 + 32 + 12;
    let (beta2, gamma2) = (hdr + 128, hdr + 256);
    let b: Vec<u8> = genesis[beta2..beta2 + 128].to_vec();
    genesis[gamma2..gamma2 + 128].copy_from_slice(&b);
    let v = verify(&genesis, &fixture("multiplier_final.zkey"), &announced());
    assert!(detail(&v, "genesis-start").contains("γ"), "{:?}", v.checks);
}

/// An expensive beacon (2^24 hashes) that is not last must not be derived.
#[test]
fn does_not_derive_a_beacon_that_is_not_the_last_entry() {
    let key = fixture("multiplier_final.zkey");
    let mut beacon = entry_bytes(&key, 2);
    // params: tag 2 (iterations) is right after the name parameter, if any; set it to 24.
    let at = beacon.windows(2).rposition(|w| w == [2, 10]).unwrap();
    beacon[at + 1] = 24;
    let forged = with_entries(&key, &[beacon, entry_bytes(&key, 0), entry_bytes(&key, 1)]);
    let start = Instant::now();
    let v = verify_final(&forged);
    assert!(!v.ok);
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );
}

#[test]
fn rejects_more_entries_than_the_cap_before_walking_them() {
    let key = fixture("multiplier_final.zkey");
    let entry = entry_bytes(&key, 0);
    let forged = with_entries(&key, &vec![entry; 10_001]);
    let start = Instant::now();
    let v = verify_final(&forged);
    assert_malformed(&v);
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );
}

/// Thousands of junk entries under the cap: the walk stops at the first broken link.
#[test]
fn stops_the_chain_walk_at_the_first_broken_entry() {
    let key = fixture("multiplier_final.zkey");
    let entry = entry_bytes(&key, 0);
    let forged = with_entries(&key, &vec![entry; 1_000]);
    let start = Instant::now();
    let v = verify_final(&forged);
    assert!(failed(&v).contains(&"chain"));
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "{:?}",
        start.elapsed()
    );
}

/// Parameter layouts snarkjs never writes: they would be other encodings of the same key.
#[test]
fn rejects_mpc_parameters_snarkjs_does_not_write() {
    let key = fixture("multiplier_final.zkey");
    let (alice, beacon) = (entry_bytes(&key, 0), entry_bytes(&key, 2));
    let alice_name = params_of(&alice).to_vec();
    let beacon_params = params_of(&beacon);
    let without_hash = &beacon_params[..beacon_params.len() - 2 - 31];
    let cases = [
        (
            "contribution with beacon params",
            0,
            with_params(
                &alice,
                &[alice_name.clone(), vec![2, 10, 3, 1, 0xaa]].concat(),
            ),
        ),
        ("empty name", 0, with_params(&alice, &[1, 0])),
        (
            "beacon without its hash",
            2,
            with_params(&beacon, without_hash),
        ),
    ];
    for (what, at, entry) in cases {
        let mut entries: Vec<Vec<u8>> = (0..3).map(|i| entry_bytes(&key, i)).collect();
        entries[at] = entry;
        eprintln!("{what}");
        assert_malformed(&verify_final(&with_entries(&key, &entries)));
    }
}

#[test]
fn rejects_a_contributor_name_with_control_characters() {
    let mut key = fixture("multiplier_final.zkey");
    let params = entry_offset(&key, 0) + 392;
    assert_eq!(key[params], 1, "entry 1 has a name");
    key[params + 2] = 0x1b;
    assert_malformed(&verify_final(&key));
}

/// Real keys from the testnet rehearsal (`ORBINUM_REHEARSAL_DIR`; `make vectors`).
#[test]
fn accepts_real_rehearsal_keys_when_available() {
    let Some(dir) = env_input("ORBINUM_REHEARSAL_DIR") else {
        return;
    };
    for circuit in ["shield", "unshield", "transfer"] {
        let genesis = fs::read(format!("{dir}/genesis/{circuit}.genesis.zkey")).unwrap();
        let final_ = fs::read(format!("{dir}/final/{circuit}.final.zkey")).unwrap();
        let start = Instant::now();
        let v = verify(
            &genesis,
            &final_,
            &Expectations {
                min_contributions: 3,
                beacon: None,
                source: None,
            },
        );
        assert!(v.ok, "{circuit}: {:?}", failed(&v));
        eprintln!("{circuit}: ok in {:?}", start.elapsed());
    }
}
