//! Stage B: the genesis against the r1cs and ptau it claims to come from (`ORBINUM_PTAU`).

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

use orbinum_ceremony_verifier::checks::{verify, Expectations, Source};
use orbinum_ceremony_verifier::formats::{section, Ptau, R1cs, SectionTable};
use support::{binfile, detail, env_input, failed, fixture, sections_of};

const SOURCE: &str = "genesis-source";

fn ptau() -> Option<Vec<u8>> {
    env_input("ORBINUM_PTAU").map(|p| fs::read(p).expect("ORBINUM_PTAU"))
}

fn with_source(r1cs: Vec<u8>, ptau: Vec<u8>, min_contributions: usize) -> Expectations {
    Expectations {
        min_contributions,
        beacon: None,
        source: Some(Source { r1cs, ptau }),
    }
}

fn verify_multiplier(r1cs: Vec<u8>, ptau: Vec<u8>) -> orbinum_ceremony_verifier::report::Verdict {
    verify(
        &fixture("multiplier_0.zkey"),
        &fixture("multiplier_final.zkey"),
        &with_source(r1cs, ptau, 2),
    )
}

/// Offset of the first A term in the multiplier r1cs (file header 12, section 2 header 12, nA 4).
const FIRST_A_SIGNAL: usize = 12 + 12 + 4;
const FIRST_A_COEF: usize = FIRST_A_SIGNAL + 4;

#[test]
fn accepts_the_genesis_snarkjs_derived() {
    let Some(ptau) = ptau() else { return };
    let v = verify_multiplier(fixture("multiplier.r1cs"), ptau);
    assert!(v.ok, "{:?}", failed(&v));
    assert!(v.checks.iter().any(|c| c.id == SOURCE));
}

#[test]
fn rejects_a_circuit_with_another_coefficient() {
    let Some(ptau) = ptau() else { return };
    let mut r1cs = fixture("multiplier.r1cs");
    let mut two = [0u8; 32];
    two[0] = 2;
    r1cs[FIRST_A_COEF..FIRST_A_COEF + 32].copy_from_slice(&two);
    let v = verify_multiplier(r1cs, ptau);
    assert_eq!(failed(&v), [SOURCE]);
    assert!(
        detail(&v, SOURCE).contains("coeffs"),
        "{}",
        detail(&v, SOURCE)
    );
}

#[test]
fn rejects_a_malformed_r1cs() {
    let Some(ptau) = ptau() else { return };
    let mut r1cs = fixture("multiplier.r1cs");
    r1cs[FIRST_A_SIGNAL..FIRST_A_SIGNAL + 4].copy_from_slice(&1000u32.to_le_bytes());
    let v = verify_multiplier(r1cs, ptau);
    assert_eq!(failed(&v), [SOURCE]);
    assert!(detail(&v, SOURCE).contains("signal 1000 out of range"));
}

/// The coordinator's attack: genesis and final altered alike, so every other check still holds.
#[test]
fn rejects_a_genesis_altered_consistently_with_its_final_key() {
    let Some(ptau) = ptau() else { return };
    let swap_a_b1 = |mut key: Vec<u8>| {
        let t = SectionTable::read(&key, b"zkey").unwrap();
        let (a, b1) = (
            t.unique(section::A).unwrap().offset,
            t.unique(section::B1).unwrap().offset,
        );
        let (pa, pb) = (key[a..a + 64].to_vec(), key[b1..b1 + 64].to_vec());
        key[a..a + 64].copy_from_slice(&pb);
        key[b1..b1 + 64].copy_from_slice(&pa);
        key
    };
    let v = verify(
        &swap_a_b1(fixture("multiplier_0.zkey")),
        &swap_a_b1(fixture("multiplier_final.zkey")),
        &with_source(fixture("multiplier.r1cs"), ptau, 2),
    );
    assert_eq!(failed(&v), [SOURCE]);
    let d = detail(&v, SOURCE);
    assert!(
        d.contains("section A") && d.contains("section B1") && d.contains("csHash"),
        "{d}"
    );
}

/// A ptau that is not the pinned one, even where the genesis does not read it.
#[test]
fn rejects_a_ptau_other_than_the_pinned_one() {
    let Some(mut ptau) = ptau() else { return };
    let last = ptau.len() - 1;
    ptau[last] ^= 1;
    let v = verify_multiplier(fixture("multiplier.r1cs"), ptau);
    assert_eq!(failed(&v), [SOURCE]);
    assert!(
        detail(&v, SOURCE).contains("pinned"),
        "{}",
        detail(&v, SOURCE)
    );
}

#[test]
fn rejects_a_ptau_whose_sections_do_not_match_its_power() {
    let Some(mut ptau) = ptau() else { return };
    // Header: magic, version, count, then section 1 (type, size) and n8 ‖ q ‖ power.
    let power_at = 12 + 12 + 4 + 32;
    ptau[power_at..power_at + 4].copy_from_slice(&17u32.to_le_bytes());
    let err = Ptau::parse(&ptau).unwrap_err().to_string();
    assert!(err.contains("section"), "{err}");
}

/// An r1cs that cannot fit the ptau is refused before its constraints are allocated.
#[test]
fn refuses_more_constraints_than_the_ptau_supports_before_reading_them() {
    let mut r1cs = fixture("multiplier.r1cs");
    // Header (section 1, after section 2 in this file): set mConstraints to 2^20.
    let t = SectionTable::read(&r1cs, b"r1cs").unwrap();
    let h = t.unique(1).unwrap();
    r1cs[h.offset + h.size - 4..h.offset + h.size].copy_from_slice(&(1u32 << 20).to_le_bytes());
    let start = Instant::now();
    let err = R1cs::parse(&r1cs, 1 << 16).unwrap_err().to_string();
    assert!(err.contains("constraints"), "{err}");
    assert!(start.elapsed() < Duration::from_millis(100));
}

/// The r1cs header and wire map as circom writes them: one map of 8·nWires bytes, and no more
/// declared inputs than wires.
#[test]
fn rejects_an_r1cs_header_or_wire_map_circom_does_not_write() {
    let honest = fixture("multiplier.r1cs");
    let sections = sections_of(&honest);
    let (h, map) = (
        sections.iter().position(|s| s.0 == 1).unwrap(),
        sections.iter().position(|s| s.0 == 3).unwrap(),
    );
    let without_map: Vec<_> = sections.iter().filter(|s| s.0 != 3).cloned().collect();
    let mut short_map = sections.clone();
    short_map[map].1.truncate(8);
    let mut private_inputs = sections.clone();
    // Header: n8 4, prime 32, nWires 4, nPubOut 4, nPubIn 4, then nPrvIn.
    private_inputs[h].1[48..52].copy_from_slice(&u32::MAX.to_le_bytes());
    for (what, s) in [
        ("no wire map", without_map),
        ("short wire map", short_map),
        ("inputs > wires", private_inputs),
    ] {
        assert!(
            R1cs::parse(&binfile(*b"r1cs", 1, &s), 1 << 16).is_err(),
            "{what}"
        );
    }
    assert!(R1cs::parse(&binfile(*b"r1cs", 1, &sections), 1 << 16).is_ok());
}

/// Real keys from the testnet rehearsal (`ORBINUM_REHEARSAL_DIR`; `make vectors`); transfer's
/// domain is the ptau's
/// full power, so its csHash includes the point snarkjs reads past section 2.
#[test]
fn accepts_real_rehearsal_geneses_when_available() {
    let (Some(ptau), Some(dir)) = (ptau(), env_input("ORBINUM_REHEARSAL_DIR")) else {
        return;
    };
    for circuit in ["shield", "unshield", "transfer"] {
        let read = |p: String| fs::read(p).unwrap();
        let v = verify(
            &read(format!("{dir}/genesis/{circuit}.genesis.zkey")),
            &read(format!("{dir}/final/{circuit}.final.zkey")),
            &with_source(read(format!("{dir}/r1cs/{circuit}.r1cs")), ptau.clone(), 3),
        );
        assert!(v.ok, "{circuit}: {:?}", failed(&v));
    }
}
