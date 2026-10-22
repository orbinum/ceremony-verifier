//! Shared helpers for the integration tests: fixtures, verdict queries and zkey surgery.
// Each test crate uses a subset; helpers fail by panicking, like the tests themselves.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::fs;
use std::path::PathBuf;

use ark_bn254::{Fq, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use orbinum_ceremony_verifier::checks::Expectations;
use orbinum_ceremony_verifier::formats::{section, SectionTable};
use orbinum_ceremony_verifier::report::Verdict;

/// The beacon the fixtures were finalized with (`generate.sh`), 2^10 iterations.
/// An input from the environment: `None` skips the test, unless `ORBINUM_REQUIRE_INPUTS` is set
/// (`make test-full`), where a missing input fails it instead of passing silently.
pub fn env_input(name: &str) -> Option<String> {
    let value = std::env::var(name).ok();
    let required = std::env::var_os("ORBINUM_REQUIRE_INPUTS").is_some();
    assert!(
        value.is_some() || !required,
        "{name} is required (ORBINUM_REQUIRE_INPUTS is set)"
    );
    value
}

pub const BEACON: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

pub fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

pub fn fixture(name: &str) -> Vec<u8> {
    fs::read(fixture_path(name)).expect("fixture")
}

pub fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// What the fixtures' ceremony announced: 2 contributions and `BEACON`.
pub fn announced() -> Expectations {
    Expectations {
        min_contributions: 2,
        beacon: Some((hex(BEACON), 10)),
        source: None,
    }
}

/// Ids of the failed checks.
pub fn failed(v: &Verdict) -> Vec<&str> {
    v.checks
        .iter()
        .filter(|c| !c.ok)
        .map(|c| c.id.as_str())
        .collect()
}

pub fn detail<'a>(v: &'a Verdict, id: &str) -> &'a str {
    v.checks
        .iter()
        .find(|c| c.id == id)
        .and_then(|c| c.detail.as_deref())
        .unwrap_or("")
}

/// Offset of a section's data in a zkey.
pub fn offset(zkey: &[u8], id: u32) -> usize {
    SectionTable::read(zkey, b"zkey")
        .unwrap()
        .unique(id)
        .unwrap()
        .offset
}

/// Montgomery little-endian bytes, as snarkjs stores field elements.
pub fn lem(x: Fq) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, limb) in x.0 .0.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    out
}

pub fn g1_lem(p: &G1Affine) -> Vec<u8> {
    let (x, y) = p.xy().unwrap();
    [lem(x), lem(y)].concat()
}

pub fn g2_lem(p: &G2Affine) -> Vec<u8> {
    let (x, y) = p.xy().unwrap();
    [lem(x.c0), lem(x.c1), lem(y.c0), lem(y.c1)].concat()
}

/// Offset of entry `i`'s first byte in the MPC section (entries before it have the given name
/// lengths: 384 B of points and transcript, type, params length, then the params).
pub fn entry_offset(zkey: &[u8], i: usize) -> usize {
    let mut at = offset(zkey, section::MPC) + 64 + 4;
    for _ in 0..i {
        let params = u32::from_le_bytes(zkey[at + 388..at + 392].try_into().unwrap()) as usize;
        at += 392 + params;
    }
    at
}

/// The raw bytes of entry `i`.
pub fn entry_bytes(zkey: &[u8], i: usize) -> Vec<u8> {
    let (start, end) = (entry_offset(zkey, i), entry_offset(zkey, i + 1));
    zkey[start..end].to_vec()
}

/// The same zkey with section 10 (the last one) replaced by csHash ‖ count ‖ `entries`.
pub fn with_entries(zkey: &[u8], entries: &[Vec<u8>]) -> Vec<u8> {
    let mpc = offset(zkey, section::MPC);
    let cs_hash = zkey[mpc..mpc + 64].to_vec();
    let mut data = cs_hash;
    data.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        data.extend_from_slice(e);
    }
    let mut out = zkey[..mpc - 8].to_vec();
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(&data);
    out
}

/// The sections of a binfile, in file order, as (type, data).
pub fn sections_of(bytes: &[u8]) -> Vec<(u32, Vec<u8>)> {
    let count = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let mut at = 12;
    (0..count)
        .map(|_| {
            let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
            let size = u64::from_le_bytes(bytes[at + 4..at + 12].try_into().unwrap()) as usize;
            at += 12 + size;
            (kind, bytes[at - size..at].to_vec())
        })
        .collect()
}

/// A binfile with the given magic and version holding `sections` in that order.
pub fn binfile(magic: [u8; 4], version: u32, sections: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut out = magic.to_vec();
    out.extend_from_slice(&version.to_le_bytes());
    out.extend_from_slice(&(sections.len() as u32).to_le_bytes());
    for (kind, data) in sections {
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&(data.len() as u64).to_le_bytes());
        out.extend_from_slice(data);
    }
    out
}

/// One MPC entry as snarkjs writes it (contribution type, optional name).
pub fn encode_entry(e: &orbinum_ceremony_verifier::formats::MpcEntry) -> Vec<u8> {
    let mut out = [
        g1_lem(&e.delta_after),
        g1_lem(&e.g1_s),
        g1_lem(&e.g1_sx),
        g2_lem(&e.g2_spx),
        e.transcript.to_vec(),
    ]
    .concat();
    out.extend_from_slice(&0u32.to_le_bytes());
    let params: Vec<u8> = match &e.name {
        Some(n) => [vec![1, n.len() as u8], n.as_bytes().to_vec()].concat(),
        None => vec![],
    };
    out.extend_from_slice(&(params.len() as u32).to_le_bytes());
    out.extend_from_slice(&params);
    out
}

/// A valid contribution with secret `x` on top of `previous` (its proof of knowledge and δ
/// update verify).
pub fn contribution(
    cs_hash: &[u8; 64],
    previous: &[orbinum_ceremony_verifier::formats::MpcEntry],
    template: &orbinum_ceremony_verifier::formats::MpcEntry,
    x: ark_bn254::Fr,
) -> orbinum_ceremony_verifier::formats::MpcEntry {
    use ark_ec::CurveGroup;
    use ark_ff::UniformRand;
    use orbinum_ceremony_verifier::compat::{expected_transcript, hash_to_g2};
    let delta = previous
        .last()
        .map_or(G1Affine::generator(), |p| p.delta_after);
    let s = ark_bn254::Fr::rand(&mut rand::rngs::OsRng);
    let mut e = template.clone();
    e.g1_s = (G1Affine::generator() * s).into_affine();
    e.g1_sx = (G1Affine::generator() * (s * x)).into_affine();
    e.delta_after = (delta * x).into_affine();
    e.transcript = expected_transcript(cs_hash, previous, &e);
    e.g2_spx = (hash_to_g2(&e.transcript) * x).into_affine();
    e
}

/// Rejected as malformed: `well-formed` fails and every other failure is "not run".
pub fn assert_malformed(v: &Verdict) {
    assert!(!v.ok);
    assert!(failed(v).contains(&"well-formed"), "{:?}", v.checks);
    for c in v.checks.iter().filter(|c| !c.ok && c.id != "well-formed") {
        let d = c.detail.as_deref().unwrap_or("");
        assert!(d.starts_with("not run"), "{}: {d}", c.id);
    }
}

/// An encoded entry with its parameters replaced.
pub fn with_params(entry: &[u8], params: &[u8]) -> Vec<u8> {
    let mut out = entry[..388].to_vec();
    out.extend_from_slice(&(params.len() as u32).to_le_bytes());
    out.extend_from_slice(params);
    out
}

/// The parameters of an encoded entry.
pub fn params_of(entry: &[u8]) -> &[u8] {
    &entry[392..]
}
