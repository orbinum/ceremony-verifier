//! Seeded mutations of the real rehearsal keys (`ORBINUM_REHEARSAL_DIR`). For every
//! mutation the verifier must not panic, must report the full set of check ids, must finish
//! within a time bound, and must not accept a changed final key unless the change lies inside a
//! contributor name (KL-7). Crafted but cryptographically valid chains (cancelled contributions,
//! a misplaced beacon) are checked the same way, with one positive control that must pass.

// Tests and their helpers fail by panicking; key sizes always fit u32.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::too_many_lines
)]

#[path = "../support/mod.rs"]
mod support;

use std::fs;
use std::ops::Range;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::{Duration, Instant};

use ark_bn254::{Fr, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, UniformRand};
use orbinum_ceremony_verifier::checks::{verify, Expectations};
use orbinum_ceremony_verifier::compat::{
    expected_transcript, fr_from_rng, g1_from_rng, hash_to_g2, ChaCha,
};
use orbinum_ceremony_verifier::formats::{
    g1_from_lem, section, EntryKind, MpcEntry, SectionTable, Zkey, G1_BYTES,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use sha2::{Digest, Sha256};
use support::{entry_bytes, entry_offset, env_input, g1_lem, g2_lem, params_of, with_entries};

const IDS: [&str; 7] = [
    "well-formed",
    "genesis-start",
    "unchanged",
    "policy",
    "chain",
    "final-delta",
    "scaled-sections",
];

struct Circuit {
    name: &'static str,
    genesis: Vec<u8>,
    final_: Vec<u8>,
    expect: Expectations,
    names: Vec<Range<usize>>,
    bound: Duration,
}

fn load(dir: &str, name: &'static str, bound: Duration) -> Circuit {
    let genesis = fs::read(format!("{dir}/genesis/{name}.genesis.zkey")).unwrap();
    let final_ = fs::read(format!("{dir}/final/{name}.final.zkey")).unwrap();
    let parsed = Zkey::parse(&final_).unwrap();
    let last = parsed.entries.last().unwrap();
    let contributions = parsed
        .entries
        .iter()
        .filter(|e| e.kind == EntryKind::Contribution)
        .count();
    let expect = Expectations {
        min_contributions: contributions,
        beacon: Some((
            last.beacon_hash.clone().unwrap(),
            last.num_iterations_exp.unwrap(),
        )),
        source: None,
    };
    let names = (0..parsed.entries.len())
        .filter_map(|i| {
            let params = entry_offset(&final_, i) + 392;
            (final_.get(params) == Some(&1))
                .then(|| params + 2..params + 2 + final_[params + 1] as usize)
        })
        .collect();
    Circuit {
        name,
        genesis,
        final_,
        expect,
        names,
        bound,
    }
}

/// Runs one verification; `Err` describes a violated invariant.
fn check(c: &Circuit, final_: &[u8], may_pass: bool, what: &str) -> Result<(), String> {
    let start = Instant::now();
    let v = catch_unwind(AssertUnwindSafe(|| verify(&c.genesis, final_, &c.expect)))
        .map_err(|_| format!("{}: {what}: PANIC", c.name))?;
    let elapsed = start.elapsed();
    let ids: Vec<&str> = v.checks.iter().map(|k| k.id.as_str()).collect();
    if ids != IDS {
        return Err(format!("{}: {what}: check ids {ids:?}", c.name));
    }
    if v.ok != v.checks.iter().all(|k| k.ok) {
        return Err(format!("{}: {what}: ok disagrees with the checks", c.name));
    }
    if v.ok && !may_pass {
        return Err(format!("{}: {what}: ACCEPTED", c.name));
    }
    if elapsed > c.bound {
        return Err(format!("{}: {what}: took {elapsed:?}", c.name));
    }
    Ok(())
}

/// One mutation of the honest final key, materialised only when it runs (keys are up to 17 MB).
enum Mut {
    Flip(usize, u32),
    Patch(usize, Vec<u8>),
    Truncate(usize),
    Append(usize),
    Whole(Vec<u8>),
}

impl Mut {
    fn apply(&self, honest: &[u8]) -> Vec<u8> {
        match self {
            Mut::Flip(at, bit) => {
                let mut k = honest.to_vec();
                k[*at] ^= 1 << bit;
                k
            }
            Mut::Patch(at, v) => {
                let mut k = honest.to_vec();
                k[*at..*at + v.len()].copy_from_slice(v);
                k
            }
            Mut::Truncate(cut) => honest[..*cut].to_vec(),
            Mut::Append(n) => [honest, &vec![0u8; *n]].concat(),
            Mut::Whole(k) => k.clone(),
        }
    }
}

type Job = (String, Mut, bool);

/// Runs `jobs` on 8 threads; returns every violation.
fn run_all(c: &Circuit, jobs: &[Job]) -> Vec<String> {
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..8)
            .map(|w| {
                scope.spawn(move || {
                    (w..jobs.len())
                        .step_by(8)
                        .filter_map(|i| {
                            let (what, m, may_pass) = &jobs[i];
                            check(c, &m.apply(&c.final_), *may_pass, what).err()
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        workers
            .into_iter()
            .flat_map(|w| w.join().unwrap())
            .collect()
    })
}

/// File header and every section header: (offset of the 12-byte header, data offset, size).
fn section_headers(key: &[u8]) -> Vec<(usize, usize, usize)> {
    let count = u32::from_le_bytes(key[8..12].try_into().unwrap());
    let mut at = 12;
    (0..count)
        .map(|_| {
            let size = u64::from_le_bytes(key[at + 4..at + 12].try_into().unwrap()) as usize;
            let h = (at, at + 12, size);
            at += 12 + size;
            h
        })
        .collect()
}

/// Byte-level mutations: truncations, bit flips in every header byte, in every byte of
/// sections 1, 2 and 10, and in a seeded sample of the bulk sections; inflated sizes and counts.
fn byte_mutations(c: &Circuit, rng: &mut StdRng, body_samples: usize, mpc_all: bool) -> Vec<Job> {
    let honest = &c.final_;
    let in_name = |at: usize| c.names.iter().any(|r| r.contains(&at));
    let mut jobs = Vec::new();
    let headers = section_headers(honest);
    let flip = |at: usize, bit: u32| {
        (
            format!("flip byte {at} bit {bit}"),
            Mut::Flip(at, bit),
            in_name(at),
        )
    };

    // Truncations: at and around every section boundary, plus seeded random cuts.
    let mut cuts: Vec<usize> = vec![0, 1, 4, 8, 11, 12, honest.len() - 1];
    for &(h, data, size) in &headers {
        for d in [0, 1, 4, 11, 12] {
            cuts.push(h + d);
        }
        cuts.extend([data + size - 1, data + size / 2]);
    }
    cuts.extend((0..64).map(|_| rng.gen_range(0..honest.len())));
    for cut in cuts {
        jobs.push((format!("truncate at {cut}"), Mut::Truncate(cut), false));
    }
    // Appended bytes.
    for extra in [1usize, 12, 64] {
        jobs.push((
            format!("append {extra} zero bytes"),
            Mut::Append(extra),
            false,
        ));
    }

    // Every bit of the file header and of every section header.
    for at in 0..12 {
        for bit in 0..8 {
            jobs.push(flip(at, bit));
        }
    }
    for &(h, _, _) in &headers {
        for at in h..h + 12 {
            for bit in 0..8 {
                jobs.push(flip(at, bit));
            }
        }
    }
    // Every byte (rotating bit) of sections 1 and 2, and of 10 when asked (else a sample).
    for &(h, data, size) in &headers {
        let kind = u32::from_le_bytes(honest[h..h + 4].try_into().unwrap());
        let all = kind == section::HEADER
            || kind == section::GROTH16
            || (kind == section::MPC && mpc_all);
        let positions: Vec<usize> = if all {
            (data..data + size).collect()
        } else {
            let n = if kind == section::MPC {
                256
            } else {
                body_samples
            };
            (0..n).map(|_| rng.gen_range(data..data + size)).collect()
        };
        for at in positions {
            jobs.push(flip(at, (at % 8) as u32));
        }
    }

    // Inflated / deflated section sizes.
    for &(h, _, size) in &headers {
        let size = size as u64;
        for v in [
            size + 1,
            size.saturating_sub(1),
            size + 64,
            size * 2,
            u64::from(u32::MAX),
            1 << 63,
            u64::MAX,
            honest.len() as u64,
        ] {
            jobs.push((
                format!("section at {h} size {v}"),
                Mut::Patch(h + 4, v.to_le_bytes().to_vec()),
                false,
            ));
        }
    }
    // Section count, version, magic.
    for v in [0u32, 9, 11, 32, 33, u32::MAX] {
        jobs.push((
            format!("section count {v}"),
            Mut::Patch(8, v.to_le_bytes().to_vec()),
            false,
        ));
    }
    for v in [0u32, 2, u32::MAX] {
        jobs.push((
            format!("version {v}"),
            Mut::Patch(4, v.to_le_bytes().to_vec()),
            false,
        ));
    }

    // Groth16 header sizes: nVars, nPublic, domain.
    let g16 = support::offset(honest, section::GROTH16);
    for (field, at) in [
        ("nVars", g16 + 72),
        ("nPublic", g16 + 76),
        ("domain", g16 + 80),
    ] {
        let cur = u32::from_le_bytes(honest[at..at + 4].try_into().unwrap());
        for v in [
            0u32,
            1,
            cur.wrapping_add(1),
            cur.wrapping_sub(1),
            cur * 2,
            1 << 31,
            u32::MAX,
        ] {
            if v == cur {
                continue;
            }
            jobs.push((
                format!("{field} = {v}"),
                Mut::Patch(at, v.to_le_bytes().to_vec()),
                false,
            ));
        }
    }

    // MPC count, entry type, parameter lengths, names, beacon parameters.
    let mpc = support::offset(honest, section::MPC);
    let n = Zkey::parse(honest).unwrap().entries.len() as u32;
    for v in [0u32, n - 1, n + 1, 10_000, 10_001, u32::MAX] {
        jobs.push((
            format!("MPC count {v}"),
            Mut::Patch(mpc + 64, v.to_le_bytes().to_vec()),
            false,
        ));
    }
    for i in 0..n as usize {
        let e = entry_offset(honest, i);
        for v in [0u32, 1, 2, u32::MAX] {
            let cur = u32::from_le_bytes(honest[e + 384..e + 388].try_into().unwrap());
            if v != cur {
                jobs.push((
                    format!("entry {i} type {v}"),
                    Mut::Patch(e + 384, v.to_le_bytes().to_vec()),
                    false,
                ));
            }
        }
        let plen = u32::from_le_bytes(honest[e + 388..e + 392].try_into().unwrap());
        for v in [0u32, plen + 1, plen.saturating_sub(1), u32::MAX] {
            if v != plen {
                jobs.push((
                    format!("entry {i} params length {v}"),
                    Mut::Patch(e + 388, v.to_le_bytes().to_vec()),
                    false,
                ));
            }
        }
        // Walk the parameters: tag 1 name, tag 2 exp, tag 3 beacon value.
        let mut p = e + 392;
        while p < e + 392 + plen as usize {
            match honest[p] {
                1 | 3 => {
                    for v in [0u8, 1, 64, 65, 255] {
                        if v != honest[p + 1] {
                            let k = Mut::Patch(p + 1, vec![v]);
                            jobs.push((
                                format!("entry {i} tag {} length {v}", honest[p]),
                                k,
                                false,
                            ));
                        }
                    }
                    p += 2 + honest[p + 1] as usize;
                }
                2 => {
                    for v in [0u8, 9, 11, 24, 25, 255] {
                        if v != honest[p + 1] {
                            let k = Mut::Patch(p + 1, vec![v]);
                            jobs.push((format!("entry {i} iterations exp {v}"), k, false));
                        }
                    }
                    p += 2;
                }
                _ => break,
            }
        }
    }
    jobs
}

/// The beacon entry snarkjs writes on top of `previous`, re-derived from its parameters, with
/// the honest beacon's parameter bytes.
fn beacon_entry(cs_hash: &[u8; 64], previous: &[MpcEntry], honest: &MpcEntry) -> MpcEntry {
    let mut cur = honest.beacon_hash.clone().unwrap();
    for _ in 0..(1u64 << honest.num_iterations_exp.unwrap()) {
        cur = Sha256::digest(&cur).to_vec();
    }
    let mut rng = ChaCha::from_be_bytes(&cur);
    let prv = fr_from_rng(&mut rng);
    let g1_s = g1_from_rng(&mut rng);
    let delta = previous
        .last()
        .map_or(G1Affine::generator(), |p| p.delta_after);
    let mut e = honest.clone();
    e.g1_s = g1_s;
    e.g1_sx = (g1_s * prv).into_affine();
    e.delta_after = (delta * prv).into_affine();
    e.transcript = expected_transcript(cs_hash, previous, &e);
    e.g2_spx = (hash_to_g2(&e.transcript) * prv).into_affine();
    e
}

/// An entry as snarkjs encodes it, with the given type and raw parameter bytes.
fn encode(e: &MpcEntry, kind: u32, params: &[u8]) -> Vec<u8> {
    let mut out = [
        g1_lem(&e.delta_after),
        g1_lem(&e.g1_s),
        g1_lem(&e.g1_sx),
        g2_lem(&e.g2_spx),
        e.transcript.to_vec(),
    ]
    .concat();
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&(params.len() as u32).to_le_bytes());
    out.extend_from_slice(params);
    out
}

/// Multiplies every point of sections L and H by `k` (rescaling for a new final δ).
fn rescale(key: &[u8], k: Fr) -> Vec<u8> {
    let mut out = key.to_vec();
    for id in [section::L, section::H] {
        let s = SectionTable::read(key, b"zkey")
            .unwrap()
            .unique(id)
            .unwrap();
        for at in (s.offset..s.offset + s.size).step_by(G1_BYTES) {
            let p = g1_from_lem(&key[at..at + G1_BYTES]).unwrap();
            if !p.is_zero() {
                let q = (p * k).into_affine();
                out[at..at + G1_BYTES].copy_from_slice(&g1_lem(&q));
            }
        }
    }
    out
}

/// Sets the vk δ (section 2) of a key.
fn with_delta(key: &[u8], d1: G1Affine, d2: ark_bn254::G2Affine) -> Vec<u8> {
    let mut out = key.to_vec();
    // n8q 4 + q 32 + n8r 4 + r 32 + sizes 12 + α1 64 + β1 64 + β2 128 + γ2 128 = 468.
    let at = support::offset(key, section::GROTH16) + 468;
    out[at..at + 64].copy_from_slice(&g1_lem(&d1));
    out[at + 64..at + 192].copy_from_slice(&g2_lem(&d2));
    out
}

/// Entry-level surgery: reorder, repeat, drop, misplace the beacon, cancel contributions.
fn structural_mutations(c: &Circuit) -> Vec<Job> {
    let honest = &c.final_;
    let parsed = Zkey::parse(honest).unwrap();
    let n = parsed.entries.len();
    let raw: Vec<Vec<u8>> = (0..n).map(|i| entry_bytes(honest, i)).collect();
    let beacon = raw[n - 1].clone();
    let mut jobs = Vec::new();
    let mut push = |what: &str, entries: Vec<Vec<u8>>| {
        jobs.push((
            what.to_string(),
            Mut::Whole(with_entries(honest, &entries)),
            false,
        ));
    };

    push("no entries", vec![]);
    push("beacon only", vec![beacon.clone()]);
    push("no beacon", raw[..n - 1].to_vec());
    push(
        "beacon first",
        [vec![beacon.clone()], raw[..n - 1].to_vec()].concat(),
    );
    push("beacon twice", [raw.clone(), vec![beacon.clone()]].concat());
    push("reversed", raw.iter().rev().cloned().collect());
    for i in 0..n - 1 {
        let mut e = raw.clone();
        e.insert(i + 1, raw[i].clone());
        push(&format!("entry {i} repeated"), e);
        let mut e = raw.clone();
        e.remove(i);
        push(&format!("entry {i} dropped"), e);
        if i + 1 < n - 1 {
            let mut e = raw.clone();
            e.swap(i, i + 1);
            push(&format!("entries {i} and {} swapped", i + 1), e);
        }
        let mut e = raw.clone();
        e.insert(i, beacon.clone());
        push(&format!("beacon copied before entry {i}"), e);
    }
    // The cap: 10,000 entries are parsed (bounded time), 10,001 are refused before parsing.
    push("10000 entries", vec![raw[0].clone(); 10_000]);
    push("10001 entries", vec![raw[0].clone(); 10_001]);

    // Valid chains crafted on top of the honest contributions.
    let cs = parsed.cs_hash;
    let contribs: Vec<MpcEntry> = parsed.entries[..n - 1].to_vec();
    let honest_beacon = &parsed.entries[n - 1];
    let beacon_params = params_of(&beacon).to_vec();
    let mut rng = rand::rngs::OsRng;
    let build = |chain: &[MpcEntry]| -> Vec<Vec<u8>> {
        chain
            .iter()
            .map(|e| match e.kind {
                EntryKind::Contribution => support::encode_entry(e),
                EntryKind::Beacon => encode(e, 1, &beacon_params),
            })
            .collect()
    };

    // x then 1/x: δ returns to an earlier value; L/H and vk δ stay the honest ones.
    let x = Fr::rand(&mut rng);
    let mut chain = contribs.clone();
    let cx = support::contribution(&cs, &chain, &contribs[0], x);
    chain.push(cx);
    let cinv = support::contribution(&cs, &chain, &contribs[0], x.inverse().unwrap());
    chain.push(cinv);
    let b = beacon_entry(&cs, &chain, honest_beacon);
    assert_eq!(
        b.delta_after, honest_beacon.delta_after,
        "cancelled chain ends at the honest δ"
    );
    chain.push(b);
    jobs.push((
        "x then 1/x before the beacon".into(),
        Mut::Whole(with_entries(honest, &build(&chain))),
        false,
    ));

    // A contribution with secret 1.
    let mut chain = contribs.clone();
    let one = support::contribution(&cs, &chain, &contribs[0], Fr::from(1u64));
    chain.push(one);
    chain.push(beacon_entry(&cs, &chain, honest_beacon));
    jobs.push((
        "secret-1 contribution".into(),
        Mut::Whole(with_entries(honest, &build(&chain))),
        false,
    ));

    // Beacon misplaced: a valid contribution y after a valid beacon; L/H and vk δ consistent.
    let y = Fr::rand(&mut rng);
    let mut chain = contribs.clone();
    chain.push(beacon_entry(&cs, &chain, honest_beacon));
    let cy = support::contribution(&cs, &chain, &contribs[0], y);
    let (d1, d2) = (cy.delta_after, (parsed.header.delta2 * y).into_affine());
    chain.push(cy);
    let key = with_delta(
        &rescale(&with_entries(honest, &build(&chain)), y.inverse().unwrap()),
        d1,
        d2,
    );
    jobs.push((
        "valid contribution after the beacon".into(),
        Mut::Whole(key),
        false,
    ));

    // Too few contributions: only the first one, then a valid beacon, consistent sections.
    let mut chain = contribs[..1].to_vec();
    chain.push(beacon_entry(&cs, &chain, honest_beacon));
    let d_new = chain.last().unwrap().delta_after;
    // δ_new / δ_honest as a scalar is unknown; skip rescaling: policy alone must fail.
    let _ = d_new;
    jobs.push((
        "one contribution and a valid beacon".into(),
        Mut::Whole(with_entries(honest, &build(&chain))),
        false,
    ));

    // Positive control: one extra valid contribution y before a re-derived beacon, sections and
    // vk δ rescaled. A sound key the Rust verifier must ACCEPT (the h_k cross-check against the
    // transcript is the TS CLI's job).
    let y = Fr::rand(&mut rng);
    let mut chain = contribs.clone();
    let cy = support::contribution(&cs, &chain, &contribs[0], y);
    chain.push(cy);
    let b = beacon_entry(&cs, &chain, honest_beacon);
    let (d1, d2) = (b.delta_after, (parsed.header.delta2 * y).into_affine());
    chain.push(b);
    let key = with_delta(
        &rescale(&with_entries(honest, &build(&chain)), y.inverse().unwrap()),
        d1,
        d2,
    );
    let v = verify(&c.genesis, &key, &c.expect);
    assert!(
        v.ok,
        "{}: positive control rejected: {:?}",
        c.name,
        v.checks
            .iter()
            .filter(|k| !k.ok)
            .map(|k| k.detail.clone())
            .collect::<Vec<_>>()
    );
    jobs
}

fn rehearsal() -> Option<String> {
    env_input("ORBINUM_REHEARSAL_DIR")
}

#[test]
fn shield_final_key_mutations() {
    let Some(dir) = rehearsal() else { return };
    let c = load(&dir, "shield", Duration::from_secs(20));
    assert!(verify(&c.genesis, &c.final_, &c.expect).ok);
    let mut rng = StdRng::seed_from_u64(0x0a0d_17ed);
    let mut jobs = byte_mutations(&c, &mut rng, 400, true);
    jobs.extend(structural_mutations(&c));
    let total = jobs.len();
    let start = Instant::now();
    let violations = run_all(&c, &jobs);
    eprintln!("shield: {total} mutations in {:?}", start.elapsed());
    assert!(
        violations.is_empty(),
        "{} violations:\n{}",
        violations.len(),
        violations.join("\n")
    );
}

#[test]
fn unshield_and_transfer_final_key_mutations() {
    let Some(dir) = rehearsal() else { return };
    for name in ["unshield", "transfer"] {
        let c = load(&dir, name, Duration::from_secs(60));
        let mut rng = StdRng::seed_from_u64(0x0a0d_17ee);
        let mut jobs = byte_mutations(&c, &mut rng, 24, false);
        // Only the cheap structural cases here; shield covers the crafted chains.
        jobs.retain(|(what, _, _)| !what.starts_with("flip") || rng.gen_ratio(1, 3));
        let total = jobs.len();
        let start = Instant::now();
        let violations = run_all(&c, &jobs);
        eprintln!("{name}: {total} mutations in {:?}", start.elapsed());
        assert!(
            violations.is_empty(),
            "{} violations:\n{}",
            violations.len(),
            violations.join("\n")
        );
    }
}

/// The genesis side: a mutated genesis against the honest final never passes either.
#[test]
fn shield_genesis_mutations() {
    let Some(dir) = rehearsal() else { return };
    let c = load(&dir, "shield", Duration::from_secs(20));
    let mut rng = StdRng::seed_from_u64(0x9e2e_5150);
    let honest = c.genesis.clone();
    let headers = section_headers(&honest);
    let mut violations = Vec::new();
    let mut positions: Vec<usize> = (0..12).collect();
    for &(h, data, size) in &headers {
        positions.extend(h..h + 12);
        positions.extend((0..64).map(|_| rng.gen_range(data..data + size)));
    }
    for at in positions {
        let mut g = honest.clone();
        g[at] ^= 1 << (at % 8);
        let r = catch_unwind(AssertUnwindSafe(|| verify(&g, &c.final_, &c.expect)));
        match r {
            Err(_) => violations.push(format!("genesis flip {at}: PANIC")),
            Ok(v) if v.ok => violations.push(format!("genesis flip {at}: ACCEPTED")),
            Ok(_) => {}
        }
    }
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}
