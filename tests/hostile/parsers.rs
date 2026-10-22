//! Seeded mutations of the r1cs and ptau readers. They never panic; values outside their
//! range (sizes, nWires, constraint counts, non-canonical coefficients) are refused; a mutated
//! r1cs that still parses never passes Stage B unless the change is in a part `newZKey` ignores
//! (wire-to-label map, nLabels, nPrvIn). Real inputs from `ORBINUM_REHEARSAL_DIR` and
//! `ORBINUM_PTAU`; the synthetic ptau tests need neither.

// Tests and their helpers fail by panicking; sizes always fit u32.
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
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::{Duration, Instant};

use ark_bn254::{Fq, Fr};
use ark_ff::{BigInteger, PrimeField};
use orbinum_ceremony_verifier::checks::{verify, Expectations, Source};
use orbinum_ceremony_verifier::compat::{coeffs_section, domain_size};
use orbinum_ceremony_verifier::formats::{Ptau, R1cs, SectionTable, G1_BYTES, G2_BYTES};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use support::{binfile, env_input};

fn no_panic<T>(what: &str, f: impl FnOnce() -> T) -> Result<T, String> {
    let start = Instant::now();
    let r = catch_unwind(AssertUnwindSafe(f)).map_err(|_| format!("{what}: PANIC"));
    let elapsed = start.elapsed();
    if elapsed > Duration::from_millis(200) {
        eprintln!("slow: {what}: {elapsed:?}");
    }
    r
}

/// Parses, and on success exercises what Stage B derives from an r1cs.
fn parse_r1cs(bytes: &[u8], max: usize) -> Option<R1cs> {
    let r = R1cs::parse(bytes, max).ok()?;
    let _ = domain_size(&r);
    let _ = coeffs_section(&r);
    Some(r)
}

/// Offsets in a circom r1cs: (header data, constraints data, constraints size, wire map data,
/// wire map size).
fn r1cs_layout(bytes: &[u8]) -> (usize, usize, usize, usize, usize) {
    let t = SectionTable::read(bytes, b"r1cs").unwrap();
    let (h, c, w) = (
        t.unique(1).unwrap(),
        t.unique(2).unwrap(),
        t.unique(3).unwrap(),
    );
    (h.offset, c.offset, c.size, w.offset, w.size)
}

fn put(bytes: &mut [u8], at: usize, v: &[u8]) {
    bytes[at..at + v.len()].copy_from_slice(v);
}

fn le32(n: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, l) in n.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&l.to_le_bytes());
    }
    out
}

#[test]
fn r1cs_reader_mutations() {
    let Some(dir) = env_input("ORBINUM_REHEARSAL_DIR") else {
        return;
    };
    let mut violations = Vec::new();
    for name in ["shield"] {
        let honest = fs::read(format!("{dir}/r1cs/{name}.r1cs")).unwrap();
        let max = 1usize << 16;
        assert!(parse_r1cs(&honest, max).is_some());
        let (h, c, csize, _w, _) = r1cs_layout(&honest);
        let mut rng = StdRng::seed_from_u64(0x0a0d_1c50);
        let mut record = |what: String, r: Result<Option<R1cs>, String>, must_fail: bool| match r {
            Err(e) => violations.push(format!("{name}: {e}")),
            Ok(Some(_)) if must_fail => violations.push(format!("{name}: {what}: parsed")),
            Ok(_) => {}
        };

        // Truncations.
        let mut cuts: Vec<usize> = (0..honest.len()).step_by(honest.len() / 400 + 1).collect();
        cuts.extend(0..h + 64);
        for cut in cuts {
            let what = format!("truncate at {cut}");
            record(
                what.clone(),
                no_panic(&what, || parse_r1cs(&honest[..cut], max)),
                true,
            );
        }
        // Every bit of the file header, section headers and header data; a seeded sample of
        // the constraints.
        let mut positions: Vec<usize> = (0..h + 64).collect();
        positions.extend(c - 12..c);
        positions.extend((0..600).map(|_| rng.gen_range(c..c + csize)));
        for at in positions {
            for bit in 0..8 {
                let mut m = honest.clone();
                m[at] ^= 1 << bit;
                let what = format!("flip {at}.{bit}");
                record(what.clone(), no_panic(&what, || parse_r1cs(&m, max)), false);
            }
        }
        // Out-of-range values that must be refused.
        let r_bytes = le32(&Fr::MODULUS.0);
        let mut r_plus_1 = Fr::MODULUS;
        r_plus_1.add_with_carry(&ark_ff::BigInt::from(1u64));
        let first_coef = c + 4 + 4; // nA, signal
        let cases: Vec<(String, usize, Vec<u8>)> = vec![
            ("nWires 0".into(), h + 36, 0u32.to_le_bytes().to_vec()),
            (
                "nWires u32::MAX".into(),
                h + 36,
                u32::MAX.to_le_bytes().to_vec(),
            ),
            (
                "nPubOut u32::MAX".into(),
                h + 40,
                u32::MAX.to_le_bytes().to_vec(),
            ),
            (
                "nPubIn u32::MAX".into(),
                h + 44,
                u32::MAX.to_le_bytes().to_vec(),
            ),
            (
                "nPrvIn u32::MAX".into(),
                h + 48,
                u32::MAX.to_le_bytes().to_vec(),
            ),
            (
                "mConstraints u32::MAX".into(),
                h + 60,
                u32::MAX.to_le_bytes().to_vec(),
            ),
            (
                "mConstraints 2^16 + 1".into(),
                h + 60,
                (65_537u32).to_le_bytes().to_vec(),
            ),
            ("n8 48".into(), h, 48u32.to_le_bytes().to_vec()),
            ("prime q".into(), h + 4, le32(&Fq::MODULUS.0).to_vec()),
            (
                "first nA u32::MAX".into(),
                c,
                u32::MAX.to_le_bytes().to_vec(),
            ),
            (
                "first signal u32::MAX".into(),
                c + 4,
                u32::MAX.to_le_bytes().to_vec(),
            ),
            ("first coefficient r".into(), first_coef, r_bytes.to_vec()),
            (
                "first coefficient r + 1".into(),
                first_coef,
                le32(&r_plus_1.0).to_vec(),
            ),
            (
                "first coefficient 2^256 - 1".into(),
                first_coef,
                vec![0xff; 32],
            ),
            (
                "section 2 size u64::MAX".into(),
                c - 8,
                u64::MAX.to_le_bytes().to_vec(),
            ),
            ("section count 33".into(), 8, 33u32.to_le_bytes().to_vec()),
        ];
        for (what, at, v) in cases {
            let mut m = honest.clone();
            put(&mut m, at, &v);
            record(what.clone(), no_panic(&what, || parse_r1cs(&m, max)), true);
        }
        // nWires = signal of the first term: out of range.
        let n_vars = u32::from_le_bytes(honest[h + 36..h + 40].try_into().unwrap());
        let mut m = honest.clone();
        put(&mut m, c + 4, &n_vars.to_le_bytes());
        record(
            "first signal = nWires".into(),
            no_panic("signal", || parse_r1cs(&m, max)),
            true,
        );
        // r − 1 is canonical: accepted by the reader (another circuit, refused by Stage B).
        let mut r_minus_1 = Fr::MODULUS;
        r_minus_1.sub_with_borrow(&ark_ff::BigInt::from(1u64));
        let mut m = honest.clone();
        put(&mut m, first_coef, &le32(&r_minus_1.0));
        assert!(R1cs::parse(&m, max).is_ok(), "{name}: r − 1 is canonical");
        // The cap: fewer constraints allowed than the file has.
        assert!(R1cs::parse(&honest, 1).is_err());
        let _ = no_panic("max usize", || R1cs::parse(&honest, usize::MAX));
    }
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

/// A mutated r1cs that still parses must fail Stage B, unless the mutation is in a part
/// `newZKey` does not read.
#[test]
fn r1cs_mutations_never_pass_stage_b() {
    let (Some(dir), Some(ptau)) = (
        env_input("ORBINUM_REHEARSAL_DIR"),
        env_input("ORBINUM_PTAU"),
    ) else {
        return;
    };
    let ptau = fs::read(ptau).unwrap();
    let read = |p: String| fs::read(p).unwrap();
    let genesis = read(format!("{dir}/genesis/shield.genesis.zkey"));
    let final_ = read(format!("{dir}/final/shield.final.zkey"));
    let honest = read(format!("{dir}/r1cs/shield.r1cs"));
    let (h, c, csize, w, wsize) = r1cs_layout(&honest);
    let expect = |r1cs: Vec<u8>| Expectations {
        min_contributions: 3,
        beacon: None,
        source: Some(Source {
            r1cs,
            ptau: ptau.clone(),
        }),
    };
    assert!(verify(&genesis, &final_, &expect(honest.clone())).ok);

    let mut rng = StdRng::seed_from_u64(0x5ba9_eb00);
    let mut candidates = Vec::new();
    // Header fields, every byte.
    for at in h..h + 64 {
        candidates.push((at, (at % 8) as u8));
    }
    for _ in 0..160 {
        candidates.push((rng.gen_range(c..c + csize), rng.gen_range(0..8)));
    }
    for _ in 0..8 {
        candidates.push((rng.gen_range(w..w + wsize), rng.gen_range(0..8)));
    }
    let ignored = |at: usize| {
        (w..w + wsize).contains(&at)        // wire-to-label map
            || (h + 52..h + 60).contains(&at) // nLabels
            || (h + 48..h + 52).contains(&at) // nPrvIn (only bounded by nWires)
    };
    let start = Instant::now();
    let candidates = &candidates;
    let (genesis, final_, honest, expect, ignored) =
        (&genesis, &final_, &honest, &expect, &ignored);
    let results: Vec<(usize, usize, Vec<String>)> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..4)
            .map(|wk| {
                scope.spawn(move || {
                    let (mut runs, mut accepted_ignored, mut violations) = (0, 0, Vec::new());
                    for &(at, bit) in candidates.iter().skip(wk).step_by(4) {
                        let mut m = honest.clone();
                        m[at] ^= 1 << bit;
                        if R1cs::parse(&m, 1 << 16).is_err() {
                            continue;
                        }
                        runs += 1;
                        match no_panic("stage b", || verify(genesis, final_, &expect(m))) {
                            Err(e) => violations.push(format!("flip {at}.{bit}: {e}")),
                            Ok(v) if v.ok && ignored(at) => accepted_ignored += 1,
                            Ok(v) if v.ok => violations.push(format!("flip {at}.{bit}: ACCEPTED")),
                            Ok(_) => {}
                        }
                    }
                    (runs, accepted_ignored, violations)
                })
            })
            .collect();
        workers.into_iter().map(|w| w.join().unwrap()).collect()
    });
    let stage_b_runs: usize = results.iter().map(|r| r.0).sum();
    let accepted_ignored: usize = results.iter().map(|r| r.1).sum();
    let violations: Vec<String> = results.into_iter().flat_map(|r| r.2).collect();
    eprintln!(
        "stage B: {stage_b_runs} parsed mutations in {:?}; {accepted_ignored} accepted, all in bytes newZKey ignores",
        start.elapsed()
    );
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

/// A minimal valid power-1 ptau: the sections and sizes `Ptau::parse` requires, zero points.
fn synthetic_ptau(power: u32) -> Vec<u8> {
    let n = 1usize << power;
    let mut header = 32u32.to_le_bytes().to_vec();
    header.extend_from_slice(&le32(&Fq::MODULUS.0));
    header.extend_from_slice(&power.to_le_bytes());
    header.extend_from_slice(&power.to_le_bytes()); // ceremonyPower
    let z = |len: usize| vec![0u8; len];
    binfile(
        *b"ptau",
        1,
        &[
            (1, header),
            (2, z((2 * n - 1) * G1_BYTES)),
            (3, z(n * G2_BYTES)),
            (4, z(n * G1_BYTES)),
            (5, z(n * G1_BYTES)),
            (6, z(G2_BYTES)),
            (12, z((4 * n - 1) * G1_BYTES)),
            (13, z((2 * n - 1) * G2_BYTES)),
            (14, z((2 * n - 1) * G1_BYTES)),
            (15, z((2 * n - 1) * G1_BYTES)),
        ],
    )
}

/// Every accessor Stage B uses, for every domain it could ask (powers of two up to 2^20).
fn exercise(p: &Ptau) {
    for k in 1..=20u32 {
        let d = 1usize << k;
        let _ = p.lagrange_tau_g1(d);
        let _ = p.lagrange_tau_g2(d);
        let _ = p.lagrange_alpha_tau_g1(d);
        let _ = p.lagrange_beta_tau_g1(d);
    }
    for i in [0usize, 1, 2, 3, 1 << 20, usize::MAX / 64, usize::MAX] {
        let _ = p.tau_g1_at(i);
    }
    let _ = (p.alpha1(), p.beta1(), p.beta2());
}

#[test]
fn ptau_reader_on_a_synthetic_file() {
    let honest = synthetic_ptau(1);
    exercise(&Ptau::parse(&honest).unwrap());
    let mut violations = Vec::new();
    for cut in 0..honest.len() {
        if let Err(e) = no_panic("truncate", || {
            Ptau::parse(&honest[..cut]).map(|p| exercise(&p))
        }) {
            violations.push(format!("truncate at {cut}: {e}"));
        }
    }
    for at in 0..honest.len() {
        for bit in 0..8 {
            let mut m = honest.clone();
            m[at] ^= 1 << bit;
            if let Err(e) = no_panic("flip", || Ptau::parse(&m).map(|p| exercise(&p))) {
                violations.push(format!("flip {at}.{bit}: {e}"));
            }
        }
    }
    // Power and n8 out of range; section sizes inflated.
    let power_at = 12 + 12 + 4 + 32;
    for p in [0u32, 2, 28, 29, 63, 64, u32::MAX] {
        let mut m = honest.clone();
        put(&mut m, power_at, &p.to_le_bytes());
        match no_panic("power", || Ptau::parse(&m).is_ok()) {
            Ok(true) => violations.push(format!("power {p}: parsed")),
            Ok(false) => {}
            Err(e) => violations.push(format!("power {p}: {e}")),
        }
    }
    for n8 in [0u32, 31, 33, 48, u32::MAX] {
        let mut m = honest.clone();
        put(&mut m, 24, &n8.to_le_bytes());
        if !matches!(no_panic("n8", || Ptau::parse(&m).is_err()), Ok(true)) {
            violations.push(format!("n8 {n8}: not refused"));
        }
    }
    let table = SectionTable::read(&honest, b"ptau").unwrap();
    let mut at = 12;
    for _ in &table.order {
        let size = u64::from_le_bytes(honest[at + 4..at + 12].try_into().unwrap());
        for v in [size + 1, size.saturating_sub(1), u64::MAX, 1 << 63] {
            let mut m = honest.clone();
            put(&mut m, at + 4, &v.to_le_bytes());
            if !matches!(no_panic("size", || Ptau::parse(&m).is_err()), Ok(true)) {
                violations.push(format!("section at {at} size {v}: not refused"));
            }
        }
        at += 12 + size as usize;
    }
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

/// The real ptau: every bit of the file and section headers, mutated in place and restored.
/// Through `verify`, any change is refused by the BLAKE2b pin before the reader runs.
#[test]
fn ptau_reader_on_the_pinned_file() {
    let Some(path) = env_input("ORBINUM_PTAU") else {
        return;
    };
    let mut bytes = fs::read(path).unwrap();
    exercise(&Ptau::parse(&bytes).unwrap());
    let mut headers = vec![];
    let count = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let mut at = 12usize;
    for _ in 0..count {
        let size = u64::from_le_bytes(bytes[at + 4..at + 12].try_into().unwrap()) as usize;
        headers.push((at, at + 12, size));
        at += 12 + size;
    }
    let mut positions: Vec<usize> = (0..12).collect();
    for &(h, data, _) in &headers {
        positions.extend(h..h + 12);
        if h == 12 {
            positions.extend(data..data + 44); // section 1: n8, q, power, ceremonyPower
        }
    }
    let mut violations = Vec::new();
    let start = Instant::now();
    for at in positions {
        for bit in 0..8 {
            bytes[at] ^= 1 << bit;
            if let Err(e) = no_panic("flip", || Ptau::parse(&bytes).map(|p| exercise(&p))) {
                violations.push(format!("flip {at}.{bit}: {e}"));
            }
            bytes[at] ^= 1 << bit;
        }
    }
    for &(h, data, size) in &headers {
        for cut in [h, h + 1, h + 11, data, data + size / 2, data + size - 1] {
            if let Err(e) = no_panic("cut", || Ptau::parse(&bytes[..cut]).map(|p| exercise(&p))) {
                violations.push(format!("truncate at {cut}: {e}"));
            }
        }
    }
    assert!(start.elapsed() < Duration::from_secs(120));
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

/// Out-of-contract arguments to the library are errors, never panics.
#[test]
fn library_refuses_out_of_contract_arguments() {
    let bytes = synthetic_ptau(1);
    let p = Ptau::parse(&bytes).unwrap();
    assert!(p.lagrange_tau_g1(0).is_err());
    assert!(p.lagrange_tau_g1(1 << 60).is_err());
    assert!(p.lagrange_tau_g1(usize::MAX).is_err());
    assert!(p.tau_g1_at(usize::MAX).is_err());
    assert!(orbinum_ceremony_verifier::formats::g1_from_lem(&[1u8; 10]).is_err());
    assert!(orbinum_ceremony_verifier::formats::g2_from_lem(&[1u8; 10]).is_err());
}

/// The fuzzer's ptau seed (`fuzz/seeds/ptau/`) stays a valid ptau, so fuzzing reaches the accessors.
#[test]
fn fuzz_ptau_seed_parses() {
    let seed = include_bytes!("../../fuzz/seeds/ptau/power1.ptau");
    let p = Ptau::parse(seed).unwrap();
    assert!(p.lagrange_tau_g1(2).is_ok());
}
