//! Deterministic mutations of the fixtures: the verifier never panics, and a changed key is
//! never accepted unless the change is inside a contributor name (names are not covered by `h_k`).

// Tests and their helpers fail by panicking; fixture sizes always fit u32.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

#[path = "../support/mod.rs"]
mod support;

use orbinum_ceremony_verifier::checks::verify;
use orbinum_ceremony_verifier::formats::{R1cs, Zkey};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use support::{announced, entry_offset, fixture};

/// Byte ranges of the contributor names in the final fixture.
fn name_ranges(key: &[u8]) -> Vec<std::ops::Range<usize>> {
    let n = Zkey::parse(key).unwrap().entries.len();
    (0..n)
        .filter_map(|i| {
            let params = entry_offset(key, i) + 392;
            (key[params] == 1).then(|| params + 2..params + 2 + key[params + 1] as usize)
        })
        .collect()
}

#[test]
fn mutated_final_keys_never_panic_or_pass() {
    let genesis = fixture("multiplier_0.zkey");
    let honest = fixture("multiplier_final.zkey");
    let names = name_ranges(&honest);

    for cut in (0..honest.len()).step_by(37) {
        assert!(
            !verify(&genesis, &honest[..cut], &announced()).ok,
            "truncated at {cut}"
        );
    }
    // One flip in every byte, the bit rotating: container, headers, points and entries.
    let accepted: Vec<usize> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..8)
            .map(|w| {
                let (genesis, honest) = (&genesis, &honest);
                scope.spawn(move || {
                    (w..honest.len())
                        .step_by(8)
                        .filter(|&at| {
                            let mut key = honest.clone();
                            key[at] ^= 1 << (at % 8);
                            verify(genesis, &key, &announced()).ok
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        workers
            .into_iter()
            .flat_map(|w| w.join().unwrap())
            .collect()
    });
    for at in accepted {
        assert!(
            names.iter().any(|r| r.contains(&at)),
            "flip at {at} accepted"
        );
    }
}

#[test]
fn mutated_r1cs_files_never_panic() {
    let honest = fixture("multiplier.r1cs");
    let mut rng = StdRng::seed_from_u64(0x71c5);
    for cut in 0..honest.len() {
        let _ = R1cs::parse(&honest[..cut], 1 << 16);
    }
    for _ in 0..2_000 {
        let mut r1cs = honest.clone();
        let at = rng.gen_range(0..r1cs.len());
        r1cs[at] = rng.gen();
        let _ = R1cs::parse(&r1cs, 1 << 16);
    }
}
