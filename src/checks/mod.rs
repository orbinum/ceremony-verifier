//! All checks of a final zkey against the pinned genesis (SPEC §2.5, §2.6, §8.4).

mod chain;
mod genesis;
mod header;
mod msm;
mod pairing;
mod sections;

use ark_bn254::{G1Affine, G2Affine};
use ark_ec::AffineRepr;

use crate::compat::contribution_hash;
use crate::formats::{EntryKind, Zkey, CONTRIBUTED_ORDER, GENESIS_ORDER};
use crate::report::{hex, EntryReport, Verdict};

pub use pairing::same_ratio;

/// Every check as (stable id, title). The CLI requires exactly these ids in a verdict.
pub mod check {
    /// Container, header and MPC section strict; points canonical, on the curve, in G2's subgroup.
    pub const WELL_FORMED: (&str, &str) = (
        "well-formed",
        "both zkeys are as snarkjs writes them: container, header, MPC entries (canonical, on curve, G2 subgroup)",
    );
    /// The genesis is a phase-2 start.
    pub const GENESIS_START: (&str, &str) = (
        "genesis-start",
        "genesis is a phase-2 start (δ = 1, no entries)",
    );
    /// Stage B: the genesis is `newZKey`'s output for the r1cs and the pinned ptau.
    pub const GENESIS_SOURCE: (&str, &str) = (
        "genesis-source",
        "genesis is derived from the announced r1cs and the pinned ptau",
    );
    /// Everything phase 2 must not touch is byte-identical to the genesis.
    pub const UNCHANGED: (&str, &str) = (
        "unchanged",
        "circuit, α/β/γ and sections IC/coeffs/A/B1/B2 unchanged from the genesis",
    );
    /// The announced minimum of contributions and beacon.
    pub const POLICY: (&str, &str) = (
        "policy",
        "enough contributions, beacon last and as announced",
    );
    /// The MPC chain, entry by entry.
    pub const CHAIN: (&str, &str) = (
        "chain",
        "every entry: transcript, proof of knowledge, δ update, not a no-op; beacon re-derived",
    );
    /// The verification key's δ.
    pub const FINAL_DELTA: (&str, &str) = (
        "final-delta",
        "final δ is the chain's δ, consistent in G1 and G2, and not trivial",
    );
    /// L and H divided by the final δ.
    pub const SCALED_SECTIONS: (&str, &str) = (
        "scaled-sections",
        "sections L and H are the genesis divided by δ",
    );
}

/// What the ceremony announced and the verifier must enforce.
#[derive(Debug, Clone)]
pub struct Expectations {
    /// At least this many contributions (never below 1: a key with only the beacon has a public δ).
    pub min_contributions: usize,
    /// The sealed beacon: value and iterations of the last entry.
    pub beacon: Option<(Vec<u8>, u8)>,
    /// The announced circuit and phase 1: the genesis must be derived from them.
    pub source: Option<Source>,
}

/// Raw bytes of the circuit's `.r1cs` and the pinned `.ptau`.
#[derive(Debug, Clone)]
pub struct Source {
    /// The circuit as circom compiled it.
    pub r1cs: Vec<u8>,
    /// `powersOfTau28_hez_final_16.ptau`, checked against its pin.
    pub ptau: Vec<u8>,
}

/// Runs every check and returns the verdict; never stops at the first failure.
pub fn verify(genesis_bytes: &[u8], final_bytes: &[u8], expect: &Expectations) -> Verdict {
    let mut v = Verdict::new();
    let parsed = (Zkey::parse(genesis_bytes), Zkey::parse(final_bytes));
    let (genesis, final_) = match parsed {
        (Ok(g), Ok(f)) => {
            v.check(check::WELL_FORMED, &layout_problems(&g, &f));
            (g, f)
        }
        (g, f) => {
            let problems = [
                g.err().map(|e| format!("genesis: {e}")),
                f.err().map(|e| format!("final: {e}")),
            ];
            let problems: Vec<String> = problems.into_iter().flatten().collect();
            v.check(check::WELL_FORMED, &problems);
            // Every id is still reported, so a caller sees this cause rather than a gap.
            let rest = [
                Some(check::GENESIS_START),
                expect.source.as_ref().map(|_| check::GENESIS_SOURCE),
                Some(check::UNCHANGED),
                Some(check::POLICY),
                Some(check::CHAIN),
                Some(check::FINAL_DELTA),
                Some(check::SCALED_SECTIONS),
            ];
            let not_run = ["not run: the keys are not well formed".to_string()];
            for c in rest.into_iter().flatten() {
                v.check(c, &not_run);
            }
            return v.finish();
        }
    };

    v.cs_hash = Some(hex(&final_.cs_hash));
    v.entries = final_
        .entries
        .iter()
        .enumerate()
        .map(|(i, e)| EntryReport {
            index: i + 1,
            kind: match e.kind {
                EntryKind::Contribution => "contribution",
                EntryKind::Beacon => "beacon",
            },
            name: e.name.clone(),
            hash: hex(&contribution_hash(e)),
        })
        .collect();

    v.check(check::GENESIS_START, &header::genesis_problems(&genesis));
    if let Some(source) = &expect.source {
        v.check(
            check::GENESIS_SOURCE,
            &genesis::source_problems(&genesis, &source.r1cs, &source.ptau),
        );
    }
    v.check(
        check::UNCHANGED,
        &header::unchanged_problems(&genesis, &final_),
    );
    v.check(check::POLICY, &policy_problems(&final_, expect));

    let (chain, last_delta) = chain::chain_problems(&final_);
    let chain_broken = !chain.is_empty();
    v.check(check::CHAIN, &chain);
    v.check(
        check::FINAL_DELTA,
        &if chain_broken {
            vec!["not checked: the chain is broken".into()]
        } else {
            final_delta_problems(&final_, last_delta)
        },
    );
    v.check(
        check::SCALED_SECTIONS,
        &sections::scaled_by_delta_problems(&genesis, &final_),
    );
    v.finish()
}

/// One encoding per key: the section order snarkjs writes, so a key has a single SHA-256.
fn layout_problems(genesis: &Zkey, final_: &Zkey) -> Vec<String> {
    let mut p = Vec::new();
    if genesis.order() != GENESIS_ORDER {
        p.push("genesis: sections not in the order snarkjs writes".into());
    }
    if final_.order() != CONTRIBUTED_ORDER {
        p.push("final: sections not in the order snarkjs writes".into());
    }
    p
}

fn policy_problems(zkey: &Zkey, expect: &Expectations) -> Vec<String> {
    let mut p = Vec::new();
    let kinds: Vec<EntryKind> = zkey.entries.iter().map(|e| e.kind).collect();
    let contributions = kinds
        .iter()
        .filter(|k| **k == EntryKind::Contribution)
        .count();
    let min = expect.min_contributions.max(1);
    if contributions < min {
        p.push(format!(
            "{contributions} contributions, at least {min} required"
        ));
    }
    match kinds.split_last() {
        Some((EntryKind::Beacon, rest)) if rest.iter().all(|k| *k == EntryKind::Contribution) => {}
        _ => p.push("the beacon must be the last entry and the only one".into()),
    }
    if let (Some((hash, exp)), Some(last)) = (&expect.beacon, zkey.entries.last()) {
        if last.beacon_hash.as_deref() != Some(hash.as_slice())
            || last.num_iterations_exp != Some(*exp)
        {
            p.push("beacon is not the announced one".into());
        }
    }
    p
}

fn final_delta_problems(zkey: &Zkey, last_delta: G1Affine) -> Vec<String> {
    let h = &zkey.header;
    let mut p = Vec::new();
    if h.delta1 != last_delta {
        p.push("vk δ1 is not the chain's last δ".into());
    }
    if !same_ratio(
        G1Affine::generator(),
        h.delta1,
        G2Affine::generator(),
        h.delta2,
    ) {
        p.push("δ1 and δ2 are not the same scalar".into());
    }
    if h.delta2 == h.gamma2 {
        p.push("δ = γ: phase 2 was skipped".into());
    }
    if h.delta1 == G1Affine::generator() || h.delta1.is_zero() {
        p.push("δ is trivial".into());
    }
    p
}
