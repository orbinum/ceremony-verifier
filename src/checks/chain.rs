//! The MPC chain: every entry's transcript, proof of knowledge and δ update; the beacon re-derived.

use std::collections::HashSet;

use ark_bn254::G1Affine;
use ark_ec::AffineRepr;

use super::pairing::same_ratio;
use crate::compat::{beacon_key, g1_uncompressed, hash_to_g2, TranscriptHasher};
use crate::formats::{EntryKind, MpcEntry, Zkey};

/// Problems found walking the chain from δ = 1, and the δ it ends at. The walk stops at the
/// first broken entry: every later one builds on it, so going on would only cost time.
/// No δ may repeat (genesis included): a cancelled contribution must not count.
pub fn chain_problems(zkey: &Zkey) -> (Vec<String>, G1Affine) {
    let mut delta = G1Affine::generator();
    let mut seen = HashSet::from([g1_uncompressed(&delta)]);
    let mut transcript = TranscriptHasher::new(&zkey.cs_hash);
    let last = zkey.entries.len().saturating_sub(1);
    for (i, e) in zkey.entries.iter().enumerate() {
        let mut problems = entry_problems(e, delta, &transcript, i == last);
        if !seen.insert(g1_uncompressed(&e.delta_after)) {
            problems.push("δ repeats an earlier value (no-op or cancelled contributions)".into());
        }
        if !problems.is_empty() {
            let n = i + 1;
            return (
                problems.iter().map(|p| format!("entry {n}: {p}")).collect(),
                delta,
            );
        }
        transcript.push(e);
        delta = e.delta_after;
    }
    (Vec::new(), delta)
}

fn entry_problems(
    e: &MpcEntry,
    delta: G1Affine,
    transcript: &TranscriptHasher,
    is_last: bool,
) -> Vec<String> {
    if [e.delta_after, e.g1_s, e.g1_sx]
        .iter()
        .any(AffineRepr::is_zero)
        || e.g2_spx.is_zero()
    {
        return vec!["point at infinity".into()];
    }
    let mut problems = Vec::new();
    if transcript.expected(e) != e.transcript {
        problems.push("inconsistent transcript".into());
    }
    if e.g1_s == e.g1_sx {
        problems.push("no-op contribution (secret 1)".into());
    }
    let g2_sp = hash_to_g2(&e.transcript);
    if !same_ratio(e.g1_s, e.g1_sx, g2_sp, e.g2_spx) {
        problems.push("proof of knowledge does not verify".into());
    }
    if !same_ratio(delta, e.delta_after, g2_sp, e.g2_spx) {
        problems.push("δ does not follow its public key".into());
    }
    if e.kind == EntryKind::Beacon {
        // Deriving costs up to 2^24 hashes: only the last entry may be the beacon.
        if is_last {
            match (e.beacon_hash.as_deref(), e.num_iterations_exp) {
                (Some(hash), Some(exp)) => match beacon_key(hash, exp) {
                    Ok(key) if key == (e.g1_s, e.g1_sx) => {}
                    Ok(_) => problems.push("beacon key is not derived from its parameters".into()),
                    Err(err) => problems.push(err.to_string()),
                },
                _ => problems.push("beacon without parameters".into()),
            }
        } else {
            problems.push("beacon before the last entry".into());
        }
    }
    problems
}
