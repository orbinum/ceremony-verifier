//! The beacon key snarkjs derives from public parameters (`rngFromBeaconParams`).

use ark_bn254::{G1Affine, G1Projective};
use sha2::{Digest, Sha256};

use super::chacha::ChaCha;
use super::rng::{fr_from_rng, g1_from_rng};
use crate::error::{invalid, Result};

/// snarkjs' minimum, and the most we derive: above 2^24 the iterated hash costs hours.
pub const MIN_ITERATIONS_EXP: u8 = 10;
/// See [`MIN_ITERATIONS_EXP`].
pub const MAX_ITERATIONS_EXP: u8 = 24;

/// The public key a beacon entry must carry: `g1_s` and `g1_s · prvKey`, all derived from
/// SHA-256 iterated 2^exp times over the beacon value.
pub fn beacon_key(beacon: &[u8], iterations_exp: u8) -> Result<(G1Affine, G1Affine)> {
    if !(MIN_ITERATIONS_EXP..=MAX_ITERATIONS_EXP).contains(&iterations_exp) {
        return invalid(format!(
            "beacon iterations 2^{iterations_exp} outside 2^{MIN_ITERATIONS_EXP}..2^{MAX_ITERATIONS_EXP}"
        ));
    }
    if beacon.is_empty() || beacon.len() > 255 {
        return invalid("beacon value length");
    }
    let mut cur = beacon.to_vec();
    for _ in 0..(1u64 << iterations_exp) {
        cur = Sha256::digest(&cur).to_vec();
    }
    let mut rng = ChaCha::from_be_bytes(&cur);
    let prv = fr_from_rng(&mut rng);
    let g1_s = g1_from_rng(&mut rng);
    Ok((g1_s, (G1Projective::from(g1_s) * prv).into()))
}
