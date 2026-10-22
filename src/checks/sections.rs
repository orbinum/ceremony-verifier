//! L and H: every point must be the genesis point divided by the final δ.
//!
//! Checked with one random linear combination: e(Σ rᵢ·Gᵢ, g2) = e(Σ rᵢ·Fᵢ, δ2). With 128-bit
//! random scalars a wrong point passes with probability ≈ 2⁻¹²⁸ (snarkjs uses 32-bit scalars).

use ark_bn254::{Fr, G1Projective, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use rand::rngs::OsRng;
use rand::Rng;

use super::msm::msm;
use super::pairing::same_ratio;
use crate::formats::{section, Zkey};

pub fn scaled_by_delta_problems(genesis: &Zkey, final_: &Zkey) -> Vec<String> {
    let mut problems = Vec::new();
    for (id, name) in [(section::L, "L"), (section::H, "H")] {
        let (g, f) = match (genesis.g1_points(id), final_.g1_points(id)) {
            (Ok(g), Ok(f)) => (g, f),
            (Err(e), _) | (_, Err(e)) => {
                problems.push(format!("section {name}: {e}"));
                continue;
            }
        };
        if g.len() != f.len() {
            problems.push(format!("section {name}: sizes differ"));
            continue;
        }
        let scalars: Vec<Fr> = (0..g.len())
            .map(|_| Fr::from(OsRng.gen::<u128>()))
            .collect();
        let (rg, rf) = match (
            msm::<G1Projective>(&g, &scalars),
            msm::<G1Projective>(&f, &scalars),
        ) {
            (Ok(rg), Ok(rf)) => (rg.into_affine(), rf.into_affine()),
            (Err(e), _) | (_, Err(e)) => {
                problems.push(format!("section {name}: {e}"));
                continue;
            }
        };
        if rg.is_zero() && rf.is_zero() {
            continue;
        }
        if !same_ratio(rf, rg, G2Affine::generator(), final_.header.delta2) {
            problems.push(format!("section {name} is not the genesis divided by δ"));
        }
    }
    problems
}
