//! Multi-scalar multiplication that refuses mismatched lengths instead of truncating.

use ark_bn254::Fr;
use ark_ec::VariableBaseMSM;

use crate::error::{invalid, Result};

pub fn msm<G: VariableBaseMSM<ScalarField = Fr>>(
    bases: &[G::MulBase],
    scalars: &[Fr],
) -> Result<G> {
    G::msm(bases, scalars)
        .or_else(|n| invalid(format!("MSM over {n} bases with {} scalars", scalars.len())))
}
