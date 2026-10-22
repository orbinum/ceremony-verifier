use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;

/// e(a1, b2) = e(b1, a2), i.e. b1/a1 = b2/a2 in the exponent. Zero inputs never pass.
pub fn same_ratio(a1: G1Affine, b1: G1Affine, a2: G2Affine, b2: G2Affine) -> bool {
    if a1.is_zero() || b1.is_zero() || a2.is_zero() || b2.is_zero() {
        return false;
    }
    Bn254::multi_pairing([a1, -b1], [b2, a2]).0 == <Bn254 as Pairing>::TargetField::from(1u64)
}
