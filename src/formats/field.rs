//! Field elements and points as snarkjs stores them: little-endian Montgomery representation.
//!
//! arkworks also stores BN254 elements in Montgomery form with R = 2^256, so a stored value `m`
//! is exactly `Fp::new_unchecked(m)`. "Unchecked" only skips reduction: canonicity (m < p) is
//! enforced here, and every point is checked on the curve and, for G2, in the subgroup.

use ark_bn254::{Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInt, PrimeField};

use crate::error::{invalid, Result};

/// Bytes per field element (BN254 Fq and Fr).
pub const N8: usize = 32;
/// Bytes per affine G1 point (x‖y).
pub const G1_BYTES: usize = 2 * N8;
/// Bytes per affine G2 point (x.c0‖x.c1‖y.c0‖y.c1).
pub const G2_BYTES: usize = 4 * N8;

/// A 256-bit little-endian integer from 32 bytes.
pub fn le_bigint(bytes: &[u8]) -> BigInt<4> {
    let mut l = [0u64; 4];
    for (i, chunk) in bytes.chunks_exact(8).take(4).enumerate() {
        let mut a = [0u8; 8];
        a.copy_from_slice(chunk);
        l[i] = u64::from_le_bytes(a);
    }
    BigInt::new(l)
}

/// Canonical Montgomery-LE Fq element (value < q).
pub fn fq_from_lem(bytes: &[u8]) -> Result<Fq> {
    let m = le_bigint(bytes);
    if m >= Fq::MODULUS {
        return invalid("Fq element out of range");
    }
    Ok(Fq::new_unchecked(m))
}

/// Canonical Montgomery-LE Fr element (value < r).
pub fn fr_from_lem(bytes: &[u8]) -> Result<Fr> {
    let m = le_bigint(bytes);
    if m >= Fr::MODULUS {
        return invalid("Fr element out of range");
    }
    Ok(Fr::new_unchecked(m))
}

/// G1 affine point (x‖y, 64 B). All-zero encodes the point at infinity.
pub fn g1_from_lem(bytes: &[u8]) -> Result<G1Affine> {
    if bytes.len() != G1_BYTES {
        return invalid("G1 point of the wrong length");
    }
    if bytes.iter().all(|&b| b == 0) {
        return Ok(G1Affine::zero());
    }
    let p = G1Affine::new_unchecked(
        fq_from_lem(&bytes[..N8])?,
        fq_from_lem(&bytes[N8..G1_BYTES])?,
    );
    // BN254 G1 has cofactor 1: on the curve means in the subgroup.
    if !p.is_on_curve() {
        return invalid("G1 point not on the curve");
    }
    Ok(p)
}

/// G2 affine point (x.c0‖x.c1‖y.c0‖y.c1, 128 B). All-zero encodes the point at infinity.
pub fn g2_from_lem(bytes: &[u8]) -> Result<G2Affine> {
    if bytes.len() != G2_BYTES {
        return invalid("G2 point of the wrong length");
    }
    if bytes.iter().all(|&b| b == 0) {
        return Ok(G2Affine::zero());
    }
    let f = |i: usize| fq_from_lem(&bytes[i * N8..(i + 1) * N8]);
    let p = G2Affine::new_unchecked(Fq2::new(f(0)?, f(1)?), Fq2::new(f(2)?, f(3)?));
    if !p.is_on_curve() {
        return invalid("G2 point not on the curve");
    }
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        return invalid("G2 point not in the prime-order subgroup");
    }
    Ok(p)
}
