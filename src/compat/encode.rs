//! The uncompressed big-endian point encoding snarkjs hashes (`toRprUncompressed`).

use ark_bn254::{Fq, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};

fn fq_be(x: Fq) -> Vec<u8> {
    x.into_bigint().to_bytes_be()
}

/// x‖y, 32 bytes each; the point at infinity is all zeros with the 0x40 flag.
pub fn g1_uncompressed(p: &G1Affine) -> [u8; 64] {
    match p.xy() {
        None => {
            let mut out = [0u8; 64];
            out[0] = 0x40;
            out
        }
        Some((x, y)) => xy_be(x, y),
    }
}

/// x‖y big-endian, also for coordinates that are not a curve point.
pub fn xy_be(x: Fq, y: Fq) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&fq_be(x));
    out[32..].copy_from_slice(&fq_be(y));
    out
}

/// x.c1‖x.c0‖y.c1‖y.c0, 32 bytes each; the point at infinity is all zeros with the 0x40 flag.
pub fn g2_uncompressed(p: &G2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    match p.xy() {
        None => out[0] = 0x40,
        Some((x, y)) => {
            for (i, c) in [x.c1, x.c0, y.c1, y.c0].into_iter().enumerate() {
                out[i * 32..(i + 1) * 32].copy_from_slice(&fq_be(c));
            }
        }
    }
    out
}

/// `batchLEMtoU`: as `g1_uncompressed`, but the point at infinity is all zeros (no flag).
pub fn g1_lem_to_u(p: &G1Affine) -> [u8; 64] {
    if p.is_zero() {
        [0; 64]
    } else {
        g1_uncompressed(p)
    }
}

/// `batchLEMtoU` for G2.
pub fn g2_lem_to_u(p: &G2Affine) -> [u8; 128] {
    if p.is_zero() {
        [0; 128]
    } else {
        g2_uncompressed(p)
    }
}
