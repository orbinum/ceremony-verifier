//! The fixed parts of snarkjs `newZKey` (`zkey_new.js`): domain size, coefficients section,
//! H section and csHash. The point sums (IC, A, B1, B2, C) are checked in `checks::genesis`.

use ark_bn254::{Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, PrimeField};
use blake2::{Blake2b512, Digest};

use super::encode::{g1_lem_to_u, g2_lem_to_u, g2_uncompressed, xy_be};
use super::wasm::sub_affine;
use crate::error::{format, invalid, Result};
use crate::formats::{g1_from_lem, Groth16Header, Ptau, R1cs, G1_BYTES};

/// snarkjs hashes the H points in chunks of this many, each chunk min(d − 1, CHUNK) long.
const H_HASH_CHUNK: usize = 1 << 14;

/// Fr's 2-adicity: larger domains take another path in snarkjs, never needed here.
const MAX_CIRCUIT_POWER: u32 = 27;

/// 2^(⌊log2(constraints + public)⌋ + 1): room for every constraint and public signal.
pub fn domain_size(r1cs: &R1cs) -> Result<usize> {
    let v = r1cs.constraints.len() + r1cs.n_public() as usize;
    let power = v.max(1).ilog2() + 1;
    if power > MAX_CIRCUIT_POWER {
        return format(format!("circuit power {power} is not supported"));
    }
    Ok(1 << power)
}

/// snarkjs writes lengths and indices as u32; anything larger cannot come from a real key.
fn u32_of(n: usize) -> Result<u32> {
    u32::try_from(n).or_else(|_| invalid(format!("{n} does not fit the u32 snarkjs writes")))
}

/// Section 4: u32 count, then (matrix, constraint, signal, n·R² mod r) for every A and B term,
/// then one A term ONE·(constraint m + s) per public signal s, ONE included.
pub fn coeffs_section(r1cs: &R1cs) -> Result<Vec<u8>> {
    let r2 = Fr::from(2u64).pow([512]);
    let n_public = r1cs.n_public();
    let m = u32_of(r1cs.constraints.len())?;
    let terms: usize = r1cs.constraints.iter().map(|k| k.a.len() + k.b.len()).sum();
    let count = terms + n_public as usize + 1;

    let mut out = Vec::with_capacity(4 + count * 44);
    out.extend_from_slice(&u32_of(count)?.to_le_bytes());
    let mut push = |matrix: u32, c: u32, s: u32, x: Fr| {
        for w in [matrix, c, s] {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out.extend_from_slice(&(x * r2).into_bigint().to_bytes_le());
    };
    for (c, k) in (0u32..).zip(&r1cs.constraints) {
        k.a.iter().for_each(|&(s, x)| push(0, c, s, x));
        k.b.iter().for_each(|&(s, x)| push(1, c, s, x));
    }
    (0..=n_public).for_each(|s| push(0, m + s, s, Fr::from(1u64)));
    Ok(out)
}

/// Section 9: the odd-index points of the Lagrange basis of size 2d.
pub fn h_section(ptau: &Ptau, d: usize) -> Result<Vec<u8>> {
    let basis = ptau.lagrange_tau_g1(2 * d)?;
    Ok(basis
        .chunks_exact(G1_BYTES)
        .skip(1)
        .step_by(2)
        .flatten()
        .copied()
        .collect())
}

/// The genesis points csHash covers, in the order snarkjs writes them.
pub struct KeyPoints {
    /// Section 3: one point per public signal, ONE included.
    pub ic: Vec<G1Affine>,
    /// Section 8 of the genesis (δ = 1): one point per private signal.
    pub c: Vec<G1Affine>,
    /// Section 5.
    pub a: Vec<G1Affine>,
    /// Section 6.
    pub b1: Vec<G1Affine>,
    /// Section 7.
    pub b2: Vec<G2Affine>,
}

/// BLAKE2b-512 over the vk points, then IC, the H-hash points, C, A, B1, B2 (each list prefixed
/// by its u32 big-endian length) exactly as `newZKey` feeds its hasher.
pub fn cs_hash(header: &Groth16Header, points: &KeyPoints, ptau: &Ptau) -> Result<[u8; 64]> {
    let mut h = Blake2b512::new();
    h.update(g1_lem_to_u(&header.alpha1));
    h.update(g1_lem_to_u(&header.beta1));
    h.update(g2_lem_to_u(&header.beta2));
    h.update(g2_uncompressed(&G2Affine::generator()));
    h.update(g1_lem_to_u(&G1Affine::generator()));
    h.update(g2_uncompressed(&G2Affine::generator()));

    let g1_list = |h: &mut Blake2b512, list: &[G1Affine]| -> Result<()> {
        h.update(u32_of(list.len())?.to_be_bytes());
        for p in list {
            h.update(g1_lem_to_u(p));
        }
        Ok(())
    };
    g1_list(&mut h, &points.ic)?;
    let d = header.domain_size as usize;
    h.update(u32_of(d - 1)?.to_be_bytes());
    for p in h_hash_points(ptau, d)? {
        h.update(p);
    }
    g1_list(&mut h, &points.c)?;
    g1_list(&mut h, &points.a)?;
    g1_list(&mut h, &points.b1)?;
    h.update(u32_of(points.b2.len())?.to_be_bytes());
    for p in &points.b2 {
        h.update(g2_lem_to_u(p));
    }
    Ok(h.finalize().into())
}

/// τ^(i+d) − τ^i from section 2 for every i snarkjs reaches. Its chunk loop always reads
/// min(d − 1, CHUNK) points, so for d > CHUNK it hashes d points rather than d − 1, and at
/// d = 2^power the last one is read past the section (see `wasm`).
fn h_hash_points(ptau: &Ptau, d: usize) -> Result<Vec<[u8; 64]>> {
    let per_chunk = (d - 1).min(H_HASH_CHUNK);
    let count = (d - 1).div_ceil(H_HASH_CHUNK) * per_chunk;

    let mut inside = Vec::with_capacity(count);
    let mut outside = Vec::new();
    for i in 0..count {
        let ((hi, in_section), (lo, _)) = (ptau.tau_g1_at(i + d)?, ptau.tau_g1_at(i)?);
        if in_section && outside.is_empty() {
            inside.push(g1_from_lem(hi)?.into_group() - g1_from_lem(lo)?);
        } else {
            match sub_affine(hi, lo) {
                Some((x, y)) => outside.push(xy_be(x, y)),
                None => return invalid("H-hash point has no affine form"),
            }
        }
    }
    let mut points: Vec<[u8; 64]> = G1Projective::normalize_batch(&inside)
        .iter()
        .map(g1_lem_to_u)
        .collect();
    points.extend(outside);
    Ok(points)
}
