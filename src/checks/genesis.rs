//! The genesis is exactly what snarkjs `newZKey` derives from the announced r1cs and ptau.
//!
//! Fixed parts (header, coeffs, H, csHash) are recomputed and compared. Each point of IC, A, B1,
//! B2 and C is a sum of Lagrange-basis points weighted by r1cs coefficients; they are checked
//! with one random linear combination per section: `Σ ρₛ·Pₛ = Σ_c (Σₛ ρₛ·kₛ,c)·L_c`, 128-bit ρ.

use ark_bn254::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::AffineRepr;
use ark_ff::Zero;
use blake2::{Blake2b512, Digest};
use rand::rngs::OsRng;
use rand::Rng;

use super::msm::msm;
use crate::compat::{coeffs_section, cs_hash, domain_size, h_section, KeyPoints};
use crate::error::Result;
use crate::formats::{g1_from_lem, g2_from_lem, section, Ptau, R1cs, Zkey, G1_BYTES, G2_BYTES};
use crate::report::hex;

/// BLAKE2b-512 of `powersOfTau28_hez_final_16.ptau` (Hermez, snarkjs README; SPEC §1.1).
pub const PINNED_PTAU_BLAKE2B: &str = "6a6277a2f74e1073601b4f9fed6e1e55226917efb0f0db8a07d98ab01df1ccf43eb0e8c3159432acd4960e2f29fe84a4198501fa54c8dad9e43297453efec125";

/// Validates in order of cost: ptau pin and layout, then the r1cs bounded by the ptau's power.
pub fn source_problems(genesis: &Zkey, r1cs: &[u8], ptau: &[u8]) -> Vec<String> {
    if hex(&Blake2b512::digest(ptau)) != PINNED_PTAU_BLAKE2B {
        return vec!["ptau is not the pinned powersOfTau28_hez_final_16.ptau".into()];
    }
    let ptau = match Ptau::parse(ptau) {
        Ok(p) => p,
        Err(e) => return vec![format!("ptau: {e}")],
    };
    let r1cs = match R1cs::parse(r1cs, 1 << ptau.power) {
        Ok(r) => r,
        Err(e) => return vec![format!("r1cs: {e}")],
    };
    problems(genesis, &r1cs, &ptau).unwrap_or_else(|e| vec![e.to_string()])
}

fn problems(genesis: &Zkey, r1cs: &R1cs, ptau: &Ptau) -> Result<Vec<String>> {
    let d = domain_size(r1cs)?;
    if d.ilog2() > ptau.power {
        return Ok(vec![format!("domain 2^{} exceeds the ptau", d.ilog2())]);
    }
    let h = &genesis.header;
    if (h.n_vars, h.n_public, h.domain_size as usize) != (r1cs.n_vars, r1cs.n_public(), d) {
        return Ok(vec!["signal counts or domain differ from the r1cs".into()]);
    }

    let mut p = Vec::new();
    if (h.alpha1, h.beta1, h.beta2)
        != (
            g1_from_lem(ptau.alpha1()?)?,
            g1_from_lem(ptau.beta1()?)?,
            g2_from_lem(ptau.beta2()?)?,
        )
    {
        p.push("α/β are not the ptau's".into());
    }
    if h.gamma2 != G2Affine::generator() {
        p.push("γ is not the G2 generator".into());
    }
    if genesis.section_bytes(section::COEFFS)? != coeffs_section(r1cs)? {
        p.push("section coeffs is not derived from the r1cs".into());
    }
    if genesis.section_bytes(section::H)? != h_section(ptau, d)? {
        p.push("section H is not the ptau's".into());
    }

    let points = KeyPoints {
        ic: genesis.g1_points(section::IC)?,
        c: genesis.g1_points(section::L)?,
        a: genesis.g1_points(section::A)?,
        b1: genesis.g1_points(section::B1)?,
        b2: genesis.g2_points(section::B2)?,
    };
    p.extend(sums_problems(&points, r1cs, ptau, d)?);
    if cs_hash(h, &points, ptau)? != genesis.cs_hash {
        p.push("csHash is not the hash of this circuit and ptau".into());
    }
    Ok(p)
}

fn rho(n: usize) -> Vec<Fr> {
    (0..n).map(|_| Fr::from(OsRng.gen::<u128>())).collect()
}

fn g1_basis(bytes: &[u8], n: usize) -> Result<Vec<G1Affine>> {
    bytes
        .chunks_exact(G1_BYTES)
        .take(n)
        .map(g1_from_lem)
        .collect()
}

fn g2_basis(bytes: &[u8], n: usize) -> Result<Vec<G2Affine>> {
    bytes
        .chunks_exact(G2_BYTES)
        .take(n)
        .map(g2_from_lem)
        .collect()
}

/// What `newZKey` sums per signal s, over constraints c with coefficient k:
/// `A[s] = Σ k·τL_c` (A terms), `B1[s] = Σ k·τL_c` and `B2[s] = Σ k·τ₂L_c` (B terms), and
/// `IC‖C[s] = Σ k·βτL_c` (A terms) `+ k·ατL_c` (B terms) `+ k·τL_c` (C terms). Each public s (ONE included)
/// also gets τL and βτL at index m + s.
fn sums_problems(points: &KeyPoints, r1cs: &R1cs, ptau: &Ptau, d: usize) -> Result<Vec<String>> {
    let n_vars = r1cs.n_vars as usize;
    let n_public = r1cs.n_public() as usize;
    let m = r1cs.constraints.len();
    let used = m + n_public + 1;

    // Bases first: the ptau bounds every allocation below.
    let tau = g1_basis(ptau.lagrange_tau_g1(d)?, used)?;
    let tau2 = g2_basis(ptau.lagrange_tau_g2(d)?, used)?;
    let alpha = g1_basis(ptau.lagrange_alpha_tau_g1(d)?, used)?;
    let beta = g1_basis(ptau.lagrange_beta_tau_g1(d)?, used)?;

    let (ra, rb1, rb2, ri) = (rho(n_vars), rho(n_vars), rho(n_vars), rho(n_vars));
    let zero = vec![Fr::zero(); used];
    let (mut wa, mut wb1, mut wb2) = (zero.clone(), zero.clone(), zero.clone());
    let (mut w_tau, mut w_alpha, mut w_beta) = (zero.clone(), zero.clone(), zero);
    for (c, k) in r1cs.constraints.iter().enumerate() {
        for &(s, x) in &k.a {
            wa[c] += ra[s as usize] * x;
            w_beta[c] += ri[s as usize] * x;
        }
        for &(s, x) in &k.b {
            wb1[c] += rb1[s as usize] * x;
            wb2[c] += rb2[s as usize] * x;
            w_alpha[c] += ri[s as usize] * x;
        }
        for &(s, x) in &k.c {
            w_tau[c] += ri[s as usize] * x;
        }
    }
    for s in 0..=n_public {
        wa[m + s] += ra[s];
        w_beta[m + s] += ri[s];
    }

    let g1 = |b: &[G1Affine], w: &[Fr]| msm::<G1Projective>(b, w);
    let g2 = |b: &[G2Affine], w: &[Fr]| msm::<G2Projective>(b, w);
    let sums = [
        ("A", g1(&points.a, &ra)? == g1(&tau, &wa)?),
        ("B1", g1(&points.b1, &rb1)? == g1(&tau, &wb1)?),
        ("B2", g2(&points.b2, &rb2)? == g2(&tau2, &wb2)?),
        (
            "IC/C",
            g1(&points.ic, &ri[..=n_public])? + g1(&points.c, &ri[n_public + 1..])?
                == g1(&tau, &w_tau)? + g1(&alpha, &w_alpha)? + g1(&beta, &w_beta)?,
        ),
    ];
    Ok(sums
        .iter()
        .filter(|(_, ok)| !ok)
        .map(|(name, _)| format!("section {name} is not derived from the r1cs and ptau"))
        .collect())
}
