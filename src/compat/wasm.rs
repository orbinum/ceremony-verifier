//! wasmcurves' BN254 G1 `subAffine` on raw words, for inputs that are not field elements.
//!
//! When the domain is 2^power of the ptau, snarkjs hashes τ^(2d−1) − τ^(d−1) for the csHash, and
//! τ^(2d−1) lies past the end of section 2: its "coordinates" are the next section's header
//! bytes, not reduced mod q. wasmcurves' field add/sub/mul are only modular for reduced inputs,
//! so the result is reproduced with its exact 256-bit integer semantics (`build_f1m.js`).

use ark_bn254::Fq;
use ark_ff::{BigInt, Field, PrimeField};

type Words = [u64; 4];

const Q: Words = Fq::MODULUS.0;

fn from_le(bytes: &[u8]) -> Words {
    let mut w = [0u64; 4];
    for (word, chunk) in w.iter_mut().zip(bytes.chunks_exact(8)) {
        *word = chunk
            .iter()
            .rev()
            .fold(0, |acc, &b| (acc << 8) | u64::from(b));
    }
    w
}

/// x + y mod 2^256, and the carry out.
#[allow(clippy::cast_possible_truncation)] // `as u64` keeps the low word of a u128, by design.
fn int_add(x: &Words, y: &Words) -> (Words, bool) {
    let mut r = [0u64; 4];
    let mut carry = 0u128;
    for i in 0..4 {
        let t = u128::from(x[i]) + u128::from(y[i]) + carry;
        r[i] = t as u64;
        carry = t >> 64;
    }
    (r, carry != 0)
}

/// x − y mod 2^256, and the borrow out.
fn int_sub(x: &Words, y: &Words) -> (Words, bool) {
    let mut r = [0u64; 4];
    let mut borrow = false;
    for i in 0..4 {
        let (d, b1) = x[i].overflowing_sub(y[i]);
        let (d, b2) = d.overflowing_sub(u64::from(borrow));
        r[i] = d;
        borrow = b1 || b2;
    }
    (r, borrow)
}

fn gte(x: &Words, y: &Words) -> bool {
    !int_sub(x, y).1
}

/// `f1m_add`: subtract q on carry or when the sum is ≥ q.
fn add(x: &Words, y: &Words) -> Words {
    let (r, carry) = int_add(x, y);
    if carry || gte(&r, &Q) {
        int_sub(&r, &Q).0
    } else {
        r
    }
}

/// `f1m_sub`: add q on borrow.
fn sub(x: &Words, y: &Words) -> Words {
    let (r, borrow) = int_sub(x, y);
    if borrow {
        int_add(&r, &Q).0
    } else {
        r
    }
}

/// `f1m_mul` (and `f1m_square`): u = (x·y + m·q) / 2^256, then one conditional subtraction of q.
#[allow(clippy::cast_possible_truncation)] // `as u64` keeps the low word of a u128, by design.
fn mul(x: &Words, y: &Words) -> Words {
    let mut t = [0u64; 9];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let v = u128::from(t[i + j]) + u128::from(x[i]) * u128::from(y[j]) + carry;
            t[i + j] = v as u64;
            carry = v >> 64;
        }
        t[i + 4] = carry as u64;
    }
    let inv = neg_q_inv();
    for i in 0..4 {
        let m = t[i].wrapping_mul(inv);
        let mut carry = 0u128;
        for j in 0..4 {
            let v = u128::from(t[i + j]) + u128::from(m) * u128::from(Q[j]) + carry;
            t[i + j] = v as u64;
            carry = v >> 64;
        }
        for k in t.iter_mut().skip(i + 4) {
            let v = u128::from(*k) + carry;
            *k = v as u64;
            carry = v >> 64;
        }
    }
    let u = [t[4], t[5], t[6], t[7]];
    if t[8] != 0 || gte(&u, &Q) {
        int_sub(&u, &Q).0
    } else {
        u
    }
}

/// −q⁻¹ mod 2^64 by Newton iteration.
fn neg_q_inv() -> u64 {
    let mut inv = 1u64;
    for _ in 0..6 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(Q[0].wrapping_mul(inv)));
    }
    inv.wrapping_neg()
}

/// The field element a Montgomery word stands for, whatever its size: w·R⁻¹ mod q.
fn element(mut w: Words) -> Fq {
    while gte(&w, &Q) {
        w = int_sub(&w, &Q).0;
    }
    Fq::new_unchecked(BigInt::new(w))
}

/// `g1m_subAffine(p1, p2)` then `batchToAffine`: affine (x, y) of p1 − p2, both given as raw
/// Montgomery-LE x‖y. After the addition formula every step is modular, so plain field math.
/// `None` when the result has no affine form (z ≡ 0).
pub fn sub_affine(p1: &[u8], p2: &[u8]) -> Option<(Fq, Fq)> {
    let (x1, y1) = (from_le(&p1[..32]), from_le(&p1[32..64]));
    let (x2, y2) = (from_le(&p2[..32]), sub(&[0; 4], &from_le(&p2[32..64])));
    // `g1m_addAffine` (mmadd-2007-bl), step by step as wasmcurves writes it.
    let h = sub(&x2, &x1);
    let dy = sub(&y2, &y1);
    let hh = mul(&h, &h);
    let i = add(&hh, &hh);
    let i = add(&i, &i);
    let j = mul(&h, &i);
    let r = add(&dy, &dy);
    let v = mul(&x1, &i);
    let r2 = mul(&r, &r);
    let v2 = add(&v, &v);
    let x3 = sub(&sub(&r2, &j), &v2);
    let y1j = mul(&y1, &j);
    let y1j2 = add(&y1j, &y1j);
    let y3 = sub(&mul(&sub(&v, &x3), &r), &y1j2);
    let z3 = add(&h, &h);

    let z_inv = element(z3).inverse()?;
    let z_inv2 = z_inv.square();
    Some((element(x3) * z_inv2, element(y3) * z_inv2 * z_inv))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fr, G1Affine};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::{BigInteger, UniformRand};

    fn lem(p: &G1Affine) -> Vec<u8> {
        let (x, y) = p.xy().unwrap();
        [x.0 .0, y.0 .0]
            .iter()
            .flat_map(|w| w.iter().flat_map(|l| l.to_le_bytes()))
            .collect()
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn is_ordinary_subtraction_for_curve_points() {
        let mut rng = rand::rngs::OsRng;
        for _ in 0..32 {
            let g = G1Affine::generator();
            let (a, b) = (
                (g * Fr::rand(&mut rng)).into_affine(),
                (g * Fr::rand(&mut rng)).into_affine(),
            );
            let expected = (a.into_group() - b).into_affine();
            assert_eq!(sub_affine(&lem(&a), &lem(&b)), expected.xy());
        }
    }

    /// The point snarkjs reads past section 2 of the power-16 ptau (section 3's header and first
    /// bytes) minus τ^65535; the expected value reproduces the transfer genesis csHash.
    #[test]
    fn reproduces_the_over_read_point_of_a_power_16_ptau() {
        let past = hex("0300000000008000000000002620bc02d1b5838e72017b493519ebdcdf1a81974726b8fb3b5096af4138571940614ca87d73b4afc4d802585add4360862fa052");
        let tau = hex("c898f9868f3d93891989fd98ef1dff901175fa997a48ad2a95513ab76fa424105cb43fb00de0d092fdac0598f7fba4f42c330e2d6d40972d08c33ede529eb812");
        let (x, y) = sub_affine(&past, &tau).unwrap();
        assert_eq!(
            [x, y].map(|c| c.into_bigint().to_bytes_be()).concat(),
            hex("10bf9ed16da4baa4730cbb1cf7020e6591c3b4889b940336b99c7fe02af5b63313a57969690742290a82d474e2f505222870cc4cb985dcb9caad78295e1be24f")
        );
    }
}
