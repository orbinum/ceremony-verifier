//! Field elements and curve points drawn from the ChaCha stream exactly as ffjavascript does.

use ark_bn254::{g1, g2, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInt, Field, PrimeField, Zero};

use super::chacha::ChaCha;

/// G2 cofactor ffjavascript multiplies by after try-and-increment (bn128.js `cofactorG2`).
const G2_COFACTOR: [u64; 4] = [
    0x345f_2299_c0f9_fa8d,
    0x06ce_ecda_572a_2489,
    0xb850_45b6_8181_585e,
    0x3064_4e72_e131_a029,
];

/// `F.fromRng`: four `nextU64` as little-endian limbs, masked to the modulus bit length, rejected
/// until below the modulus. The value is written directly as the Montgomery representation.
fn limbs_from_rng(rng: &mut ChaCha, modulus: BigInt<4>, bits: u32) -> BigInt<4> {
    loop {
        let mut l = [0u64; 4];
        for limb in &mut l {
            *limb = rng.next_u64();
        }
        let top = bits - 192;
        l[3] &= (1u64 << top) - 1;
        let v = BigInt::new(l);
        if v < modulus {
            return v;
        }
    }
}

/// `Fq.fromRng`: a base-field element.
pub fn fq_from_rng(rng: &mut ChaCha) -> Fq {
    Fq::new_unchecked(limbs_from_rng(rng, Fq::MODULUS, Fq::MODULUS_BIT_SIZE))
}

/// `Fr.fromRng`: a scalar.
pub fn fr_from_rng(rng: &mut ChaCha) -> Fr {
    Fr::new_unchecked(limbs_from_rng(rng, Fr::MODULUS, Fr::MODULUS_BIT_SIZE))
}

/// `F2.fromRng`: c0 then c1.
fn fq2_from_rng(rng: &mut ChaCha) -> Fq2 {
    let c0 = fq_from_rng(rng);
    Fq2::new(c0, fq_from_rng(rng))
}

/// wasmcurves `isNegative`: the canonical value is above (p − 1) / 2.
fn fq_is_negative(x: Fq) -> bool {
    x.into_bigint() > Fq::MODULUS_MINUS_ONE_DIV_TWO
}

/// wasmcurves `f2m_isNegative`: decided by c1, or by c0 when c1 is zero.
fn fq2_is_negative(x: Fq2) -> bool {
    if x.c1.is_zero() {
        fq_is_negative(x.c0)
    } else {
        fq_is_negative(x.c1)
    }
}

/// `G.fromRng`: try-and-increment on x; the root is chosen so that `isNegative(y) == greatest`.
fn point_from_rng<F: Field>(
    rng: &mut ChaCha,
    draw: impl Fn(&mut ChaCha) -> F,
    b: F,
    is_negative: impl Fn(F) -> bool,
) -> (F, F) {
    loop {
        let x = draw(rng);
        let greatest = rng.next_bool();
        if let Some(mut y) = (x.square() * x + b).sqrt() {
            if greatest ^ is_negative(y) {
                y = -y;
            }
            return (x, y);
        }
    }
}

/// `G1.fromRng`: a G1 point (cofactor 1).
pub fn g1_from_rng(rng: &mut ChaCha) -> G1Affine {
    let (x, y) = point_from_rng(rng, fq_from_rng, g1::Config::COEFF_B, fq_is_negative);
    G1Affine::new_unchecked(x, y)
}

/// `G2.fromRng`: a G2 point, cofactor cleared.
pub fn g2_from_rng(rng: &mut ChaCha) -> G2Affine {
    let (x, y) = point_from_rng(rng, fq2_from_rng, g2::Config::COEFF_B, fq2_is_negative);
    G2Affine::new_unchecked(x, y)
        .mul_bigint(G2_COFACTOR)
        .into_affine()
}

/// snarkjs `hashToG2`: seed ChaCha with the first 32 bytes of the hash, draw a G2 point.
pub fn hash_to_g2(hash: &[u8; 64]) -> G2Affine {
    g2_from_rng(&mut ChaCha::from_be_bytes(hash))
}
