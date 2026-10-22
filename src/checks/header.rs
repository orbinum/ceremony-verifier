//! What phase 2 must not change: the circuit-dependent parts of the key (δ-free).

use ark_bn254::{G1Affine, G2Affine};
use ark_ec::AffineRepr;

use crate::formats::{section, Zkey};

/// The genesis is phase 2's starting point: δ = 1, γ = the generator and no MPC entry.
pub fn genesis_problems(genesis: &Zkey) -> Vec<String> {
    let mut p = Vec::new();
    if !genesis.entries.is_empty() {
        p.push("genesis already has MPC entries".into());
    }
    if genesis.header.delta1 != G1Affine::generator()
        || genesis.header.delta2 != G2Affine::generator()
    {
        p.push("genesis δ is not 1".into());
    }
    if genesis.header.gamma2 != G2Affine::generator() {
        p.push("genesis γ is not the G2 generator".into());
    }
    p
}

/// Same circuit, same α/β/γ, and sections IC, coeffs, A, B1, B2 byte-identical to the genesis.
pub fn unchanged_problems(genesis: &Zkey, final_: &Zkey) -> Vec<String> {
    let (g, f) = (&genesis.header, &final_.header);
    let mut p = Vec::new();
    if genesis.cs_hash != final_.cs_hash {
        p.push("csHash differs: another circuit".into());
    }
    if (g.n_vars, g.n_public, g.domain_size) != (f.n_vars, f.n_public, f.domain_size) {
        p.push("circuit sizes differ".into());
    }
    if (g.alpha1, g.beta1) != (f.alpha1, f.beta1) || (g.beta2, g.gamma2) != (f.beta2, f.gamma2) {
        p.push("α/β/γ differ".into());
    }
    for (id, name) in [
        (section::IC, "IC"),
        (section::COEFFS, "coeffs"),
        (section::A, "A"),
        (section::B1, "B1"),
        (section::B2, "B2"),
    ] {
        match (genesis.section_bytes(id), final_.section_bytes(id)) {
            (Ok(a), Ok(b)) if a == b => {}
            _ => p.push(format!("section {name} differs from the genesis")),
        }
    }
    p
}
