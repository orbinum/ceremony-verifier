//! Strict reader for circom `.r1cs` files: header (section 1) and constraints (section 2).

use ark_bn254::Fr;
use ark_ff::PrimeField;

use super::binfile::SectionTable;
use super::field::{le_bigint, N8};
use super::reader::ByteReader;
use crate::error::{format, invalid, Result};

/// A linear combination: (signal, coefficient) in file order, duplicates kept.
pub type Lc = Vec<(u32, Fr)>;

/// One constraint A·B = C.
#[derive(Debug, Clone)]
pub struct Constraint {
    /// A.
    pub a: Lc,
    /// B.
    pub b: Lc,
    /// C.
    pub c: Lc,
}

/// A parsed circuit: what `newZKey` reads from it.
#[derive(Debug)]
pub struct R1cs {
    /// Wires, ONE included (the zkey's nVars).
    pub n_vars: u32,
    /// Public outputs.
    pub n_outputs: u32,
    /// Public inputs.
    pub n_pub_inputs: u32,
    /// Every constraint, in file order.
    pub constraints: Vec<Constraint>,
}

mod section {
    pub const HEADER: u32 = 1;
    pub const CONSTRAINTS: u32 = 2;
    pub const WIRE_TO_LABEL: u32 = 3;
}

/// Smallest encoded constraint: three empty linear combinations.
const MIN_CONSTRAINT: usize = 12;
/// One term: u32 signal + coefficient.
const TERM: usize = 4 + N8;

impl R1cs {
    /// Parses and validates; more than `max_constraints` is refused before any is read.
    pub fn parse(bytes: &[u8], max_constraints: usize) -> Result<Self> {
        let sections = SectionTable::read(bytes, b"r1cs")?;
        // Custom-gate sections (4, 5) are a PLONK feature and never part of a Groth16 circuit.
        if let Some(k) = sections.kinds().find(|k| {
            ![
                section::HEADER,
                section::CONSTRAINTS,
                section::WIRE_TO_LABEL,
            ]
            .contains(k)
        }) {
            return format(format!("unexpected r1cs section {k}"));
        }
        if sections.end != bytes.len() {
            return format("trailing bytes after the last r1cs section");
        }

        let h = sections.unique(section::HEADER)?;
        let mut r = ByteReader::bounded(bytes, h.offset, h.offset + h.size);
        if r.u32()? as usize != N8 || le_bigint(r.take(N8)?) != Fr::MODULUS {
            return format("r1cs prime is not BN254 Fr");
        }
        let n_vars = r.u32()?;
        let n_outputs = r.u32()?;
        let n_pub_inputs = r.u32()?;
        let n_prv_inputs = r.u32()?;
        r.u64()?; // labels
        let n_constraints = r.u32()? as usize;
        if r.remaining() != 0 {
            return format("trailing bytes in the r1cs header");
        }
        let n_public = u64::from(n_outputs) + u64::from(n_pub_inputs);
        if 1 + n_public + u64::from(n_prv_inputs) > u64::from(n_vars) {
            return format("r1cs declares more inputs than signals");
        }
        // circom maps every wire to its label: one u64 per wire.
        if sections.unique(section::WIRE_TO_LABEL)?.size as u64 != 8 * u64::from(n_vars) {
            return format("r1cs wire map is not one entry per wire");
        }

        let s = sections.unique(section::CONSTRAINTS)?;
        let mut r = ByteReader::bounded(bytes, s.offset, s.offset + s.size);
        if n_constraints > max_constraints || n_constraints > r.remaining() / MIN_CONSTRAINT {
            return format(format!("declares {n_constraints} constraints"));
        }
        let mut lc = || read_lc(&mut r, n_vars);
        let constraints = (0..n_constraints)
            .map(|_| {
                Ok(Constraint {
                    a: lc()?,
                    b: lc()?,
                    c: lc()?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if r.remaining() != 0 {
            return format("trailing bytes in the r1cs constraints");
        }
        Ok(Self {
            n_vars,
            n_outputs,
            n_pub_inputs,
            constraints,
        })
    }

    /// Public signals, not counting the constant ONE.
    pub fn n_public(&self) -> u32 {
        self.n_outputs + self.n_pub_inputs
    }
}

fn read_lc(r: &mut ByteReader, n_vars: u32) -> Result<Lc> {
    let n = r.u32()? as usize;
    if n > r.remaining() / TERM {
        return format(format!("linear combination declares {n} terms"));
    }
    (0..n)
        .map(|_| {
            let signal = r.u32()?;
            if signal >= n_vars {
                return invalid(format!("signal {signal} out of range"));
            }
            // Coefficients are plain little-endian integers, not Montgomery.
            match Fr::from_bigint(le_bigint(r.take(N8)?)) {
                Some(k) => Ok((signal, k)),
                None => invalid("r1cs coefficient out of range"),
            }
        })
        .collect()
}
