//! Reader for prepared snarkjs `.ptau` files (phase 1 with Lagrange sections 12–15).
//!
//! Only what phase 2's genesis reads is exposed, as raw Montgomery-LE bytes. Section sizes are
//! checked against the declared power; the file itself is pinned by hash in `checks::genesis`.

use ark_bn254::Fq;
use ark_ff::PrimeField;

use super::binfile::{Section, SectionTable};
use super::field::{le_bigint, G1_BYTES, G2_BYTES, N8};
use super::reader::ByteReader;
use crate::error::{format, Result};

mod section {
    pub const HEADER: u32 = 1;
    pub const TAU_G1: u32 = 2;
    pub const TAU_G2: u32 = 3;
    pub const ALPHA_TAU_G1: u32 = 4;
    pub const BETA_TAU_G1: u32 = 5;
    pub const BETA_G2: u32 = 6;
    pub const LAGRANGE_TAU_G1: u32 = 12;
    pub const LAGRANGE_TAU_G2: u32 = 13;
    pub const LAGRANGE_ALPHA_TAU_G1: u32 = 14;
    pub const LAGRANGE_BETA_TAU_G1: u32 = 15;
}

/// A parsed ptau: the header's power and the sections the genesis reads, borrowed.
#[derive(Debug)]
pub struct Ptau<'a> {
    bytes: &'a [u8],
    sections: SectionTable,
    /// Phase 1 supports domains up to 2^power.
    pub power: u32,
}

impl<'a> Ptau<'a> {
    /// Reads the header and checks every section size against the declared power.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let sections = SectionTable::read(bytes, b"ptau")?;
        let h = sections.unique(section::HEADER)?;
        let mut r = ByteReader::bounded(bytes, h.offset, h.offset + h.size);
        if r.u32()? as usize != N8 || le_bigint(r.take(N8)?) != Fq::MODULUS {
            return format("ptau base field is not BN254 Fq");
        }
        let power = r.u32()?;
        if !(1..=28).contains(&power) {
            return format(format!("ptau power {power}"));
        }
        // Prepared phase 2: τ in G1 up to 2n − 2, Lagrange bases for every size up to 2n (G1 τ)
        // or n (the rest), where n = 2^power.
        let n = 1usize << power;
        let expected = [
            (section::TAU_G1, (2 * n - 1) * G1_BYTES),
            (section::TAU_G2, n * G2_BYTES),
            (section::ALPHA_TAU_G1, n * G1_BYTES),
            (section::BETA_TAU_G1, n * G1_BYTES),
            (section::BETA_G2, G2_BYTES),
            (section::LAGRANGE_TAU_G1, (4 * n - 1) * G1_BYTES),
            (section::LAGRANGE_TAU_G2, (2 * n - 1) * G2_BYTES),
            (section::LAGRANGE_ALPHA_TAU_G1, (2 * n - 1) * G1_BYTES),
            (section::LAGRANGE_BETA_TAU_G1, (2 * n - 1) * G1_BYTES),
        ];
        for (id, size) in expected {
            if sections.unique(id)?.size != size {
                return format(format!("ptau section {id} does not match power {power}"));
            }
        }
        Ok(Self {
            bytes,
            sections,
            power,
        })
    }

    /// α·τ⁰ in G1.
    pub fn alpha1(&self) -> Result<&'a [u8]> {
        self.slice(section::ALPHA_TAU_G1, 0, G1_BYTES)
    }

    /// β·τ⁰ in G1.
    pub fn beta1(&self) -> Result<&'a [u8]> {
        self.slice(section::BETA_TAU_G1, 0, G1_BYTES)
    }

    /// β in G2.
    pub fn beta2(&self) -> Result<&'a [u8]> {
        self.slice(section::BETA_G2, 0, G2_BYTES)
    }

    /// Lagrange basis of size `domain` in G1: section 12 stores every power of two in turn.
    pub fn lagrange_tau_g1(&self, domain: usize) -> Result<&'a [u8]> {
        self.lagrange(section::LAGRANGE_TAU_G1, G1_BYTES, domain)
    }

    /// Lagrange basis of size `domain` in G2 (section 13).
    pub fn lagrange_tau_g2(&self, domain: usize) -> Result<&'a [u8]> {
        self.lagrange(section::LAGRANGE_TAU_G2, G2_BYTES, domain)
    }

    /// Lagrange basis of size `domain` for α·τ in G1 (section 14).
    pub fn lagrange_alpha_tau_g1(&self, domain: usize) -> Result<&'a [u8]> {
        self.lagrange(section::LAGRANGE_ALPHA_TAU_G1, G1_BYTES, domain)
    }

    /// Lagrange basis of size `domain` for β·τ in G1 (section 15).
    pub fn lagrange_beta_tau_g1(&self, domain: usize) -> Result<&'a [u8]> {
        self.lagrange(section::LAGRANGE_BETA_TAU_G1, G1_BYTES, domain)
    }

    /// The 64 bytes where τⁱ·G1 would be, read like snarkjs does: by file offset, possibly past
    /// the end of section 2. The flag says whether they are inside the section (a real point).
    pub fn tau_g1_at(&self, i: usize) -> Result<(&'a [u8], bool)> {
        let s = self.sections.unique(section::TAU_G1)?;
        let start = i
            .checked_mul(G1_BYTES)
            .and_then(|o| o.checked_add(s.offset));
        match start {
            Some(start)
                if start
                    .checked_add(G1_BYTES)
                    .is_some_and(|end| end <= self.bytes.len()) =>
            {
                Ok((
                    &self.bytes[start..start + G1_BYTES],
                    start + G1_BYTES <= s.offset + s.size,
                ))
            }
            _ => format(format!("τ^{i} lies outside the ptau file")),
        }
    }

    fn lagrange(&self, id: u32, point: usize, domain: usize) -> Result<&'a [u8]> {
        let start = domain.checked_sub(1).and_then(|d| d.checked_mul(point));
        match (start, domain.checked_mul(point)) {
            (Some(start), Some(len)) if domain > 0 => self.slice(id, start, len),
            _ => format(format!("no Lagrange basis of size {domain}")),
        }
    }

    fn slice(&self, id: u32, start: usize, len: usize) -> Result<&'a [u8]> {
        let Section { offset, size } = self.sections.unique(id)?;
        match start.checked_add(len) {
            Some(end) if end <= size => Ok(&self.bytes[offset + start..offset + end]),
            _ => format(format!("ptau section {id} is too small")),
        }
    }
}
