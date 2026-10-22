//! Strict reader for snarkjs Groth16 zkeys (sections 1–10).

use ark_bn254::{Fq, Fr, G1Affine, G2Affine};
use ark_ff::PrimeField;

use super::binfile::{Section, SectionTable};
use super::field::{g1_from_lem, g2_from_lem, le_bigint, G1_BYTES, G2_BYTES, N8};
use super::reader::ByteReader;
use crate::error::{format, Result};

/// Section ids of a snarkjs Groth16 zkey.
pub mod section {
    /// Protocol (1 = Groth16).
    pub const HEADER: u32 = 1;
    /// Field moduli, sizes and the verification key points.
    pub const GROTH16: u32 = 2;
    /// IC: one G1 point per public signal, ONE included.
    pub const IC: u32 = 3;
    /// The A and B matrix coefficients.
    pub const COEFFS: u32 = 4;
    /// A query (G1).
    pub const A: u32 = 5;
    /// B query in G1.
    pub const B1: u32 = 6;
    /// B query in G2.
    pub const B2: u32 = 7;
    /// L (C over δ): one G1 point per private signal.
    pub const L: u32 = 8;
    /// H over δ: one G1 point per domain element.
    pub const H: u32 = 9;
    /// csHash and the MPC entries.
    pub const MPC: u32 = 10;
}

/// Section 2: the circuit sizes and the verification key points.
#[derive(Debug, Clone, PartialEq)]
pub struct Groth16Header {
    /// Signals, ONE included.
    pub n_vars: u32,
    /// Public signals, ONE excluded.
    pub n_public: u32,
    /// Evaluation domain, a power of two.
    pub domain_size: u32,
    /// α in G1.
    pub alpha1: G1Affine,
    /// β in G1.
    pub beta1: G1Affine,
    /// β in G2.
    pub beta2: G2Affine,
    /// γ in G2 (the generator in snarkjs keys).
    pub gamma2: G2Affine,
    /// δ in G1.
    pub delta1: G1Affine,
    /// δ in G2.
    pub delta2: G2Affine,
}

/// The MPC entry type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A contributor's secret (type 0).
    Contribution,
    /// The public random beacon (type 1).
    Beacon,
}

/// One MPC entry (contribution or beacon) as stored in section 10.
#[derive(Debug, Clone)]
pub struct MpcEntry {
    /// Contribution or beacon.
    pub kind: EntryKind,
    /// δ after this entry, in G1.
    pub delta_after: G1Affine,
    /// Public key: a random point s·G.
    pub g1_s: G1Affine,
    /// Public key: s·x·G, x being the entry's secret.
    pub g1_sx: G1Affine,
    /// Public key: x·`hashToG2(transcript)`.
    pub g2_spx: G2Affine,
    /// BLAKE2b-512 over csHash, every earlier public key, `g1_s` and `g1_sx`.
    pub transcript: [u8; 64],
    /// Contributor name (tag 1), absent when empty.
    pub name: Option<String>,
    /// Beacon only (tag 2): 2^exp SHA-256 iterations over the beacon value.
    pub num_iterations_exp: Option<u8>,
    /// Beacon only (tag 3): the beacon value.
    pub beacon_hash: Option<Vec<u8>>,
}

/// A parsed zkey: header and MPC section decoded, bulk sections borrowed.
#[derive(Debug)]
pub struct Zkey<'a> {
    bytes: &'a [u8],
    sections: SectionTable,
    /// Section 2.
    pub header: Groth16Header,
    /// The circuit hash (section 10).
    pub cs_hash: [u8; 64],
    /// The MPC entries, in chain order.
    pub entries: Vec<MpcEntry>,
}

const SECTION_IDS: [u32; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

/// Section order `newZKey` writes (a genesis), and the order `zkey contribute` and `zkey beacon`
/// write; a final key always comes from `zkey beacon`.
pub const GENESIS_ORDER: [u32; 10] = [1, 2, 4, 3, 9, 8, 5, 6, 7, 10];
/// See [`GENESIS_ORDER`].
pub const CONTRIBUTED_ORDER: [u32; 10] = SECTION_IDS;
/// Far above any real ceremony; bounds the chain walk (pairings per entry).
pub const MAX_ENTRIES: usize = 10_000;
/// Contributor names: printable ASCII, as the coordinator accepts them.
const MAX_NAME: usize = 64;

impl<'a> Zkey<'a> {
    /// Parses and validates the header and MPC sections; the bulk sections are validated on use.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let sections = SectionTable::read(bytes, b"zkey")?;
        if let Some(k) = sections.kinds().find(|k| !SECTION_IDS.contains(k)) {
            return format(format!("unknown section {k}"));
        }
        for id in SECTION_IDS {
            sections.unique(id)?;
        }
        if sections.end != bytes.len() {
            return format(format!(
                "{} bytes after the last section",
                bytes.len() - sections.end
            ));
        }

        let mut r = reader(bytes, sections.unique(section::HEADER)?);
        if r.u32()? != 1 {
            return format("not a Groth16 zkey");
        }
        if r.remaining() != 0 {
            return format("trailing bytes in the zkey header");
        }
        let header = read_groth16_header(&mut reader(bytes, sections.unique(section::GROTH16)?))?;
        let (cs_hash, entries) = read_mpc(&mut reader(bytes, sections.unique(section::MPC)?))?;

        let zkey = Self {
            bytes,
            sections,
            header,
            cs_hash,
            entries,
        };
        zkey.check_sizes()?;
        Ok(zkey)
    }

    /// Section types in file order.
    pub fn order(&self) -> &[u32] {
        &self.sections.order
    }

    /// Raw bytes of a section, for byte-equality comparisons.
    pub fn section_bytes(&self, id: u32) -> Result<&'a [u8]> {
        let s = self.sections.unique(id)?;
        Ok(&self.bytes[s.offset..s.offset + s.size])
    }

    /// The G1 points of a section, each validated.
    pub fn g1_points(&self, id: u32) -> Result<Vec<G1Affine>> {
        self.section_bytes(id)?
            .chunks_exact(G1_BYTES)
            .map(g1_from_lem)
            .collect()
    }

    /// The G2 points of a section, each validated.
    pub fn g2_points(&self, id: u32) -> Result<Vec<G2Affine>> {
        self.section_bytes(id)?
            .chunks_exact(G2_BYTES)
            .map(g2_from_lem)
            .collect()
    }

    fn check_sizes(&self) -> Result<()> {
        let h = &self.header;
        let (n_vars, n_public, domain) = (
            h.n_vars as usize,
            h.n_public as usize,
            h.domain_size as usize,
        );
        if n_public + 1 > n_vars {
            return format("nPublic + 1 exceeds nVars");
        }
        let expected = [
            (section::IC, (n_public + 1) * G1_BYTES),
            (section::A, n_vars * G1_BYTES),
            (section::B1, n_vars * G1_BYTES),
            (section::B2, n_vars * G2_BYTES),
            (section::L, (n_vars - n_public - 1) * G1_BYTES),
            (section::H, domain * G1_BYTES),
        ];
        for (id, size) in expected {
            if self.sections.unique(id)?.size != size {
                return format(format!("section {id} has the wrong size"));
            }
        }
        Ok(())
    }
}

fn reader(bytes: &[u8], s: Section) -> ByteReader<'_> {
    ByteReader::bounded(bytes, s.offset, s.offset + s.size)
}

fn read_groth16_header(r: &mut ByteReader) -> Result<Groth16Header> {
    if r.u32()? as usize != N8 || le_bigint(r.take(N8)?) != Fq::MODULUS {
        return format("base field is not BN254 Fq");
    }
    if r.u32()? as usize != N8 || le_bigint(r.take(N8)?) != Fr::MODULUS {
        return format("scalar field is not BN254 Fr");
    }
    let n_vars = r.u32()?;
    let n_public = r.u32()?;
    let domain_size = r.u32()?;
    if !domain_size.is_power_of_two() {
        return format("domain size is not a power of two");
    }
    let header = Groth16Header {
        n_vars,
        n_public,
        domain_size,
        alpha1: g1_from_lem(r.take(G1_BYTES)?)?,
        beta1: g1_from_lem(r.take(G1_BYTES)?)?,
        beta2: g2_from_lem(r.take(G2_BYTES)?)?,
        gamma2: g2_from_lem(r.take(G2_BYTES)?)?,
        delta1: g1_from_lem(r.take(G1_BYTES)?)?,
        delta2: g2_from_lem(r.take(G2_BYTES)?)?,
    };
    if r.remaining() != 0 {
        return format("trailing bytes in the Groth16 header");
    }
    Ok(header)
}

/// Smallest encoded entry: 3 × G1 + G2 + transcript + type + params length.
const MIN_ENTRY: usize = 3 * G1_BYTES + G2_BYTES + 64 + 8;

fn read_mpc(r: &mut ByteReader) -> Result<([u8; 64], Vec<MpcEntry>)> {
    let mut cs_hash = [0u8; 64];
    cs_hash.copy_from_slice(r.take(64)?);
    let count = r.u32()? as usize;
    if count > MAX_ENTRIES || count > r.remaining() / MIN_ENTRY {
        return format(format!("declares {count} MPC entries"));
    }
    let entries = (0..count)
        .map(|_| read_entry(r))
        .collect::<Result<Vec<_>>>()?;
    if r.remaining() != 0 {
        return format("trailing bytes in the MPC section");
    }
    Ok((cs_hash, entries))
}

fn read_entry(r: &mut ByteReader) -> Result<MpcEntry> {
    let delta_after = g1_from_lem(r.take(G1_BYTES)?)?;
    let g1_s = g1_from_lem(r.take(G1_BYTES)?)?;
    let g1_sx = g1_from_lem(r.take(G1_BYTES)?)?;
    let g2_spx = g2_from_lem(r.take(G2_BYTES)?)?;
    let mut transcript = [0u8; 64];
    transcript.copy_from_slice(r.take(64)?);
    let kind = match r.u32()? {
        0 => EntryKind::Contribution,
        1 => EntryKind::Beacon,
        other => return format(format!("unknown MPC entry type {other}")),
    };

    let mut entry = MpcEntry {
        kind,
        delta_after,
        g1_s,
        g1_sx,
        g2_spx,
        transcript,
        name: None,
        num_iterations_exp: None,
        beacon_hash: None,
    };
    let params_len = r.u32()? as usize;
    let end = r.pos() + params_len;
    let mut last_tag = 0u8;
    while r.pos() < end {
        let tag = r.u8()?;
        if tag <= last_tag {
            return format("MPC parameters not sorted");
        }
        last_tag = tag;
        match tag {
            1 => {
                let len = r.u8()? as usize;
                let name = r.take(len)?;
                if len > MAX_NAME || !name.iter().all(|b| (0x20..0x7f).contains(b)) {
                    return format("contributor name is not printable ASCII of at most 64 bytes");
                }
                entry.name = Some(name.iter().map(|&b| char::from(b)).collect());
            }
            2 => entry.num_iterations_exp = Some(r.u8()?),
            3 => {
                let len = r.u8()? as usize;
                entry.beacon_hash = Some(r.take(len)?.to_vec());
            }
            other => return format(format!("unknown MPC parameter {other}")),
        }
    }
    if r.pos() != end {
        return format("MPC parameter length mismatch");
    }
    // snarkjs writes a name only when non-empty, and the beacon parameters exactly on a beacon.
    let beacon_params = (
        entry.num_iterations_exp.is_some(),
        entry.beacon_hash.is_some(),
    );
    let expected = (kind == EntryKind::Beacon, kind == EntryKind::Beacon);
    if beacon_params != expected || entry.name.as_deref() == Some("") {
        return format("MPC parameters are not the ones snarkjs writes for this entry type");
    }
    Ok(entry)
}
