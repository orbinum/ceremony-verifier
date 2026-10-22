//! Strict readers for the snarkjs and circom binary formats.

mod binfile;
mod field;
mod ptau;
mod r1cs;
mod reader;
mod zkey;

pub use binfile::{Section, SectionTable, MAX_SECTIONS};
pub use field::{
    fq_from_lem, fr_from_lem, g1_from_lem, g2_from_lem, le_bigint, G1_BYTES, G2_BYTES, N8,
};
pub use ptau::Ptau;
pub use r1cs::{Constraint, Lc, R1cs};
pub use reader::ByteReader;
pub use zkey::{
    section, EntryKind, Groth16Header, MpcEntry, Zkey, CONTRIBUTED_ORDER, GENESIS_ORDER,
    MAX_ENTRIES,
};
