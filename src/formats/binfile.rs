use std::collections::BTreeMap;

use super::reader::ByteReader;
use crate::error::{format, Result};

/// Real zkeys have 10 sections; a larger header is hostile and refused before the table is read.
pub const MAX_SECTIONS: u32 = 32;
/// The only binfile version snarkjs and circom write for zkey, ptau and r1cs.
const VERSION: u32 = 1;

/// Where a section's data lies in the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Section {
    /// First byte of the data, after the section header.
    pub offset: usize,
    /// Data length in bytes.
    pub size: usize,
}

/// The iden3 binfile container: magic, u32 version, u32 count, then (u32 type, u64 size, data).
#[derive(Debug)]
pub struct SectionTable {
    sections: BTreeMap<u32, Vec<Section>>,
    /// Section types in file order.
    pub order: Vec<u32>,
    /// Offset just past the last section.
    pub end: usize,
}

impl SectionTable {
    /// Reads the table, refusing another magic, a version other than 1, more than
    /// [`MAX_SECTIONS`] sections, or a section past the end of the file.
    pub fn read(bytes: &[u8], magic: &[u8; 4]) -> Result<Self> {
        let mut r = ByteReader::new(bytes);
        if r.take(4)? != magic {
            return format(format!(
                "bad magic, expected {:?}",
                String::from_utf8_lossy(magic)
            ));
        }
        let version = r.u32()?;
        if version != VERSION {
            return format(format!("binfile version {version}, expected {VERSION}"));
        }
        let count = r.u32()?;
        if count > MAX_SECTIONS {
            return format(format!("{count} sections, at most {MAX_SECTIONS}"));
        }
        let mut sections: BTreeMap<u32, Vec<Section>> = BTreeMap::new();
        let mut order = Vec::new();
        for _ in 0..count {
            let kind = r.u32()?;
            let size = usize::try_from(r.u64()?)
                .map_err(|_| crate::error::Error::Format("section too large".into()))?;
            let offset = r.pos();
            r.take(size)?;
            sections
                .entry(kind)
                .or_default()
                .push(Section { offset, size });
            order.push(kind);
        }
        Ok(Self {
            sections,
            order,
            end: r.pos(),
        })
    }

    /// The only section of this type; none or several is an error.
    pub fn unique(&self, kind: u32) -> Result<Section> {
        match self.sections.get(&kind).map(Vec::as_slice) {
            Some([one]) => Ok(*one),
            other => format(format!(
                "expected one section {kind}, found {}",
                other.map_or(0, <[_]>::len)
            )),
        }
    }

    /// The section types present, ascending.
    pub fn kinds(&self) -> impl Iterator<Item = &u32> {
        self.sections.keys()
    }
}
