//! The MPC transcript and contribution hashes (snarkjs `hashPubKey`, BLAKE2b-512).

use blake2::{Blake2b512, Digest};

use super::encode::{g1_uncompressed, g2_uncompressed};
use crate::formats::MpcEntry;

fn update_pub_key(h: &mut Blake2b512, e: &MpcEntry) {
    h.update(g1_uncompressed(&e.delta_after));
    h.update(g1_uncompressed(&e.g1_s));
    h.update(g1_uncompressed(&e.g1_sx));
    h.update(g2_uncompressed(&e.g2_spx));
    h.update(e.transcript);
}

/// `h_k`: BLAKE2b-512 over (`deltaAfter`, `g1_s`, `g1_sx`, `g2_spx`, transcript).
pub fn contribution_hash(e: &MpcEntry) -> [u8; 64] {
    let mut h = Blake2b512::new();
    update_pub_key(&mut h, e);
    h.finalize().into()
}

/// The running transcript: csHash, then every public key so far. Walking a chain with it is
/// linear in the number of entries.
#[derive(Clone)]
pub struct TranscriptHasher(Blake2b512);

impl TranscriptHasher {
    /// The state before the first entry: csHash only.
    pub fn new(cs_hash: &[u8; 64]) -> Self {
        let mut h = Blake2b512::new();
        h.update(cs_hash);
        Self(h)
    }

    /// The transcript the next entry must carry: the state so far plus its own `g1_s`, `g1_sx`.
    pub fn expected(&self, e: &MpcEntry) -> [u8; 64] {
        let mut h = self.0.clone();
        h.update(g1_uncompressed(&e.g1_s));
        h.update(g1_uncompressed(&e.g1_sx));
        h.finalize().into()
    }

    /// Appends an accepted entry's public key.
    pub fn push(&mut self, e: &MpcEntry) {
        update_pub_key(&mut self.0, e);
    }
}

/// The transcript entry k must carry: csHash, every earlier public key, then its own `g1_s`,
/// `g1_sx`.
pub fn expected_transcript(cs_hash: &[u8; 64], previous: &[MpcEntry], e: &MpcEntry) -> [u8; 64] {
    let mut h = TranscriptHasher::new(cs_hash);
    for p in previous {
        h.push(p);
    }
    h.expected(e)
}
