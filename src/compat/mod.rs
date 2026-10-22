//! Exact reproductions of what snarkjs derives deterministically, written from its behaviour
//! (not its code): ChaCha stream, `fromRng`, `hashToG2`, transcript, beacon key and the fixed
//! parts of the genesis.

mod beacon;
mod chacha;
mod encode;
mod genesis;
mod rng;
mod transcript;
mod wasm;

pub use beacon::{beacon_key, MAX_ITERATIONS_EXP, MIN_ITERATIONS_EXP};
pub use chacha::ChaCha;
pub use encode::{g1_uncompressed, g2_uncompressed};
pub use genesis::{coeffs_section, cs_hash, domain_size, h_section, KeyPoints};
pub use rng::{fq_from_rng, fr_from_rng, g1_from_rng, g2_from_rng, hash_to_g2};
pub use transcript::{contribution_hash, expected_transcript, TranscriptHasher};
