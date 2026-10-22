//! Independent verifier for the Orbinum Groth16 phase-2 ceremony (SPEC §8.4).
//!
//! Re-checks a final zkey against the pinned genesis with arkworks only: no snarkjs or
//! ffjavascript code. What snarkjs derives deterministically is reproduced in `compat`.

#![forbid(unsafe_code)]

// Offsets and sizes from the inputs are widened to `usize`; a narrower one could truncate them.
#[cfg(not(target_pointer_width = "64"))]
compile_error!("ceremony-verifier supports 64-bit targets only (KNOWN_LIMITS KL-18)");

pub mod checks;
pub mod compat;
pub mod error;
pub mod formats;
pub mod report;
