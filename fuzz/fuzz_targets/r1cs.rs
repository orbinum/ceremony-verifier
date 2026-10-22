//! Any bytes as an r1cs (up to the 2^16 constraints of the pinned ptau): parsed or refused.
#![no_main]

use libfuzzer_sys::fuzz_target;
use orbinum_ceremony_verifier::formats::R1cs;

fuzz_target!(|data: &[u8]| {
    let _ = R1cs::parse(data, 1 << 16);
});
