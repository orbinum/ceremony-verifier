//! Any bytes as a zkey: parsed or refused, never a panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use orbinum_ceremony_verifier::formats::Zkey;

fuzz_target!(|data: &[u8]| {
    let _ = Zkey::parse(data);
});
