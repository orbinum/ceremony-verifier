//! Strict argv: known flags only, each once and with a value; the announced policy is required.

use std::collections::BTreeMap;

use orbinum_ceremony_verifier::compat::{MAX_ITERATIONS_EXP, MIN_ITERATIONS_EXP};

pub const USAGE: &str = "usage: ceremony-verifier --genesis <zkey> --final <zkey> \
    --min-contributions <n> --beacon <hex> --iterations <exp> --r1cs <file> --ptau <file>";

const FLAGS: [&str; 7] = [
    "--genesis",
    "--final",
    "--min-contributions",
    "--beacon",
    "--iterations",
    "--r1cs",
    "--ptau",
];

#[derive(Debug)]
pub struct Args {
    pub genesis: String,
    pub final_: String,
    pub min_contributions: usize,
    pub beacon: Vec<u8>,
    pub iterations: u8,
    /// `--r1cs` and `--ptau`: the genesis is always checked against them.
    pub source: (String, String),
}

pub fn parse(argv: &[String]) -> Result<Args, String> {
    let mut values: BTreeMap<&str, &str> = BTreeMap::new();
    let mut it = argv.iter();
    while let Some(arg) = it.next() {
        let Some(&flag) = FLAGS.iter().find(|f| **f == arg) else {
            return Err(format!("unknown argument {arg}"));
        };
        let value = it
            .next()
            .filter(|v| !v.starts_with("--"))
            .ok_or_else(|| format!("{flag} needs a value"))?;
        if values.insert(flag, value).is_some() {
            return Err(format!("{flag} given more than once"));
        }
    }
    let required = |flag: &str| {
        values
            .get(flag)
            .map(ToString::to_string)
            .ok_or_else(|| format!("missing {flag}"))
    };
    let invalid = |flag: &str| format!("invalid {flag}");

    let beacon = parse_hex(&required("--beacon")?.to_lowercase())
        .filter(|b| (1..=255).contains(&b.len()))
        .ok_or_else(|| invalid("--beacon"))?;
    let source = (required("--r1cs")?, required("--ptau")?);
    Ok(Args {
        genesis: required("--genesis")?,
        final_: required("--final")?,
        min_contributions: number(&required("--min-contributions")?)
            .ok_or_else(|| invalid("--min-contributions"))?,
        beacon,
        iterations: number(&required("--iterations")?)
            .and_then(|n| u8::try_from(n).ok())
            .filter(|n| (MIN_ITERATIONS_EXP..=MAX_ITERATIONS_EXP).contains(n))
            .ok_or_else(|| invalid("--iterations"))?,
        source,
    })
}

/// Decimal digits only: `str::parse` would also take a leading `+`.
fn number(s: &str) -> Option<usize> {
    let digits = !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    digits.then(|| s.parse().ok()).flatten()
}

fn parse_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}
