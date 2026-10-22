//! ceremony-verifier --genesis <zkey> --final <zkey> --min-contributions <n>
//!                            --beacon <hex> --iterations <exp> --r1cs <file> --ptau <file>
//!
//! Prints the JSON verdict; exits 1 when any check fails, 2 on bad usage, unreadable input or
//! an unwritable verdict.

#![forbid(unsafe_code)]

mod cli;

use std::env;
use std::io::{self, Write};
use std::process::ExitCode;

use orbinum_ceremony_verifier::checks::{verify, Expectations, Source};

fn main() -> ExitCode {
    let utf8: Option<Vec<String>> = env::args_os()
        .skip(1)
        .map(|a| a.into_string().ok())
        .collect();
    let args = match utf8
        .ok_or_else(|| "arguments must be UTF-8".to_string())
        .and_then(|raw| cli::parse(&raw))
    {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{e}\n{}", cli::USAGE);
            return ExitCode::from(2);
        }
    };
    let inputs = (|| {
        let (r1cs, ptau) = &args.source;
        let source = Some(Source {
            r1cs: cli::read(r1cs)?,
            ptau: cli::read(ptau)?,
        });
        Ok::<_, String>((cli::read(&args.genesis)?, cli::read(&args.final_)?, source))
    })();
    let (genesis, final_, source) = match inputs {
        Ok(inputs) => inputs,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let verdict = verify(
        &genesis,
        &final_,
        &Expectations {
            min_contributions: args.min_contributions,
            beacon: Some((args.beacon, args.iterations)),
            source,
        },
    );
    let written = serde_json::to_string_pretty(&verdict)
        .map_err(io::Error::from)
        .and_then(|json| writeln!(io::stdout().lock(), "{json}"));
    if let Err(e) = written {
        eprintln!("cannot write the verdict: {e}");
        return ExitCode::from(2);
    }
    if verdict.ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
