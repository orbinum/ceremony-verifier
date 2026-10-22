//! The binary's argument and input handling: anything ambiguous is refused with exit 2.

// Tests and their helpers fail by panicking; fixture sizes always fit u32.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

#[path = "../support/mod.rs"]
mod support;

use std::fs::{self, File};
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::process::Command;

use support::{env_input, fixture_path, BEACON};

const BIN: &str = env!("CARGO_BIN_EXE_ceremony-verifier");

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(BIN).args(args).output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn path(name: &str) -> String {
    fixture_path(name).to_string_lossy().into_owned()
}

/// The pinned ptau when available; argument and input errors are found before it is read.
fn ptau() -> Option<String> {
    env_input("ORBINUM_PTAU")
}

/// Every required flag, for the honest fixtures.
fn base() -> Vec<String> {
    let ptau = ptau().unwrap_or_else(|| path("multiplier.r1cs"));
    [
        "--genesis",
        &path("multiplier_0.zkey"),
        "--final",
        &path("multiplier_final.zkey"),
        "--min-contributions",
        "2",
        "--beacon",
        BEACON,
        "--iterations",
        "10",
        "--r1cs",
        &path("multiplier.r1cs"),
        "--ptau",
        &ptau,
    ]
    .map(String::from)
    .to_vec()
}

fn run_with(edit: impl FnOnce(&mut Vec<String>)) -> (i32, String) {
    let mut args = base();
    edit(&mut args);
    run(&args.iter().map(String::as_str).collect::<Vec<_>>())
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("orbinum-verify-rs-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let p = dir.join(name);
    let _ = fs::remove_file(&p);
    p
}

#[test]
fn accepts_the_honest_fixtures() {
    if ptau().is_none() {
        return;
    }
    assert_eq!(run_with(|_| {}).0, 0);
}

/// A closed stdout is an error (exit 2), not a panic.
#[test]
fn reports_a_closed_stdout_as_an_error() {
    if ptau().is_none() {
        return;
    }
    let mut child = Command::new(BIN)
        .args(base())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    assert_eq!(child.wait().unwrap().code(), Some(2));
}

#[test]
fn refuses_a_misspelled_flag() {
    let (code, err) = run_with(|a| a.extend(["--min-contribution".into(), "50".into()]));
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("--min-contribution"), "{err}");
}

#[test]
fn refuses_a_duplicated_flag() {
    let (code, _) = run_with(|a| a.extend(["--final".into(), path("multiplier_1.zkey")]));
    assert_eq!(code, 2);
}

#[test]
fn refuses_a_flag_used_as_a_value_and_positional_arguments() {
    assert_eq!(run_with(|a| a[1] = "--final".into()).0, 2);
    assert_eq!(run_with(|a| a.push("extra".into())).0, 2);
}

#[test]
fn requires_the_announced_policy_and_the_genesis_source() {
    for flag in [
        "--min-contributions",
        "--beacon",
        "--iterations",
        "--r1cs",
        "--ptau",
    ] {
        let (code, err) = run_with(|a| {
            let i = a.iter().position(|x| x == flag).unwrap();
            a.drain(i..i + 2);
        });
        assert_eq!(code, 2, "{flag}: {err}");
    }
    let (code, err) = run_with(|a| a.truncate(10));
    assert_eq!(code, 2, "without --r1cs and --ptau: {err}");
}

#[test]
fn refuses_signs_and_out_of_range_numbers() {
    let set = |flag: &'static str, value: &'static str| {
        move |a: &mut Vec<String>| {
            let i = a.iter().position(|x| x == flag).unwrap();
            a[i + 1] = value.into();
        }
    };
    for (flag, value) in [
        ("--min-contributions", "+2"),
        ("--iterations", "+10"),
        ("--iterations", "9"),
        ("--iterations", "25"),
        ("--beacon", "+1+2+3+4"),
    ] {
        let (code, err) = run_with(set(flag, value));
        assert_eq!(code, 2, "{flag} {value}: {err}");
    }
}

#[test]
fn refuses_non_utf8_arguments_as_usage_errors() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let out = Command::new(BIN)
        .args([OsStr::new("--genesis"), OsStr::from_bytes(b"\xff")])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn refuses_symlinks_fifos_and_oversized_files() {
    let link = scratch("link.zkey");
    symlink(fixture_path("multiplier_final.zkey"), &link).unwrap();
    let fifo = scratch("fifo.zkey");
    assert!(Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    let big = scratch("big.zkey");
    File::create(&big)
        .unwrap()
        .set_len(129 * 1024 * 1024)
        .unwrap();
    for p in [&link, &fifo, &big] {
        let p = p.to_string_lossy().into_owned();
        let (code, err) = run_with(|a| a[3] = p.clone());
        assert_eq!(code, 2, "{p}: {err}");
    }
    for p in [link, fifo, big] {
        let _ = fs::remove_file(p);
    }
}
