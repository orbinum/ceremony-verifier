//! Hostile argv and input edge cases beyond `args.rs`. Every one is a usage or input error
//! (exit 2, nothing on stdout), except where noted as accepted by design.

// Tests and their helpers fail by panicking.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../support/mod.rs"]
mod support;

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;
use std::process::Command;

use support::{fixture_path, BEACON};

const BIN: &str = env!("CARGO_BIN_EXE_ceremony-verifier");

fn path(name: &str) -> String {
    fixture_path(name).to_string_lossy().into_owned()
}

/// Every flag, honest fixtures; the r1cs stands in for the ptau (input errors come first).
fn base() -> Vec<String> {
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
        &path("multiplier.r1cs"),
    ]
    .map(String::from)
    .to_vec()
}

fn run(args: &[String]) -> (i32, String, String) {
    let out = Command::new(BIN).args(args).output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn with(flag: &str, value: &str) -> Vec<String> {
    let mut a = base();
    let i = a.iter().position(|x| x == flag).unwrap();
    a[i + 1] = value.into();
    a
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("orbinum-hostile-cli-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

#[test]
fn refuses_ambiguous_values() {
    let long_hex = "ab".repeat(256);
    let max_hex = "ab".repeat(255);
    let cases: Vec<Vec<String>> = vec![
        with("--min-contributions", "18446744073709551616"),
        with("--min-contributions", "-1"),
        with("--min-contributions", " 2"),
        with("--min-contributions", "2 "),
        with("--min-contributions", "0x2"),
        with("--min-contributions", ""),
        with("--min-contributions", "２"),
        with("--iterations", "256"),
        with("--iterations", "4294967306"),
        with("--iterations", ""),
        with("--beacon", ""),
        with("--beacon", "abc"),
        with("--beacon", "0xab"),
        with("--beacon", &long_hex),
        with("--beacon", "ａｂ"),
        with("--genesis", "--final"),
        {
            let mut a = base();
            a[0] = "--genesis=x".into();
            a
        },
        {
            let mut a = base();
            a.insert(0, "-h".into());
            a
        },
        {
            let mut a = base();
            a.insert(0, String::new());
            a
        },
        {
            let mut a = base();
            a.pop();
            a
        },
        vec![],
    ];
    for args in cases {
        let (code, stdout, err) = run(&args);
        assert_eq!(code, 2, "{args:?}: {err}");
        assert!(stdout.is_empty(), "{args:?}: stdout {stdout}");
    }
    // 255 bytes of beacon and leading zeros are accepted by argv (the verdict decides).
    assert_ne!(run(&with("--beacon", &max_hex)).0, 2);
    assert_ne!(run(&with("--iterations", "0010")).0, 2);
}

#[test]
fn refuses_non_regular_and_unreadable_inputs() {
    let dir = scratch("a-directory");
    fs::create_dir_all(&dir).unwrap();
    let unreadable = scratch("unreadable.zkey");
    fs::copy(fixture_path("multiplier_final.zkey"), &unreadable).unwrap();
    fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).unwrap();
    let missing = scratch("missing.zkey");
    for p in [
        dir.to_string_lossy().into_owned(),
        "/dev/null".into(),
        "/dev/zero".into(),
        "/dev/random".into(),
        unreadable.to_string_lossy().into_owned(),
        missing.to_string_lossy().into_owned(),
    ] {
        for flag in ["--genesis", "--final", "--r1cs", "--ptau"] {
            let (code, stdout, err) = run(&with(flag, &p));
            assert_eq!(code, 2, "{flag} {p}: {err}");
            assert!(stdout.is_empty());
        }
    }
    let _ = fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o600));
    let _ = fs::remove_file(unreadable);
}

/// `O_NOFOLLOW` covers the last path component only: a symlinked parent directory is followed.
/// Accepted (exit ≠ 2); the CLI passes private staged copies, so this is informational.
#[test]
fn follows_a_symlinked_parent_directory() {
    let link = scratch("fixtures-link");
    let _ = fs::remove_file(&link);
    symlink(fixture_path(""), &link).unwrap();
    let through = link.join("multiplier_final.zkey");
    let (code, _, err) = run(&with("--final", &through.to_string_lossy()));
    let _ = fs::remove_file(&link);
    assert_ne!(code, 2, "{err}");
}
