# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-21

### Added

- **Independent verifier for the Orbinum Groth16 phase-2 ceremony** (`ceremony-verifier`):
  Rust + arkworks 0.5, no code shared with snarkjs, ffjavascript or `groth16-proofs`. It prints
  a JSON verdict with every check and the `h_k` of each MPC entry; exit 0 (every check passed),
  1 (a check failed) or 2 (bad usage, unreadable input).
- **Stage A:** a final zkey against its pinned genesis. The checks are `well-formed`,
  `genesis-start`, `unchanged`, `policy`, `chain`, `final-delta` and `scaled-sections`.
- **Stage B:** the genesis re-derived from the r1cs and the pinned Hermez
  `powersOfTau28_hez_final_16.ptau` (`genesis-source`, csHash included), reproducing snarkjs's
  H-hash over-read past ptau section 2.
- **Hardening:**
  - strict argv with every flag required;
  - inputs opened with `O_NOFOLLOW | O_NONBLOCK` and read with a 128 MiB cap;
  - stable check ids, all of them always reported;
  - bounded cost (≤ 10,000 entries, linear transcript, early stop);
  - one encoding per key, stricter than snarkjs;
  - no repeated δ along the chain (no-op and cancelling contributions);
  - no `unsafe`, `unwrap`, `expect` or `panic` outside tests, and library accessors refuse
    out-of-contract arguments;
  - 64-bit Unix targets only, enforced at compile time;
  - release builds fail closed on overflow (panic, exit 101).
- **Tests**, grouped by concern under `tests/`: snarkjs oracle fixtures, Stage A attacks and
  Stage B against the pinned ptau (`verifier/`); the binary's argv and inputs (`cli/`);
  every-byte robustness and hostile mutations of the real rehearsal keys, r1cs and ptau
  (`hostile/`). Coverage-guided fuzz targets for the zkey, r1cs and ptau readers (`fuzz/`,
  `make fuzz`).
- **Test inputs** downloaded and checked against pins (`make ptau`, `make vectors`,
  `scripts/fetch.sh`) from this repo's `test-vectors-1` release: the Hermez ptau (whose original
  hosts answer 403 since September 2026) and the testnet-rehearsal-1 ceremony with its whole
  chain (genesis, contributions, finals, vk.json, r1cs, transcript), packed reproducibly by
  `scripts/pack-vectors.py`; the ceremony repo's attack suites use the same archive.
- **Tooling:** `Makefile` (`check`, `test-full` with required inputs, `release` with the build
  machine's paths remapped out of the binary), pinned toolchain, `rustfmt.toml`, `[lints]`,
  `clippy.toml`, `deny.toml`.
- **CI** on every push to `main` and pull request into `main`: fmt, clippy, docs, every test with
  every input, `cargo audit`, `cargo deny` and a secrets scan; every action pinned by commit,
  read-only tokens, pinned `ubuntu-24.04` runner images.
- **Releases** on a push to `main` that changes `Cargo.toml`: only a new version with its dated
  CHANGELOG section, after CI passes on that commit (a passed CI run of the same commit is
  reused). Linux and macOS binaries built without cache on pinned runner images, a `vX.Y.Z` tag,
  and a GitHub release with the CHANGELOG section, `Cargo.lock`, SHA-256 checksums and signed
  build provenance.
- **Docs:** `README.md`, `docs/USAGE.md`, `docs/ARCHITECTURE.md`, `docs/DEVELOPMENT.md`.
