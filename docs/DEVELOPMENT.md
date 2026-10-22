# Development

## Commands

`make` on its own lists them. All cargo commands use `--locked`.

| Target                        | Runs                                                                            | When                                                                                 |
| ----------------------------- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `make check` | `fmt-check` + `lint` + `test` | The fast loop while working; the Stage B and real-key tests skip without their inputs |
| `make test-full` | Every test in release, the pinned ptau and rehearsal keys **required** (fetched if missing) | Before a pull request; CI runs it on every change |
| `make fmt` / `make fmt-check` | rustfmt                                                                         |                                                                                      |
| `make lint`                   | clippy on every target, warnings as errors                                      |                                                                                      |
| `make test`                   | Tests; the ptau and real-key ones skip themselves without their inputs          |                                                                                      |
| `make release`                | The binary used by the CLI                                                      |                                                                                      |
| `make doc`                    | API docs (`target/doc`)                                                         |                                                                                      |
| `make ptau` / `make vectors` | Download and check the test inputs (see below) | `make test-full` calls them |
| `make fuzz` | Coverage-guided fuzzing of one reader: `FUZZ_TARGET=zkey\|r1cs\|ptau`, `FUZZ_SECONDS` (default 300) | Needs a nightly toolchain and `cargo install cargo-fuzz`; not part of CI |

### Test inputs

`make test-full` never assumes files on this machine. It fetches its inputs into this checkout (gitignored), from this repo's [`test-vectors-1`](https://github.com/orbinum/ceremony-verifier/releases/tag/test-vectors-1) release, and checks each against a pin in the `Makefile` before using it (`scripts/fetch.sh`):

| Input | Fetched to | Pin | Used by |
|---|---|---|---|
| `powersOfTau28_hez_final_16.ptau` (Hermez phase 1) | `ptau/pot16_final.ptau` | BLAKE2b-512, the one the binary enforces and snarkjs's README publishes | Stage B (`tests/verifier/genesis.rs`, `tests/cli/args.rs`) |
| `testnet-rehearsal-1.tar.gz`: the testnet-rehearsal-1 ceremony with its whole chain — genesis, contributions, finals with their `vk.json`, and r1cs of shield, unshield and transfer, with its `ceremony.json`, `genesis/init.json` and `transcript.json` | `vectors/testnet-rehearsal-1/` | SHA-256 of the archive | Real-key tests (and the ceremony repo's attack suites) |

- A cached input with the right digest is not downloaded again. A download with the wrong digest is refused and nothing is left in place.
- Point `ORBINUM_PTAU` or `ORBINUM_REHEARSAL_DIR` at local copies to skip a fetch.
- `ORBINUM_REQUIRE_INPUTS` turns a missing input into a failure instead of a skip. A suite that silently skips its Stage B and real-key tests would otherwise look exactly like one that passes them.

The ptau is hosted here because its original hosts (`storage.googleapis.com/zkevm`, `hermez.s3…`) have answered 403 since September 2026 ([snarkjs#636](https://github.com/iden3/snarkjs/issues/636)). The pin, not the host, is what makes a copy genuine.

`scripts/pack-vectors.py <ceremony dir> <out.tar.gz>` builds the vectors archive reproducibly (sorted entries, fixed metadata, gzip without a timestamp), with a provenance `README.txt`. To publish new vectors:
1. Build them.
2. Publish a new `test-vectors-N` release with the archive (and the ptau).
3. Update `VECTORS_URL` and `VECTORS_SHA256`.

## Lint and format rules

| File                          | What it sets                                                                                                                        | Why                                                                    |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| `rust-toolchain.toml`         | Rust 1.93.0 with rustfmt and clippy                                                                                                 | Same results everywhere                                                |
| `rustfmt.toml`                | Edition 2021, width 100, Unix newlines, field-init and `?` shorthands                                                               | Stable options only                                                    |
| `Cargo.toml` `[lints.rust]`   | `unsafe_code = forbid`, `missing_docs`, `unused_qualifications`                                                                     | No unsafe code; every public item documented                           |
| `Cargo.toml` `[lints.clippy]` | `all` denied, `pedantic` warned; `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented`, `dbg_macro`, `print_stdout` denied | No panic path reachable from an input; the verdict has a single writer |
| `clippy.toml`                 | Unwrap, expect and panic allowed in `#[test]` functions; proper names for `doc_markdown`                                            | Tests fail by panicking                                                |

Lint exceptions are local and carry a one-line reason. For example, `compat/wasm.rs` keeps the low word of a `u128` on purpose. Test crates and `tests/support` allow unwrapping at their top, because their helpers fail by panicking like the tests themselves. Allowed crate-wide:

- `module_name_repetitions`, `must_use_candidate`, `missing_errors_doc`: noise here;
- `many_single_char_names`: field arithmetic reads best as x, y, z.

## Build profiles

| Profile   | Settings                                             | Why                                                                                                      |
| --------- | ---------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `release` | `overflow-checks = true`, thin LTO, one codegen unit | An overflow aborts instead of wrapping (fail closed)                                                     |
| `dev`     | `opt-level = 1`, dependencies at `opt-level = 3`     | Tests keep debug assertions and overflow checks but run in seconds (arkworks unoptimized is ~10× slower) |

## Tests

| File                        | Covers                                                                                                                                                       | Inputs                                  |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------- |
| `src/compat/wasm.rs` (unit) | The wasmcurves emulation: ordinary subtraction on curve points; the over-read point of the power-16 ptau                                                     | —                                       |
| `tests/verifier/compat.rs`  | Oracle: snarkjs fixtures verify only if ChaCha, `hashToG2`, the transcript, `h_k` and the beacon key are bit-exact                                           | —                                       |
| `tests/verifier/checks.rs`  | Stage A on honest keys and crafted attacks (forged proofs, swapped points, subgroup, no-op and cancelled contributions, containers, parameter layouts, caps) | Real keys optional                      |
| `tests/verifier/genesis.rs` | Stage B: honest genesis, another coefficient, a consistently altered genesis + final, another ptau, malformed r1cs and ptau                                  | `ORBINUM_PTAU`; real keys optional      |
| `tests/cli/args.rs`         | The binary: strict argv, required flags, symlink/FIFO/oversized inputs, non-UTF-8 argv, closed stdout                                                        | `ORBINUM_PTAU` for the runs that verify |
| `tests/cli/hostile.rs`      | Hostile argv and input edge cases beyond `args.rs`: exit 2 and nothing on stdout                                                                       | —                                       |
| `tests/hostile/keys.rs`     | Seeded mutations of the real rehearsal keys: no panic, the full check set, never accepted                                                                    | `ORBINUM_REHEARSAL_DIR`                 |
| `tests/hostile/parsers.rs`  | Seeded mutations of the r1cs and ptau readers: no panic; out-of-range values refused                                                                         | `ORBINUM_PTAU`, `ORBINUM_REHEARSAL_DIR` |
| `tests/hostile/robustness.rs` | Truncations and one bit flip in **every byte** of a final key never panic and never pass (except inside a name); mutated r1cs files never panic              | —                                       |

The fuzz targets (`fuzz/fuzz_targets/`: `zkey`, `r1cs`, `ptau`) live in their own workspace and lockfile, seeded from `tests/fixtures/` and `fuzz/seeds/`; crashes land in `fuzz/artifacts/` (gitignored).

Tests are grouped by concern (`verifier/`, `cli/`, `hostile/`), one test binary per file, each declared as a `[[test]]` in `Cargo.toml` (a new file needs its entry). `tests/support/` holds the shared helpers:

- fixtures and verdict queries;
- zkey surgery (`with_entries`, `with_params`, `binfile`, `sections_of`);
- valid synthetic contributions (`contribution`);
- `env_input`.

Fixtures live in `tests/fixtures/` and are generated by its `generate.sh` (circom + snarkjs 0.7.6 + the pinned ptau). The ceremony repo's TS tests use the same files; regenerate both together.

## Changing a check

1. **Test first.** Write the test that reproduces the attack or the new rule, and see it fail.
2. **Keep the id set stable.** A new check gets a new id in `checks::check`. Add it in the same change to `REQUIRED_CHECKS` in `packages/core/src/verification/independent/verdict.ts` of the [ceremony](https://github.com/orbinum/ceremony) repo; otherwise every `cli verify` fails, by design. Update the parse-failure path in `checks::verify` so the full set is still reported.
3. **Respect the invariants:**
   - no panic reachable from an input;
   - every allocation bounded by a validated size;
   - anything unverifiable is a failure;
   - a stricter rule must still accept every honest snarkjs 0.7.6 output. `make test-full` runs the real rehearsal keys.
4. **Update the docs in the same step:**
   - [SPEC §8.4](https://github.com/orbinum/ceremony/blob/main/docs/SPEC.md);
   - the Phase 6b checklist in [CEREMONY_PLAN.md](https://github.com/orbinum/ceremony/blob/main/docs/CEREMONY_PLAN.md);
   - [KNOWN_LIMITS.md](https://github.com/orbinum/ceremony/blob/main/docs/KNOWN_LIMITS.md) if the change accepts a limit;
   - these docs, if usage or architecture change.
5. Run `make check` and `make test-full`, then the ceremony repo's tests with `ORBINUM_RUST_VERIFIER` pointing at your build (see its README).

## CI and releases

| Workflow | Runs on | Does |
|---|---|---|
| `.github/workflows/ci.yml` | Every push to `main` and every pull request into `main`; a run on `main` is never cancelled, a newer push to a pull request cancels its older run | **Build and Test:** fmt, clippy, docs, tests in release (which also builds the binary) against the downloaded and pinned ptau, so Stage B runs for real. **Security:** `cargo audit` and `cargo deny` (blocking) and a secrets scan. **All Checks Passed:** one status that says whether a job failed, was cancelled or never ran. A newer push cancels the older run on the same ref |
| `.github/workflows/release.yml` | CI passing on a push to `main`, on the commit CI tested; by hand on `main` to finish a failed release (only if CI passed on that commit). Never cancelled; runs queue | **Verify:** releases only a version with no GitHub release yet, not below the latest `vx.y.z` tag, with its dated CHANGELOG section; otherwise stays green (no new version) or fails (a version without its section, or one that went backwards). **Build:** binaries for `x86_64`/`aarch64` Linux and macOS (`--locked`, no cache). **Tag and Release:** tag `vx.y.z` on that commit (skipped if it exists), GitHub release with the CHANGELOG section as notes, the packages, `Cargo.lock`, SHA-256 checksums and signed build provenance |

A tag left without its GitHub release (a run that died in between) is finished by the next run only if it names the commit being released; otherwise the release fails and asks for that commit's release to be re-run, or the tag to be deleted.

To release:
1. Bump `version` in `Cargo.toml`, then run `cargo metadata --format-version 1 > /dev/null` so `Cargo.lock` carries it too. CI builds with `--locked`, so a stale lock fails.
2. Rename `## [Unreleased]` in `CHANGELOG.md` to `## [x.y.z] - YYYY-MM-DD`, the same version.
3. Open the pull request into `main`; CI runs every test, real keys included. After the merge, the release checks the version and its CHANGELOG section, runs CI on the merged commit (or reuses its passed run), and publishes `vx.y.z`. A failed release is retried with "Re-run jobs".

Changes between releases only go under `## [Unreleased]`; the version changes only to release. If the ceremony CLI needs the new version, raise `INDEPENDENT_VERIFIER.minVersion` in `packages/core/src/verification/independent/verdict.ts` of the [ceremony](https://github.com/orbinum/ceremony) repo.

