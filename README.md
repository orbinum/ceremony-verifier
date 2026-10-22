# ceremony-verifier

Independent verifier for the Orbinum Groth16 phase-2 trusted-setup ceremony.

The ceremony's contributions are produced and verified with snarkjs. If snarkjs's verification had a bug, every check that uses it would share that bug. This crate is the **second implementation**. It is written from scratch in Rust on arkworks 0.5 and shares no code with snarkjs, ffjavascript or `groth16-proofs`. It re-verifies each **final** zkey against its pinned genesis, and re-derives the genesis itself from the circuit's r1cs and the pinned Phase 1 ptau.

`orbinum-ceremony verify --rust-verifier <bin>` runs it for every circuit and requires it to agree with the transcript. It is a mandatory security check of the ceremony (SPEC §8.4).

## What it checks

Each check has a stable id, and the CLI requires exactly this set:

| Id                | Verifies                                                                                                                                        |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `well-formed`     | Both zkeys are exactly as snarkjs writes them: container, header, MPC entries; fields canonical, points on the curve, G2 points in the subgroup |
| `genesis-start`   | The genesis is a phase-2 start: δ = 1, γ = generator, no entries                                                                                |
| `genesis-source`  | The genesis is snarkjs `newZKey`'s output for the announced r1cs and the pinned ptau, csHash included                                           |
| `unchanged`       | Everything phase 2 must not touch (circuit sizes, α/β/γ, IC, coeffs, A, B1, B2, csHash) is byte-identical to the genesis                        |
| `policy`          | At least the announced number of contributions; exactly one beacon, last, equal to the announced one                                            |
| `chain`           | Every entry: transcript, proof of knowledge, δ update, no repeated δ; the beacon key re-derived from its value                                  |
| `final-delta`     | The verification key's δ is the chain's last δ, consistent in G1 and G2, and not trivial                                                        |
| `scaled-sections` | Sections L and H are the genesis's divided by the final δ                                                                                       |

## Quick start

```bash
make release        # cargo build --release --locked (or download a release: docs/USAGE.md)
target/release/ceremony-verifier \
  --genesis genesis/transfer.genesis.zkey --final final/transfer.final.zkey \
  --min-contributions 50 --beacon <drand randomness, hex> --iterations 10 \
  --r1cs r1cs/transfer.r1cs --ptau powersOfTau28_hez_final_16.ptau
```

It prints a JSON verdict. Exit 0 means every check passed, 1 means a check failed, and 2 means bad usage or unreadable input. `make` on its own lists the development commands. `make test-full` downloads its test inputs (the Hermez ptau and the rehearsal keys) from this repo's `test-vectors-1` release, checked against pinned hashes.

## Documentation

| Document                                     | For                                                                                    |
| -------------------------------------------- | -------------------------------------------------------------------------------------- |
| [docs/USAGE.md](docs/USAGE.md)               | Running it: flags, exit codes, the verdict JSON, reading failures, troubleshooting     |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | How it is built: modules, data flow, where each check lives, design decisions          |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)   | Working on it: `make` targets, lint and format rules, tests, how to add a check safely |

Security rationale and its limits live with the ceremony:

- [SPEC §8.4](https://github.com/orbinum/ceremony/blob/main/docs/SPEC.md): the verifier and its hardening (Stages A–E).
- [KNOWN_LIMITS.md](https://github.com/orbinum/ceremony/blob/main/docs/KNOWN_LIMITS.md): what it does not guarantee (KL-15 to KL-19, KL-24).

## Versions and license

Releases follow [Semantic Versioning](https://semver.org); changes are in [CHANGELOG.md](CHANGELOG.md). The ceremony CLI states the oldest version it accepts.

[GPL-3.0-or-later](LICENSE).
