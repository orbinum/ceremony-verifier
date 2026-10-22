# Usage

## Install

From a [release](https://github.com/orbinum/ceremony-verifier/releases): download the package for your platform and its `checksums-vX.Y.Z.txt`, then:

```bash
sha256sum --ignore-missing -c checksums-vX.Y.Z.txt
tar -xzf ceremony-verifier-vX.Y.Z-<target>.tar.gz
```

Or build it from the tag yourself, which is what the ceremony asks of independent verifiers (KL-19):

```bash
git clone --branch vX.Y.Z https://github.com/orbinum/ceremony-verifier && cd ceremony-verifier
make release      # = cargo build --release --locked → target/release/ceremony-verifier
```

The toolchain is pinned in `rust-toolchain.toml` (Rust 1.93.0), and `--locked` builds exactly the dependency versions in `Cargo.lock`. It runs on Unix, 64-bit only (Linux, macOS).

## Inputs

All flags are **required**. Each one is given exactly once, with a value; anything else is refused with exit 2.

| Flag                      | Value                                                     | Validation                                                  |
| ------------------------- | --------------------------------------------------------- | ----------------------------------------------------------- |
| `--genesis <file>`        | The circuit's genesis zkey (`init.json` pins its SHA-256) | Regular file, not a symlink, ≤ 128 MiB                      |
| `--final <file>`          | The final zkey to verify                                  | Same                                                        |
| `--min-contributions <n>` | The announced minimum (`ceremony.json`)                   | Decimal digits only; 0 counts as 1                          |
| `--beacon <hex>`          | The sealed beacon value (drand randomness)                | Hex digits only, 1–255 bytes, any case                      |
| `--iterations <exp>`      | The beacon's `numIterationsExp`                           | 10–24                                                       |
| `--r1cs <file>`           | The circuit's r1cs (pinned in `init.json`)                | As `--genesis`                                              |
| `--ptau <file>`           | `powersOfTau28_hez_final_16.ptau`                         | As `--genesis`, then its BLAKE2b-512 must be the Hermez pin |

## Running it

Directly, for one circuit:

```bash
ceremony-verifier \
  --genesis genesis/transfer.genesis.zkey --final final/transfer.final.zkey \
  --min-contributions 50 \
  --beacon 9f2c…e1 --iterations 10 \
  --r1cs r1cs/transfer.r1cs --ptau powersOfTau28_hez_final_16.ptau
```

Through the ceremony CLI, which runs it for every circuit on its own private copies of the inputs and cross-checks the result with the transcript:

```bash
pnpm ceremony verify --dir <ceremony> --announcement-sha256 <hex> --network <testnet|mainnet> \
  --ptau <ptau> --circuits-repo <clone> --vk-packer <bin> \
  --rust-verifier ../ceremony-verifier/target/release/ceremony-verifier
```

The CLI requires exactly the eight check ids and requires the exit code to agree with the verdict. Every `h_k` must equal the transcript's, and the csHash must equal `init.json`'s.

## Exit codes

| Code | Meaning                                                                                                      |
| ---- | ------------------------------------------------------------------------------------------------------------ |
| 0    | Every check passed                                                                                           |
| 1    | At least one check failed; the verdict says which                                                            |
| 2    | Bad usage, an unreadable or refused input, or the verdict could not be written. Nothing is printed on stdout |

## The verdict

Printed on stdout as JSON:

```json
{
  "ok": true,
  "verifier": "ceremony-verifier 0.1.0",
  "cs_hash": "d8c64056…ac0816",
  "entries": [
    { "index": 1, "kind": "contribution", "name": "alice", "hash": "5b8dde56…4bea58" },
    { "index": 2, "kind": "contribution", "name": "bob", "hash": "2f050c2c…eadd16" },
    { "index": 3, "kind": "beacon", "name": "beacon", "hash": "49a58f55…777519" }
  ],
  "checks": [
    { "id": "well-formed", "title": "both zkeys are as snarkjs writes them: …", "ok": true },
    { "id": "genesis-start", "title": "genesis is a phase-2 start (δ = 1, no entries)", "ok": true },
    …
  ]
}
```

| Field            | Meaning                                                                                         |
| ---------------- | ----------------------------------------------------------------------------------------------- |
| `ok`             | True only if every check passed                                                                 |
| `verifier`       | Name and version of the implementation                                                          |
| `cs_hash`        | The final key's circuit hash (absent if the keys did not parse)                                 |
| `entries[]`      | The final key's MPC entries in chain order, as this implementation read them                    |
| `entries[].hash` | `h_k`: BLAKE2b-512 of the entry's public key and transcript. A contributor finds their own here |
| `entries[].name` | The contributor's name. It is **not** covered by `h_k` (KL-7)                                   |
| `checks[]`       | Every check in a fixed order: `id` (stable), `title`, `ok`, and `detail` when it failed         |

The check ids and what each one verifies are in the [README](../README.md#what-it-checks).

## Reading failures

`detail` lists the problems found, separated by `; `. Examples, as `<id>: <detail>`:

| Check                                                                           | Meaning                                                                                                  |
| ------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `policy: 0 contributions, at least 2 required`                                  | The final key has only the beacon on top of the genesis: its δ is public                                 |
| `chain: entry 3: proof of knowledge does not verify`                            | Entry 3 is forged; the walk stops there                                                                  |
| `chain: entry 2: δ repeats an earlier value (no-op or cancelled contributions)` | A contribution with secret 1, or contributions that cancel each other                                    |
| `well-formed: final: format: …`                                                 | The final key is not a zkey snarkjs would write; the rest report `not run: the keys are not well formed` |
| `final-delta: not checked: the chain is broken`                                 | A consequence of a `chain` failure, not a separate problem                                               |
| `genesis-source: ptau is not the pinned powersOfTau28_hez_final_16.ptau`        | Wrong ptau file (see below)                                                                              |

## Limits and timings

| Limit             | Value                                   |
| ----------------- | --------------------------------------- |
| Input size        | 128 MiB per file                        |
| MPC entries       | 10,000 (refused before they are parsed) |
| Beacon iterations | 2^10 to 2^24                            |
| ptau              | Hermez `_16` only                       |

Measured times for the real circuits, release build, Apple M-series:

| Circuit  | Time   |
| -------- | ------ |
| shield   | ~0.2 s |
| unshield | ~3 s   |
| transfer | ~6 s   |

The worst case at every cap is about 61 s and 1.2 GB. The CLI gives it 10 minutes.

## Troubleshooting

| Symptom                                             | Cause                                                                       | Fix                                                                                                                                  |
| --------------------------------------------------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `genesis-source: ptau is not the pinned …`          | Another ptau, even one from the same Hermez ceremony (`_17`, the full file) | Use exactly `powersOfTau28_hez_final_16.ptau`. With another file snarkjs itself reports transfer as `Circuit does not match` (KL-10) |
| Exit 2, `…: Too many levels of symbolic links`      | The input is a symlink                                                      | Pass the real file                                                                                                                   |
| Exit 2, `not a regular file within 134217728 bytes` | A FIFO, a device or an oversized file                                       | Pass the real file                                                                                                                   |
| Exit 2, `unknown argument …` or `missing …`         | A misspelled or missing flag                                                | See [Inputs](#inputs); every flag is required                                                                                        |
| Exit 2, `invalid --iterations`                      | Outside 10–24                                                               | The ceremony uses 10                                                                                                                 |
