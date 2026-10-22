#!/usr/bin/env bash
# Regenerates the MPC fixtures: a 1-constraint circuit with 2 contributions + a beacon.
# Expected hashes are taken from `snarkjs zkey verify` output (the ground truth).
# The same fixtures are used by the ceremony repo's TS tests (packages/core/tests/fixtures);
# regenerate both together.
set -euo pipefail
cd "$(dirname "$0")"
PTAU="${PTAU:?set PTAU to powersOfTau28_hez_final_16.ptau}"
read -r -a SNARKJS <<< "${SNARKJS:-npx --yes snarkjs@0.7.6}"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

circom multiplier.circom --r1cs -o "$tmp" >/dev/null
cp "$tmp/multiplier.r1cs" multiplier.r1cs
"${SNARKJS[@]}" groth16 setup multiplier.r1cs "$PTAU" multiplier_0.zkey >/dev/null
"${SNARKJS[@]}" zkey contribute multiplier_0.zkey multiplier_1.zkey --name="alice" -e="fixture entropy 1" >/dev/null
"${SNARKJS[@]}" zkey contribute multiplier_1.zkey multiplier_2.zkey --name="bob" -e="fixture entropy 2" >/dev/null
"${SNARKJS[@]}" zkey beacon multiplier_2.zkey multiplier_final.zkey \
  0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="beacon" >/dev/null
# Attack fixture: the beacon applied straight onto the genesis, with no contribution (public δ).
"${SNARKJS[@]}" zkey beacon multiplier_0.zkey multiplier_beacon_only.zkey \
  0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="beacon" >/dev/null
"${SNARKJS[@]}" zkey verify multiplier.r1cs "$PTAU" multiplier_final.zkey | sed 's/\x1b\[[0-9;]*m//g' > verify.log
grep -q "ZKey Ok!" verify.log
