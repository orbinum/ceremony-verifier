# ceremony-verifier — development commands. `make` on its own lists them.
#
# One thing here is load-bearing rather than convenience:
#
#   * `test-full` sets ORBINUM_REQUIRE_INPUTS. The Stage B and real-key tests skip themselves
#     when the pinned ptau or the rehearsal keys are absent, so a suite that skips them looks
#     exactly like one that passes them. That variable turns absence into a failure. CI runs
#     it on every change.
#
# Its inputs are downloaded and pinned, never assumed to be on this machine, both from this
# repo's `test-vectors-1` release: the Hermez ptau (BLAKE2b-512, the same pin the binary
# enforces; its original hosts have answered 403 since September 2026, and the pin, not the
# host, is what makes a copy genuine) and the rehearsal keys (SHA-256). Point ORBINUM_PTAU
# or ORBINUM_REHEARSAL_DIR at local copies to skip a download.

.DEFAULT_GOAL := help

BLUE  := \033[0;34m
GREEN := \033[0;32m
NC    := \033[0m

# Inputs of the full suite, fetched into this checkout (gitignored).
PTAU_URL     ?= https://github.com/orbinum/ceremony-verifier/releases/download/test-vectors-1/powersOfTau28_hez_final_16.ptau
PTAU_BLAKE2B := 6a6277a2f74e1073601b4f9fed6e1e55226917efb0f0db8a07d98ab01df1ccf43eb0e8c3159432acd4960e2f29fe84a4198501fa54c8dad9e43297453efec125
PTAU_FILE    := ptau/pot16_final.ptau

# The keys of the testnet rehearsal (scripts/pack-vectors.py builds this archive reproducibly).
VECTORS_URL    ?= https://github.com/orbinum/ceremony-verifier/releases/download/test-vectors-1/testnet-rehearsal-1.tar.gz
VECTORS_SHA256 := 1b09813386697048f77e160e35beda6ace578c305a8b2053e8d781bb980082c7
VECTORS_TAR    := vectors/testnet-rehearsal-1.tar.gz
VECTORS_DIR    := vectors/testnet-rehearsal-1

ORBINUM_PTAU          ?= $(PTAU_FILE)
ORBINUM_REHEARSAL_DIR ?= $(VECTORS_DIR)

.PHONY: help
help: ## List available commands
	@echo "$(BLUE)ceremony-verifier$(NC)"
	@echo ""
	@grep -hE '^[a-z][a-z0-9-]*:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-11s$(NC) %s\n", $$1, $$2}'

# ─── Checks ──────────────────────────────────────────────────────────────────

.PHONY: fmt
fmt: ## Format with rustfmt
	cargo fmt

.PHONY: fmt-check
fmt-check: ## Check formatting without writing
	cargo fmt --check

.PHONY: lint
lint: ## Clippy on every target, warnings as errors
	cargo clippy --all-targets --locked -- -D warnings

.PHONY: check
check: fmt-check lint test ## Formatting + clippy + tests: the fast local loop

# ─── Tests ───────────────────────────────────────────────────────────────────

.PHONY: test
test: ## Tests; the ptau and real-key ones skip without their inputs
	cargo test --locked

.PHONY: test-full
# Fetches only the inputs left at their defaults; overridden ones are used as given.
test-full: $(if $(filter $(PTAU_FILE),$(ORBINUM_PTAU)),ptau) $(if $(filter $(VECTORS_DIR),$(ORBINUM_REHEARSAL_DIR)),vectors) ## Every test, release build, inputs required: what CI runs
	ORBINUM_PTAU=$(ORBINUM_PTAU) ORBINUM_REHEARSAL_DIR=$(ORBINUM_REHEARSAL_DIR) \
		ORBINUM_REQUIRE_INPUTS=1 cargo test --release --locked

# ─── Test inputs ─────────────────────────────────────────────────────────────

.PHONY: ptau
ptau: ## Download the pinned Hermez ptau (Stage B)
	@scripts/fetch.sh "$(PTAU_URL)" blake2b $(PTAU_BLAKE2B) $(PTAU_FILE)

.PHONY: vectors
vectors: ## Download the pinned rehearsal keys (real-key tests)
	@scripts/fetch.sh "$(VECTORS_URL)" sha256 $(VECTORS_SHA256) $(VECTORS_TAR)
	@tar -xzf $(VECTORS_TAR) -C vectors

# ─── Build ───────────────────────────────────────────────────────────────────

# The build machine's paths are remapped so they never end up in the binary; std's sources (when
# the rust-src component is installed) map to /rustc/<commit>, as without it.
CARGO_HOME ?= $(HOME)/.cargo
RUSTUP_HOME ?= $(HOME)/.rustup
# Expanded only by `release` (`=`, not `:=`), so no other target runs rustc to read them.
RUST_SYSROOT = $(shell rustc --print sysroot)
RUST_COMMIT = $(shell rustc -vV | sed -n 's/^commit-hash: //p')
RELEASE_FLAGS := --remap-path-prefix=$(CARGO_HOME)=/cargo --remap-path-prefix=$(RUSTUP_HOME)=/rustup \
	--remap-path-prefix=$(CURDIR)=/src \
	--remap-path-prefix=$(RUST_SYSROOT)/lib/rustlib/src/rust=/rustc/$(RUST_COMMIT)

.PHONY: release
release: ## Release build: target/release/ceremony-verifier (TARGET=<triple>: target/<triple>/release/)
	RUSTFLAGS="$(RELEASE_FLAGS)" cargo build --release --locked $(if $(TARGET),--target $(TARGET))

# Coverage-guided fuzzing of one reader (needs a nightly toolchain and `cargo install cargo-fuzz`),
# seeded with the test fixtures and fuzz/seeds/. Runs for FUZZ_SECONDS; crashes land in fuzz/artifacts/.
FUZZ_TARGET ?= zkey
FUZZ_SECONDS ?= 300

.PHONY: fuzz
fuzz: ## Fuzz a reader: FUZZ_TARGET=zkey|r1cs|ptau FUZZ_SECONDS=300 (nightly + cargo-fuzz)
	mkdir -p fuzz/corpus/$(FUZZ_TARGET)
	cp tests/fixtures/*.$(FUZZ_TARGET) fuzz/seeds/$(FUZZ_TARGET)/* fuzz/corpus/$(FUZZ_TARGET)/ 2>/dev/null || true
	cd fuzz && cargo +nightly fuzz run $(FUZZ_TARGET) -- -max_total_time=$(FUZZ_SECONDS)

.PHONY: doc
doc: ## API documentation (missing docs fail the lint)
	cargo doc --no-deps --locked
