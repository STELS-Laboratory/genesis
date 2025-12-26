## STELS Network — Regulator Information (Short Technical Description)

**Purpose**: Provide a concise, auditable, regulator-facing description of the STELS network and the technologies used to define and verify its Genesis configuration.

**License**: MIT (see `LICENSE`)  
**Main Developer & Author**: Pavlo Chabanov  
**Company**: Gliesereum Ukraine LLC

### 1) What this package is
This repository contains the **canonical Genesis configuration** for the STELS network and tooling to verify it:
- **Genesis contract (JSON)**: `src/genesis/genesis.json`
- **JSON Schema**: `src/schemes/genesis-smart-1.0.json`
- **Deterministic signed package**:
  - `src/genesis/genesis.blob` — all-in-one binary blob containing:
    - Genesis contract JSON bytes
    - JSON Schema bytes
    - Initial transactions (distribution, staking, nomination) with `fee = 0`
    - Embedded signatures (ECDSA secp256k1 with **k-of-n** threshold)

The package is designed so an independent reviewer can verify **integrity, authenticity (threshold signatures), and schema correctness** without any private keys. The blob is self-contained; no separate signature file is needed (default behavior).

### 2) Network identity (as defined by Genesis)
From `src/genesis/genesis.json`:
- **Network**: mainnet (`network.id = mainnet`, `network.environment = mainnet`)
- **Chain identifier**: `network.chain_id = 1`
- **Genesis activation time**: `genesis.activation_time` (ISO-8601)

### 3) Core technologies (high level)
- **Contract-as-configuration**: critical parameters are declared in a signed Genesis contract (JSON) and validated against a published schema.
- **Deterministic packaging**: the signed `.blob` bundles the *exact bytes* of the contract + schema + initial transactions + signatures to prevent "schema drift" or ambiguous encodings.
- **Cryptography**:
  - **Hashing**: SHA-256 for content and package integrity.
  - **Signing**: ECDSA secp256k1 (DER signatures; low-S canonicalization required).
  - **Key identifiers (addresses / `kid`)**: derived from compressed secp256k1 public keys using the Genesis `addressing.version_byte` with Base58 encoding.
- **Determinism constraints for smart execution**: Genesis encodes a pure-deterministic profile (no network I/O, no filesystem I/O, logical-only clock), to reduce nondeterminism and consensus divergence risk.

### 4) Consensus and finality (as encoded in Genesis)
Genesis defines an event-ledger system with notarized finality:
- Committee/registry rules and threshold signature requirements are specified under `consensus.*`.
- The contract includes normative notes for committee/registry root computations and proof-of-possession (PoP) verification rules.

### 5) Monetary policy (summary)
Full policy is documented in `ECONOMICS.md` and is derived from Genesis fields.
Key disclosures:
- **Native utility coin**: `SLI` (Stels Liq Index), **decimals = 8**.
- **Minting**: disabled at genesis (`monetary.minting = disabled`).
- Fee model and fee distribution (bps split + designated addresses) are encoded in Genesis and can be audited.

### 6) How a reviewer can verify everything (recommended)
Generate a human-readable audit report from the signed blob:

```bash
cargo run -- --report src/genesis/genesis.blob
```

Strict verification (parsing safety checks + schema validation + signature threshold enforcement):

```bash
cargo run -- --verify-blob src/genesis/genesis.blob
```

Economics invariant audit (PASS/FAIL checks over the verified blob):

```bash
cargo run -- --economics-audit src/genesis/genesis.blob
```

Create a signed blob with initial transactions:

```bash
cargo run -- --create-blob src/genesis/genesis.json
```

This command validates the document, generates initial transactions (fee = 0), and creates a signed blob with embedded signatures.

### 7) Notes / reviewer expectations
- Private keys are **not** part of this package.
- The `.blob` file is the primary regulator/auditor artifact. It contains embedded signatures (default), making it self-contained and ready for network bootstrap.
- Initial transactions have `fee = 0` to preserve distribution economics.
- The tool verifies **blob signatures** (embedded in blob); the contract may also contain an internal `signatures` section which is a protocol-level concept that requires canonical signing rules to evaluate.
