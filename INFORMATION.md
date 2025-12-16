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
  - `src/genesis/genesis.blob` — binary blob containing the exact bytes of `{genesis.json, schema.json}`
  - `src/genesis/genesis.sig.json` — signature manifest that signs `SHA256(blob)` using **ECDSA secp256k1** with a **k-of-n** threshold

The package is designed so an independent reviewer can verify **integrity, authenticity (threshold signatures), and schema correctness** without any private keys.

### 2) Network identity (as defined by Genesis)
From `src/genesis/genesis.json`:
- **Network**: mainnet (`network.id = mainnet`, `network.environment = mainnet`)
- **Chain identifier**: `network.chain_id = 1`
- **Genesis activation time**: `genesis.activation_time` (ISO-8601)

### 3) Core technologies (high level)
- **Contract-as-configuration**: critical parameters are declared in a signed Genesis contract (JSON) and validated against a published schema.
- **Deterministic packaging**: the signed `.blob` bundles the *exact bytes* of the contract + schema to prevent “schema drift” or ambiguous encodings.
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

If only the JSON is available, validate it against the schema:

```bash
cargo run -- --validate src/genesis/genesis.json
```

### 7) Notes / reviewer expectations
- Private keys are **not** part of this package.
- The `.blob` + `.sig.json` pair is the primary regulator/auditor artifact for integrity + threshold signature verification.
- The tool verifies **blob signatures**; the contract may also contain an internal `signatures` section which is a protocol-level concept that requires canonical signing rules to evaluate.
