### STELS Mainnet/Beta Genesis

Built by Ukrainian Cyber Engineers  
In Solidarity with Ukraine's Defenders

A comprehensive monochain mainnet/beta configuration for the STELS (Smart Transaction Event Ledger System) platform, featuring advanced consensus mechanisms, smart contract capabilities, and enterprise-grade security.

`SLI` (Stels Liq Index) is the **native utility coin of the STELS network** (fees, staking/economic security, and protocol incentives). The Genesis contract also includes the disclosure `token_is_not_equity = true`.

### Regulatory Review Package (Genesis)

This repository contains tooling and artifacts for reviewing a **Genesis contract** and its **signed binary package**.

### License

MIT License. See `LICENSE`.

**Main Developer & Author**: Pavlo Chabanov  
**Company**: Gliesereum Ukraine LLC

### Scope

This package provides:
- A **Genesis contract** (`.json`) validated against a published JSON Schema.
- A **Genesis blob** (`.blob`) that bundles the exact bytes of the contract + schema.
- A **signature file** (`.sig.json`) that cryptographically signs the blob hash (ECDSA secp256k1).
- A CLI that can produce a **human-readable audit report** and perform strict verification.

### Files to Review

All regulator-facing artifacts are in:
- `src/genesis/genesis.json` — Genesis contract (JSON)
- `src/genesis/genesis.blob` — Binary blob packaging the contract + schema
- `src/genesis/genesis.sig.json` — Blob signature file (k-of-n threshold)
- `src/schemes/genesis-smart-1.0.json` — JSON Schema used for validation

### Documentation (Regulator-facing)

- `INFORMATION.md` — Short regulator-facing network/technology overview
- `WHITEPAPER.md` — Technical overview derived from Genesis artifacts
- `ECONOMICS.md` — Monetary & economic policy (regulator-facing)

### One-command Audit Report (Human-readable)

Contract report:

```bash
cargo run -- --report src/genesis/genesis.json
```

Blob package report (includes signature and integrity checks):

```bash
cargo run -- --report src/genesis/genesis.blob
```

If the signature file is not next to the blob, pass it explicitly:

```bash
cargo run -- --report src/genesis/genesis.blob --sig src/genesis/genesis.sig.json
```

### Strict Verification Commands

Validate the contract against the schema (and regenerate blob+sig in-place):

```bash
cargo run -- --validate src/genesis/genesis.json
```

To generate a **k-of-n** signature file where not all signers are required, set `k` explicitly:

```bash
cargo run -- --validate src/genesis/genesis.json --threshold-k 3
```

Verify the blob package (parsing safety checks + JSON validity + schema validation + signature verification):

```bash
cargo run -- --verify-blob src/genesis/genesis.blob
```

### Economics Audit (PASS/FAIL invariants)

Run the economics invariant audit over the signed blob package (recommended):

```bash
cargo run -- --economics-audit src/genesis/genesis.blob
```

Or run it over the raw contract JSON:

```bash
cargo run -- --economics-audit src/genesis/genesis.json
```

### What Is Verified

When reporting/verifying a blob (`.blob`) using the provided CLI:
- **Blob format safety**: magic/version, length bounds, no trailing bytes.
- **Embedded JSON validity**: the embedded document and schema are valid JSON.
- **Schema validation**: the embedded document validates against the embedded schema.
- **Integrity**: `sha256(blob)`, `sha256(document)`, `sha256(schema)` match the values in `genesis.sig.json`, and sizes match.
- **Signatures**:
  - Algorithm: **ECDSA secp256k1**, DER-encoded signature.
  - Public key: compressed SEC1 (33 bytes, prefix 0x02/0x03).
  - Signer identity (`kid`): derived from public key using the contract’s `addressing.version_byte`:
    - payload = `version_byte || RIPEMD160(SHA256(pubkey_compressed))`
    - checksum = `SHA256(payload)[0..4]`
    - address = Base58(payload || checksum)
  - Threshold: **k-of-n** is enforced using **unique** valid signers (duplicates do not count).

### Notes

- The **private signing keys are not part of the regulator package**.
- The contract (`genesis.json`) also contains its own `signatures` section. The CLI currently verifies **blob signatures** (`genesis.sig.json`) and does **not** cryptographically verify the in-document `signatures` section because that requires the protocol’s canonical “signing view” rules.

### Build Requirements

- Rust toolchain (Cargo)

Build and run:

```bash
cargo build
```

Generate and open API docs:

```bash
cargo doc --no-deps --open
```
