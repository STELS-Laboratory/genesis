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
- A **Genesis blob** (`.blob`) that bundles the exact bytes of the contract + schema + initial transactions + signatures.
- A CLI that can produce a **human-readable audit report** and perform strict verification.
- **Initial transaction generation** for network bootstrap (distribution, staking, nomination).
- **Extended blob format** (version 3) with distinct sections for schema, document, transactions, and signatures.

### Files to Review

All regulator-facing artifacts are in:
- `src/genesis/genesis.json` — Genesis contract (JSON)
- `src/genesis/genesis.blob` — All-in-one binary blob (schema + document + transactions + signatures)
- `src/schemes/genesis-smart-1.0.json` — JSON Schema used for validation

**Note**: 
- The blob file is self-contained with embedded signatures (default). No separate `.sig.json` file is created.
- The blob is a binary file. Use `--extract-transactions` to view transactions.
- Initial transactions have `fee = 0` to preserve distribution economics.

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

**Note**: For blobs with embedded signatures (default), no signature file is needed. The report uses embedded signatures automatically.

### Create Blob with Initial Transactions

Create a signed blob with initial transactions (distribution, staking, nomination):

```bash
cargo run -- --create-blob src/genesis/genesis.json
```

This command:
- Validates the document against the schema
- Generates initial distribution transactions (fee = 0 to preserve distribution economics)
- Creates a signed blob with embedded signatures and transactions

To generate a **k-of-n** signature file where not all signers are required, set `k` explicitly:

```bash
cargo run -- --create-blob src/genesis/genesis.json --threshold-k 3
```

Verify the blob package (parsing safety checks + JSON validity + schema validation + signature verification):

```bash
cargo run -- --verify-blob src/genesis/genesis.blob
```

### Blob Format

The tool creates an **all-in-one blob** (version 3) containing:

- **SCHEMA** (0x0001): JSON Schema bytes
- **GENESIS_DOCUMENT** (0x0002): Genesis contract JSON bytes
- **INITIAL_TX_STATE** (0x0003): Initial transactions JSON array (distribution, staking, nomination)
- **SIGNATURE_SET** (0x0004): Signature set JSON (embedded in blob)

This single blob file is self-contained and ready for network startup.

**Note**: Initial transactions have `fee = 0` to preserve distribution economics.

Advanced options:

```bash
# Extended format without transactions
cargo run -- --create-blob src/genesis/genesis.json --no-transactions

# Extended format with detached signatures (creates separate .sig.json file)
cargo run -- --create-blob src/genesis/genesis.json --detached-signatures
```

Extract sections from an extended blob:

```bash
cargo run -- --extract-sections src/genesis/genesis.blob
```

Extract and view transactions from a blob:

**Note**: The blob is a binary file. Transactions are embedded in the `INITIAL_TX_STATE` section but are not visible when opening the blob as text. Use the commands below to extract and view them.

```bash
# Display transactions
cargo run -- --extract-transactions src/genesis/genesis.blob

# Save transactions to file
cargo run -- --extract-transactions src/genesis/genesis.blob --tx-output transactions.json
```

Verify initial transactions against genesis protocol:

```bash
cargo run -- --verify-transactions src/genesis/genesis.blob
```

Verify distribution protocol and initial state:

```bash
cargo run -- --verify-distribution src/genesis/genesis.json
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
- **Integrity**: `sha256(blob)`, `sha256(document)`, `sha256(schema)` are verified.
  - For extended blobs with embedded signatures, signatures are verified against the blob **without** the SIGNATURE_SET section.
- **Signatures**:
  - Algorithm: **ECDSA secp256k1**, DER-encoded signature.
  - Public key: compressed SEC1 (33 bytes, prefix 0x02/0x03).
  - Signer identity (`kid`): derived from public key using the contract's `addressing.version_byte`:
    - payload = `version_byte || RIPEMD160(SHA256(pubkey_compressed))`
    - checksum = `SHA256(payload)[0..4]`
    - address = Base58(payload || checksum)
  - Threshold: **k-of-n** is enforced using **unique** valid signers (duplicates do not count).
  - Canonicalization: Signatures are normalized to low-S to reduce ECDSA malleability.
- **Initial Transactions** (if present):
  - Transaction chain integrity: `prev_hash` links transactions sequentially.
  - Genesis funding transaction: First transaction has `prev_hash` pointing to `genesis.id`.
  - Distribution: All non-treasury accounts receive distribution transactions.
  - Staking: All accounts with initial stake have corresponding staking transactions.
  - Nomination: All initial committee members have registration transactions.
  - Fee: All initial transactions have fee = 0 to preserve distribution economics.
  - Signatures: All transactions are signed with all provided signing keys.

### Notes

- The **private signing keys are not part of the regulator package**.
- The contract (`genesis.json`) also contains its own `signatures` section. The CLI verifies **blob signatures** (embedded in blob) and does **not** cryptographically verify the in-document `signatures` section because that requires the protocol's canonical "signing view" rules.

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
