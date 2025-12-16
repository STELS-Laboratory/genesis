## STELS Genesis Contract Whitepaper (Derived from JSON Artifacts)

**Status**: Generated from the canonical Genesis artifacts in this repository.

**License**: MIT (see `LICENSE`)  
**Main Developer & Author**: Pavlo Chabanov  
**Company**: Gliesereum Ukraine LLC

### Source of truth

This document is derived from:
- `src/genesis/genesis.json` (Genesis contract)
- `src/schemes/genesis-smart-1.0.json` (JSON Schema)
- `src/genesis/genesis.blob` + `src/genesis/genesis.sig.json` (signed packaging)

Reproducible verification:

```bash
cargo run -- --report src/genesis/genesis.blob
```

---

## 1) Executive summary

The STELS network is bootstrapped by a Genesis contract that defines:
- Network identity and chain parameters (mainnet, chain_id=1)
- Consensus committee rules and notarized finality
- Notary registry and stake-based eligibility rules
- Monetary policy, fee distribution, and reward model
- Governance controls (upgrade, emergency pause, revocation list)
- Compliance and audit logging constraints

The regulator/auditor package is delivered as:
- a schema-validated JSON contract (`genesis.json`),
- a deterministic binary blob (`genesis.blob`) containing the exact bytes of `{contract, schema}`,
- and a signature manifest (`genesis.sig.json`) signing `SHA256(blob)`.

---

## 2) Network identity and deployment

**Network** (`network.*`):
- **id**: `mainnet`
- **name**: `STELS Mainnet Network`
- **environment**: `mainnet`
- **chain_id**: `1`

**Genesis metadata** (`genesis.*`):
- **created_at**: `2025-12-14T18:04:16.750Z`
- **activation_time**: `2025-12-14T18:19:16.750Z`
- **issuer**: `Gliesereum Ukraine LLC` (`labs@stels.io`)
- **upgrade_policy**: allowed, threshold `k-of-n` with `k=4, n=5`

**Content hash** (`content.*`):
- **hash_alg**: `sha256`
- **hash**: `sha256:982839404f558bbe53e0d21cbe01b17de035ebc83537d4182e78389bfb04f333`
- **size**: `35574` bytes

Consistency invariant enforced in reports:

\[
\texttt{genesis.id} = \text{"genesis:"} \; || \; \texttt{content.hash}
\]

---

## 3) Determinism and execution constraints

The runtime is configured with a **pure-deterministic** profile (`intrinsics.determinism.profile = pure-deterministic`).

Key constraints:
- **No network I/O** (`network = denied`)
- **No filesystem I/O** (`filesystem = denied`)
- **Clock** is logical-only (`clock = logical-only`)
- Allowed state access: `accounts`, `tx_index`, `kv`

Security intent:
- Prevent nondeterministic behavior that could cause consensus divergence.
- Limit available side-effects for on-chain execution.

---

## 4) Cryptographic primitives and identifiers

### 4.1 Hashing

The system uses SHA-256 for:
- `content.hash`
- blob/package integrity (`SHA256(blob)`)
- committee/registry Merkle roots (see normative spec in `consensus.state_root.note`)

\[
H(x) = \mathrm{SHA256}(x)
\]

### 4.2 Signing (ECDSA secp256k1)

ECDSA secp256k1 is used for:
- Genesis and upgrade signing keys (`signing_keys`)
- Signatures (`signatures.signers`)
- Blob package signatures (`genesis.sig.json`)

DER requirements (`security.der_requirements`):
- **lowS**: `true`
- **canonical_DER**: `true`

### 4.3 Address / `kid` derivation

Addresses (key identifiers, `kid`) are derived from compressed secp256k1 public keys using the contract’s `addressing.version_byte`.

Given compressed public key bytes `PK` (33 bytes), and `version_byte = 98`:

\[
\begin{aligned}
H160 &= \mathrm{RIPEMD160}(\mathrm{SHA256}(PK)) \\
payload &= version\_byte \; || \; H160 \\
checksum &= \mathrm{SHA256}(payload)[0..4] \\
address &= \mathrm{Base58}(payload \; || \; checksum)
\end{aligned}
\]

Notes:
- This is **not** Bitcoin Base58Check (no double-SHA checksum).
- The checksum is for tamper detection; authenticity comes from ECDSA signatures.

---

## 5) Consensus and finality

### 5.1 Consensus type

`consensus.type = blockless-quorum`

Interpretation:
- The network uses an event-stream style execution with notarized finality.

### 5.2 Timing

- **window_ms**: `5000`
- **network_clock_skew_ms**: `500`
- Time source:
  - **mode**: `notary-median`
  - **fallback**: `system-ntp`
  - **skew_enforcement_ms**: `1000`

### 5.3 Committee

`consensus.committee`:
- **mode**: `all-active-notaries`
- **epoch_ms**: `60000`
- **quorum_rule**: fraction `2/3`, `round_up=true`

Threshold formula:

\[
q(n) = \left\lceil \frac{2}{3} \cdot n \right\rceil
\]

Bootstrap:
- **enabled**: `true`
- **initial_committee_size**: `5`
- **initial_members** (base58):
  - `ghJejxMRW5V5ZyFyxsn9tqQ4BNcSvmqMrv`
  - `gYjDnckjrKCw3CYVerH1LMbgTWv3dmg6Hu`
  - `gohgoWbJK7dMf5MUKKtthRJdCAMmoVqDMo`
  - `gncGHDzymYmC37EPEK3kk3kWp2fJ9W52tH`
  - `gpcr2Uqbqg3zt6a3VkkCcMm2s2xUtvT2L9`

Bootstrap exit condition:
- min active notaries: `6`

Churn limits:
- enter fraction: `0.08`
- exit fraction: `0.08`

Selection:
- RNG: `vrf`, `vrf_alg = ed25519-vrf`, `vrf_key_required = true`
- Selection policy: `vrf-top-stake`
- Seed: `prev_epoch_beacon` with format `sha256(gls-det-1(prev_epoch_finality_certificate))`

### 5.4 Finality certificate

`consensus.finality_certificate`:
- **hash_alg**: `sha256`
- **alg**: `ecdsa-secp256k1-multi`
- Max signers: `256`

---

## 6) Notary registry and Proof-of-Possession

`consensus.notary_registry` parameters:
- **min_stake**: `100000000000`
- **bonding_ms**: `259200000` (3 days)
- **unbonding_ms**: `604800000` (7 days)
- **key_rotation.min_interval_ms**: `3600000` (1 hour)
- **slash.double_sign**: `0.05`
- **slash.surround_vote**: `0.02`

Identity specification:
- consensus key format: `secp256k1-compressed-hex`
- vrf key format: `ed25519-pubkey-hex`
- proof_of_possession_required: `true`

Normative PoP message (from `consensus.state_root.note`):

\[
msg = \mathrm{SHA256}(\text{"STELS-POP"} || 0x00 || \mathrm{uint32\_be}(chain\_id) || pk_{consensus} || pk_{vrf})
\]

Signature: ECDSA secp256k1 DER low-S, verified with `pk_consensus`.

---

## 7) Transaction rules and fees

### 7.1 Currency

`parameters.currency`:
- **symbol**: `SLI`
- **name**: `Stels Liq Index`
- **decimals**: `8`
- **fee_unit**: `10^8 SLI`

### 7.2 Fee policy

`parameters.fees`:
- base: `10000`
- per_byte: `20`
- currency: `SLI`

`tx_rules` highlights:
- admission_skew_ms: `5000`
- finalization_skew_ms: `500`
- fee_policy_composition:
  - `effective_min_fee = max(tx_rules.min_fee, fees.base) + fees.per_byte * tx_bytes + Σ per_op(ops)`

Linear fee formula:

\[
fee_{min} = base + per\_byte \cdot tx\_bytes + \sum_i per\_op(op_i)
\]

---

## 8) Genesis state snapshot

The initial state is declared in `state.accounts` and `state.registries`.

Accounts listed (5):
- One treasury-like account with balance `4596000000000`
- Four additional accounts with balance `100000000000` each

All five accounts have active stake:
- stake amount: `100000000000`
- status: `active`
- locked_until: `2026-12-14T18:19:16.750Z`

Registry snapshot (`state.registries.notary`):
- bootstrap: `true`
- epoch: `0`
- total_stake: `500000000000`
- committee_root: `08b777a873dff03ef9c191229f64f83ff3999718aaddafda8a0626b6b72e5947`
- registry_root: `b77f290efc42759d04fb7b13159e0eae5d0ac694988bc5105bc202e699c08893`

---

## 9) Monetary policy and rewards

`monetary.supply_cap = 2100000000000000`

Minting:
- `minting = disabled`

Fee distribution (`monetary.fee_distribution`):
- validators: `4000` bps
- workers: `3000` bps
- treasury: `2000` bps
- insurance: `1000` bps
- burn: `0` bps

BPS invariant:

\[
4000 + 3000 + 2000 + 1000 + 0 = 10000
\]

Rewards mode (`monetary.rewards`):
- mode: `execution-mining`
- source: `treasury`
- unit: `smart_op`
- rate_per_unit: `100000`
- max_per_epoch: `159800000`
- caps:
  - global_ops_cap_per_epoch: `1598`
  - per_worker_ops_cap_per_epoch: `1000`

Staking required for rewards:
- min_stake: `100000000000`
- max_stake: `10000000000000`

Treasury policy (`monetary.treasury_policy`):
- accounting: decrement-only
- reward_pool_initial: `420000000000000`
- reward_cap_total: `420000000000000`
- reward_cap_per_year: `83990880000000`
- reward_cap_per_epoch: `159800000`

---

## 10) Staking and slashing

`staking.enabled = true`

Types:
- participation, notary, worker, governance

Lock policy:
- min_lock_ms: `0`
- max_lock_ms: `2592000000` (30 days)

Bonding/unbonding:
- bonding_ms: `259200000` (3 days)
- unbonding_ms: `604800000` (7 days)
- cooldown_epochs: `1`

Slashing policy:
- enabled: `true`
- double_sign: `0.05`
- equivocation: `0.02`
- downtime: `0.01`

Effective stake model:

\[
\mathrm{effective\_stake} = \mathrm{clamp}(stake, min, max) \cdot lock\_multiplier \cdot rating\_multiplier
\]

---

## 11) Governance and emergency controls

Upgrade envelope:
- sign_domain: `["STELS-GENESIS", 1, "v1", "chain:1"]`
- threshold: `k=4, n=5`

Emergency pause:
- allowed: `true`
- max_duration_ms: `3600000` (1 hour)
- trigger threshold: `4-of-5`
- during pause, only allow methods:
  - `governance.upgrade`, `governance.unpause`, `notary.registry`

Revocation list (CRL):
- `seq = 1`
- `revoked = []`
- sign_domain: `["STELS-CRL", 1, "v1", "chain:1"]`

---

## 12) Compliance, logging, and audit trail

Compliance:
- jurisdiction includes `UA`
- travel rule enabled (off-chain implementation)
- on-chain storage forbids PII (`pii_allowed=false`) and stores proof hashes/timestamps

Audit logging channels:
- runtime includes an `audit` stream
- audit retention in storage namespace: `220752000000` ms

---

## 13) Regulator verification procedure (reproducible)

### 13.1 Human-readable report

```bash
cargo run -- --report src/genesis/genesis.blob
```

Expected:
- `schema_validation: OK`
- `integrity_checks: OK`
- `signatures_ok: OK`
- `ready_for_regulator: YES`

### 13.2 Strict verification

```bash
cargo run -- --verify-blob src/genesis/genesis.blob
```

### 13.3 Schema-only check

```bash
cargo run -- --report src/genesis/genesis.json
```

---

## 14) Threat model (high level)

Mitigations implemented by the artifact format and tooling:
- **Tampering**: detected via SHA-256 integrity fields and ECDSA signatures.
- **Schema drift**: prevented by bundling schema bytes into `genesis.blob`.
- **Threshold bypass via duplicates**: prevented by counting only **unique** valid signers.
- **Parsing ambiguity**: prevented by deterministic blob format and JSON Schema validation.

Out of scope / requires protocol implementation:
- Cryptographic verification of the in-document `signatures` section (requires canonical signing-view rules).

---

## 15) Glossary

- **Genesis contract**: JSON document defining initial network state and protocol parameters.
- **Blob**: deterministic binary package of contract+schema bytes.
- **Signature manifest**: JSON describing hashes, sizes, and ECDSA signatures over the blob.
- **Notary**: validator participating in committee-based notarized finality.
- **k-of-n**: threshold rule requiring at least `k` unique valid signers out of `n`.
