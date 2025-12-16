## STELS Monetary & Economic Policy (Regulator-Facing)

**Document purpose**: Provide a precise, auditable description of the STELS network’s monetary policy and economic flows as defined by the Genesis contract.

**License**: MIT (see `LICENSE`)  
**Main Developer & Author**: Pavlo Chabanov  
**Company**: Gliesereum Ukraine LLC

**Source of truth**:
- `src/genesis/genesis.json` (Genesis contract)
- `src/schemes/genesis-smart-1.0.json` (schema)

**Reproducible verification** (schema + blob integrity + signatures):

```bash
cargo run -- --report src/genesis/genesis.blob
```

---

## 1) Currency definition

**Currency symbol**: `SLI` (Stels Liq Index)

**Token classification**: `SLI` is the **native utility coin of the STELS network**.

Primary functions (as encoded by Genesis policy):
- Paying **transaction fees** (`parameters.fees`, `tx_rules`)
- **Staking** / economic security for consensus participation (`staking`, `consensus.notary_registry`)
- Governance/security controls that rely on threshold signing and network roles (`governance`, `signing_keys`)

The Genesis contract also explicitly states `token_is_not_equity = true`.

**Denomination**:
- `decimals = 8`
- One whole unit: \(1\ \mathrm{SLI} = 10^8\) base units
- Fee unit string: `10^8 SLI`

All amounts that must be consensus-safe are represented as **decimal strings** in the Genesis state and policy fields.

---

## 2) Supply policy

### 2.1 Supply cap

The protocol defines a maximum supply cap:
- `monetary.supply_cap = "2100000000000000"` (base units)

### 2.2 Minting policy

- `monetary.minting = "disabled"`

Interpretation:
- There is **no ongoing minting/inflation engine** enabled at genesis.
- Any token distribution after genesis is modeled as **reallocation** from reserved balances (see Treasury Reserve Model), not issuance of new units.

### 2.3 Genesis circulating supply model

The circulating supply model is defined as:
- `genesis_circulating = sum(state.accounts[*].balance)`
- `uncirculated_supply = virtual_treasury_reserve`
- `release_mechanism = treasury_reward_decrement`

This establishes a conservative accounting model: rewards are paid by decrementing a reserve (not by minting).

---

## 3) Treasury reserve and reward pool

### 3.1 Treasury policy

Treasury reward pool parameters:
- `reward_pool_mode = virtual-ledger`
- `accounting = decrement-only`
- `accounting_model = virtual-reserve-cap`

Reward pool caps:
- `reward_pool_initial = "420000000000000"`
- `reward_cap_total = "420000000000000"`
- `reward_cap_per_year = "83990880000000"`
- `reward_cap_per_epoch = "159800000"`

These caps are intended to bound payout rates and total issuance-from-reserve over time.

### 3.2 Rewards mode switching

- `rewards_mode_switch.bootstrap = treasury`
- `rewards_mode_switch.on_treasury_empty = fee-only`
- `rewards_mode_switch.irreversible = true`

Interpretation:
- Rewards are initially funded from the treasury reserve.
- Once the treasury reserve is exhausted, the system switches to a **fee-only** regime.
- The switch is irreversible, limiting discretionary policy changes.

---

## 4) Transaction fees

### 4.1 Fee parameters

Base fee model (from `parameters.fees`):
- `base = 10000`
- `per_byte = 20`
- `currency = SLI`

Fee calculation guidance (from `tx_rules.fee_calculation`):
- `tx_bytes = byteLength(UTF8(gls-det-1(signing_view)))`
- `fee_min = base + per_byte * tx_bytes + Σ per_op(ops)`

Formalized:

\[
\mathrm{fee_{min}} = base + per\_byte \cdot tx\_bytes + \sum_i per\_op(op_i)
\]

Additional guard:
- `tx_rules.min_fee = 10000` (base units)
- `effective_min_fee = max(tx_rules.min_fee, fees.base) + fees.per_byte * tx_bytes + Σ per_op(ops)`

---

## 5) Fee distribution (economic sinks and recipients)

### 5.1 Basis points split

The fee distribution totals 10,000 bps:
- Validators: `4000` bps (40%)
- Workers: `3000` bps (30%)
- Treasury: `2000` bps (20%)
- Insurance: `1000` bps (10%)
- Burn: `0` bps (0%)

Invariant:

\[
4000 + 3000 + 2000 + 1000 + 0 = 10000
\]

### 5.2 Distribution addresses

Fixed distribution addresses:
- `treasury_address = ghJejxMRW5V5ZyFyxsn9tqQ4BNcSvmqMrv`
- `insurance_address = gohgoWbJK7dMf5MUKKtthRJdCAMmoVqDMo`

### 5.3 Designated wallets (economic roles / off-chain labels)

The Genesis contract encodes **addresses** and their **protocol roles** (e.g., treasury distribution, insurance distribution, initial accounts).  
The following labels are **off-chain administrative descriptions** intended for regulator/auditor clarity. They do not, by themselves, change protocol behavior.

| Address | Label (requested) | Where it appears in Genesis economics |
|---|---|---|
| `gohgoWbJK7dMf5MUKKtthRJdCAMmoVqDMo` | Gliesereum Ukraine — lead developer | `monetary.fee_distribution.distribution_addresses.insurance_address` (insurance distribution); also present in `state.accounts` |
| `ghJejxMRW5V5ZyFyxsn9tqQ4BNcSvmqMrv` | Foundation | `parameters.treasury_address`; `monetary.fee_distribution.distribution_addresses.treasury_address`; also present in `state.accounts` |
| `gYjDnckjrKCw3CYVerH1LMbgTWv3dmg6Hu` | EC funds | Present in `state.accounts` (initial balance/stake) |
| `gncGHDzymYmC37EPEK3kk3kWp2fJ9W52tH` | Third‑party developers | Present in `state.accounts` (initial balance/stake) |
| `gpcr2Uqbqg3zt6a3VkkCcMm2s2xUtvT2L9` | Claim program | Present in `state.accounts` (initial balance/stake) |

Note: claim program uses a dedicated address (`gpcr2…`) per the off-chain labeling request.

Distribution algorithms:
- Validators: `pro-rata-by-effective-stake`
- Workers: `pro-rata-by-verified-ops`
- Treasury/Insurance: `fixed-address`

Worker verification model:
- `model = notary-attested`
- Proof schema: `execution-receipt`
- `verification_epoch_window = 1`

Interpretation:
- Worker rewards depend on notarized proofs and are constrained by verification rules.

---

## 6) Rewards (execution-mining)

### 6.1 Mode and unit

- `monetary.rewards.mode = execution-mining`
- `source = treasury`
- `unit = smart_op`

### 6.2 Rate and caps

- `rate_per_unit = "100000"`
- `max_per_epoch = "159800000"`

Operational caps:
- `global_ops_cap_per_epoch = 1598`
- `per_worker_ops_cap_per_epoch = 1000`
- Overflow policy: `pro-rata-scale-down`

Declared invariant:

\[
\mathrm{max\_per\_epoch} = \mathrm{rate\_per\_unit} \cdot \mathrm{global\_ops\_cap\_per\_epoch}
\]

(As stated in `monetary.rewards.invariants`.)

### 6.3 Eligibility and stake requirements

Rewards require staking:
- `required = true`
- `min_stake = 100000000000`
- `max_stake = 10000000000000`

A decentralization guard is enabled:
- `enabled = true`
- `gini_threshold = 0.85`
- `penalty_multiplier = 0.8`

Interpretation:
- The system encodes explicit guardrails intended to reduce centralization risk in reward outcomes.

---

## 7) Staking economics (bonding/unbonding and slashing)

Stake parameters relevant to economic security:
- `consensus.notary_registry.min_stake = 100000000000`
- Bonding delay: `bonding_ms = 259200000` (3 days)
- Unbonding delay: `unbonding_ms = 604800000` (7 days)

Slashing (economic penalties):
- `double_sign = 0.05`
- `surround_vote = 0.02` (notary registry)

Network-wide slashing policy (staking):
- `double_sign = 0.05`
- `equivocation = 0.02`
- `downtime = 0.01`

Effective stake is modeled as:

\[
\mathrm{effective\_stake} = \mathrm{clamp}(stake, min, max) \cdot lock\_multiplier \cdot rating\_multiplier
\]

These mechanisms align validator incentives with uptime and protocol compliance.

---

## 8) Disclosures (as encoded in Genesis)

The Genesis contract includes explicit disclaimers:
- `no_profit_guarantee = true`
- `staking_is_security_mechanism = true`
- `rewards_are_fees = true`
- `token_is_not_equity = true`

These statements are part of the on-chain policy metadata and may be used for compliance alignment.

---

## 9) Regulator audit procedure (recommended)

1) Validate the contract and produce a signed blob package:

```bash
cargo run -- --validate src/genesis/genesis.json
```

2) Verify the blob package (schema + integrity + signatures):

```bash
cargo run -- --verify-blob src/genesis/genesis.blob
```

3) Generate the human-readable report:

```bash
cargo run -- --report src/genesis/genesis.blob
```

---

## Appendix A — Key parameters table

| Category | Field | Value |
|---|---|---|
| Currency | symbol | SLI |
| Currency | decimals | 8 |
| Supply | supply_cap (base units) | 2100000000000000 |
| Minting | minting | disabled |
| Fees | base | 10000 |
| Fees | per_byte | 20 |
| Fees | currency | SLI |
| Fee distribution | validators_bps | 4000 |
| Fee distribution | workers_bps | 3000 |
| Fee distribution | treasury_bps | 2000 |
| Fee distribution | insurance_bps | 1000 |
| Fee distribution | burn_bps | 0 |
| Treasury | reward_pool_initial | 420000000000000 |
| Treasury | reward_cap_total | 420000000000000 |
| Rewards | mode | execution-mining |
| Rewards | rate_per_unit | 100000 |
| Rewards | max_per_epoch | 159800000 |
| Staking | min_stake | 100000000000 |
| Staking | bonding_ms | 259200000 |
| Staking | unbonding_ms | 604800000 |
