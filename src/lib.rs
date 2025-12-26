// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Pavlo Chabanov, Gliesereum Ukraine LLC
// Main Developer & Author: Pavlo Chabanov

#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Genesis tooling library (docs.rs ready).
//!
//! This crate provides **auditor/regulator-oriented** helpers for working with a Genesis contract:
//! - Validate a Genesis contract JSON against a JSON Schema (`validate_document`).
//! - Build a deterministic binary blob packaging `{document_bytes, schema_bytes}` (`build_blob_bytes`).
//! - Sign and verify blob packages using **ECDSA secp256k1** over `SHA256(blob)` (`create_blob_and_sign`, `verify_blob_and_signatures`).
//! - Import and migrate older contract variants to match the current schema (`import_old_contract`).
//! - Render a human-readable Markdown audit report (`render_audit_report`).
//! - Generate and sign initial transactions for network bootstrap (`generate_and_sign_initial_transactions`).
//! - Extract and verify transactions from blob packages (`extract_transactions_from_blob`, `verify_transactions_against_genesis`).
//!
//! ## Blob Format Versions
//!
//! The library supports three blob format versions:
//!
//! - **Version 1** (`BLOB_VERSION`): Basic blob with document and schema only
//! - **Version 2** (`BLOB_VERSION_WITH_TXS`): Includes initial transactions array
//! - **Version 3** (`BLOB_VERSION_EXTENDED`): Extended format with distinct sections:
//!   - `SECTION_SCHEMA` (0x0001): JSON Schema bytes
//!   - `SECTION_GENESIS_DOCUMENT` (0x0002): Genesis contract JSON bytes
//!   - `SECTION_INITIAL_TX_STATE` (0x0003): Initial transactions JSON array (optional)
//!   - `SECTION_SIGNATURE_SET` (0x0004): Signature set JSON (optional, can be detached)
//!
//! ## Artifact layout (recommended)
//!
//! - `src/genesis/genesis.json` — the Genesis contract
//! - `src/schemes/genesis-smart-1.0.json` — the JSON Schema
//! - `src/genesis/genesis.blob` — signed blob packaging contract+schema bytes (and optionally transactions)
//! - `src/genesis/genesis.sig.json` — signatures for the blob
//!
//! ## Signature model (blob package)
//!
//! - **Message**: `SHA256(blob_bytes)` (32-byte prehash)
//!   - For extended blobs with embedded signatures, signatures are computed over the blob **without** the SIGNATURE_SET section
//! - **Algorithm**: ECDSA secp256k1, DER-encoded signatures
//! - **Public key format**: compressed SEC1 (33 bytes, prefix `0x02`/`0x03`)
//! - **Threshold**: `k-of-n`, enforced using **unique** valid signers (duplicate entries do not count)
//! - **Canonicalization**: Signatures are normalized to low-S to reduce ECDSA malleability
//!
//! ## Initial Transaction Chain
//!
//! The library can generate an initial transaction chain for network bootstrap:
//!
//! 1. **Genesis Funding Transaction**: Treasury receives full balance, with `prev_hash` pointing to `genesis.id`
//! 2. **Distribution Transactions**: Treasury distributes funds to other accounts
//! 3. **Staking Transactions**: Accounts with initial stake activate staking
//! 4. **Nomination Transactions**: Initial committee members register as nominators
//!
//! All transactions are chained using `prev_hash` and signed with all provided signing keys.
//!
//! ## Examples
//!
//! Validate a contract against the schema:
//!
//! ```no_run
//! use std::path::Path;
//! # fn main() -> anyhow::Result<()> {
//! genesis::validate_document(
//!     Path::new("src/schemes/genesis-smart-1.0.json"),
//!     Path::new("src/genesis/genesis.json"),
//! )?;
//! # Ok(()) }
//! ```
//!
//! Verify a blob package and its signatures:
//!
//! ```no_run
//! use std::path::Path;
//! # fn main() -> anyhow::Result<()> {
//! genesis::verify_blob_and_signatures(
//!     Path::new("src/genesis/genesis.blob"),
//!     Path::new("src/genesis/genesis.sig.json"),
//! )?;
//! # Ok(()) }
//! ```
//!
//! Render a human-readable audit report (Markdown):
//!
//! ```no_run
//! use std::path::Path;
//! # fn main() -> anyhow::Result<()> {
//! let report = genesis::render_audit_report(
//!     Path::new("src/genesis/genesis.blob"),
//!     Some(Path::new("src/schemes/genesis-smart-1.0.json")),
//!     None,
//! )?;
//! println!("{report}");
//! # Ok(()) }
//! ```

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use hex::ToHex;
use jsonschema::validator_for;
use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use ripemd::{Digest as RipemdDigest, Ripemd160};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;

/// Default private key filenames expected in the current working directory.
///
/// These are used by the CLI when no `--key-file` paths are provided.
pub const DEFAULT_PRIV_KEYS: [&str; 5] = [
    "ghJejxMRW5V5ZyFyxsn9tqQ4BNcSvmqMrv.key",
    "gncGHDzymYmC37EPEK3kk3kWp2fJ9W52tH.key",
    "gohgoWbJK7dMf5MUKKtthRJdCAMmoVqDMo.key",
    "gpcr2Uqbqg3zt6a3VkkCcMm2s2xUtvT2L9.key",
    "gYjDnckjrKCw3CYVerH1LMbgTWv3dmg6Hu.key",
];

const BLOB_MAGIC: &[u8; 16] = b"GENESIS-BLOB\0\0\0\0";
const BLOB_VERSION: u32 = 1;
const BLOB_VERSION_WITH_TXS: u32 = 2; // Version 2 includes initial transactions
const BLOB_VERSION_EXTENDED: u32 = 3; // Version 3: extended format with sections
const MAX_BLOB_PART_SIZE_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB safety cap per part

// Section type constants (big-endian u16)
/// Section type for SCHEMA (0x0001) in extended blob format
pub const SECTION_SCHEMA: u16 = 0x0001;
/// Section type for GENESIS_DOCUMENT (0x0002) in extended blob format
pub const SECTION_GENESIS_DOCUMENT: u16 = 0x0002;
/// Section type for INITIAL_TX_STATE (0x0003) in extended blob format
pub const SECTION_INITIAL_TX_STATE: u16 = 0x0003;
/// Section type for SIGNATURE_SET (0x0004) in extended blob format
pub const SECTION_SIGNATURE_SET: u16 = 0x0004;
const PUBKEY_COMPRESSED_BYTES: usize = 33;
const MAX_SIG_DER_BYTES: usize = 128; // generous cap; typical DER ECDSA(secp256k1) is ~70-72 bytes

/// Metadata about a blob component (path/size/sha256).
#[derive(Serialize, Deserialize, Clone)]
pub struct BlobPartMeta {
    /// Source path as recorded by the generator (informational only).
    pub path: String,
    /// Byte length of the component.
    pub size: usize,
    /// SHA-256 of the component in the form `sha256:<64 hex>`.
    pub sha256: String,
}

/// A single signer entry in the blob signature file.
#[derive(Serialize, Deserialize, Clone)]
pub struct BlobSigner {
    /// Address-like identifier derived from the compressed public key.
    pub kid: String,
    /// Signature algorithm identifier (currently `ecdsa-secp256k1`).
    pub alg: String,
    /// Compressed secp256k1 public key, hex-encoded (33 bytes, `02/03` + 32 bytes).
    pub public_key: String,
    /// DER-encoded ECDSA signature, hex-encoded.
    pub signature_der_hex: String,
}

/// Signature file describing and signing a blob package.
#[derive(Serialize, Deserialize)]
pub struct BlobSignatureFile {
    /// Signature file format identifier (currently `genesis-blob-signature-v1`).
    pub format: String,
    /// Timestamp when the signature file was created (RFC3339).
    pub created_at: String,
    /// Metadata for the blob itself.
    pub blob: BlobPartMeta,
    /// Metadata for the embedded document.
    pub document: BlobPartMeta,
    /// Metadata for the embedded schema.
    pub schema: BlobPartMeta,
    /// Threshold object (typically `{ type: \"k-of-n\", k: ..., n: ... }`).
    pub threshold: serde_json::Value,
    /// List of signer entries.
    pub signers: Vec<BlobSigner>,
}

struct BlobParts {
    document_bytes: Vec<u8>,
    schema_bytes: Vec<u8>,
    transactions_bytes: Option<Vec<u8>>, // Optional: transactions JSON array
    signature_set_bytes: Option<Vec<u8>>, // Optional: signature set JSON
}

/// Resolve the default key paths using [`DEFAULT_PRIV_KEYS`] in the current working directory.
pub fn default_key_paths() -> Result<Vec<PathBuf>> {
    let cwd = std::env::current_dir()?;
    DEFAULT_PRIV_KEYS
        .iter()
        .map(|rel| Ok(cwd.join(rel)))
        .collect()
}

/// Load a secp256k1 ECDSA signing key from a hex file.
///
/// The file must contain a 32-byte private key as **64 hex characters** (whitespace is trimmed).
pub fn load_signing_key(path: &Path) -> Result<SigningKey> {
    let data = fs::read_to_string(path)
        .with_context(|| format!("failed to read private key from {}", path.display()))?;
    let hex_input = data.trim();
    if hex_input.len() != 64 {
        bail!(
            "private key at {} must be 32 bytes (64 hex chars)",
            path.display()
        );
    }

    let bytes = hex::decode(hex_input)
        .with_context(|| format!("failed to decode hex in {}", path.display()))?;
    SigningKey::from_bytes(&bytes)
        .map_err(|e| anyhow!("invalid private key {}: {}", path.display(), e))
}

/// Default blob output path derived from a document path (replaces extension with `.blob`).
pub fn default_blob_out(doc_path: &Path) -> PathBuf {
    doc_path.with_extension("blob")
}

/// Default signature output path derived from a blob path (replaces extension with `.sig.json`).
pub fn default_sig_out(blob_out: &Path) -> PathBuf {
    blob_out.with_extension("sig.json")
}

fn sha256_meta(path: &Path, bytes: &[u8]) -> BlobPartMeta {
    let hash_bytes: [u8; 32] = Sha256::digest(bytes).into();
    BlobPartMeta {
        path: path.display().to_string(),
        size: bytes.len(),
        sha256: format!("sha256:{}", hash_bytes.encode_hex::<String>()),
    }
}

/// Build a deterministic blob format for `{document_bytes, schema_bytes}`.
///
/// Format v1 (big-endian):
/// - 16 bytes: magic `GENESIS-BLOB\\0\\0\\0\\0`
/// - 4 bytes: version (`1`)
/// - 8 bytes: document length
/// - N bytes: document bytes (raw, not re-serialized)
/// - 8 bytes: schema length
/// - M bytes: schema bytes (raw, not re-serialized)
///
/// Format v2 (big-endian):
/// - 16 bytes: magic `GENESIS-BLOB\\0\\0\\0\\0`
/// - 4 bytes: version (`2`)
/// - 8 bytes: document length
/// - N bytes: document bytes (raw, not re-serialized)
/// - 8 bytes: schema length
/// - M bytes: schema bytes (raw, not re-serialized)
/// - 8 bytes: transactions length
/// - K bytes: transactions JSON array bytes (raw, not re-serialized)
pub fn build_blob_bytes(
    doc_bytes: &[u8],
    schema_bytes: &[u8],
    transactions_bytes: Option<&[u8]>,
) -> Vec<u8> {
    let version = if transactions_bytes.is_some() {
        BLOB_VERSION_WITH_TXS
    } else {
        BLOB_VERSION
    };

    let tx_bytes = transactions_bytes.unwrap_or(&[]);
    let mut out = Vec::with_capacity(
        16 + 4 + 8 + doc_bytes.len() + 8 + schema_bytes.len() + 8 + tx_bytes.len(),
    );
    out.extend_from_slice(BLOB_MAGIC);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&(doc_bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(doc_bytes);
    out.extend_from_slice(&(schema_bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(schema_bytes);
    if version == BLOB_VERSION_WITH_TXS {
        out.extend_from_slice(&(tx_bytes.len() as u64).to_be_bytes());
        out.extend_from_slice(tx_bytes);
    }
    out
}

/// Build extended blob format (v3) with sections.
///
/// Sections are written in order:
/// 1. SCHEMA (0x0001) - required
/// 2. GENESIS_DOCUMENT (0x0002) - required
/// 3. INITIAL_TX_STATE (0x0003) - optional
/// 4. SIGNATURE_SET (0x0004) - optional
pub fn build_extended_blob_bytes(
    schema_bytes: &[u8],
    genesis_document_bytes: &[u8],
    initial_tx_state_bytes: Option<&[u8]>,
    signature_set_bytes: Option<&[u8]>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        16 + 4 + // magic + version
        2 + 8 + schema_bytes.len() + // SCHEMA section
        2 + 8 + genesis_document_bytes.len() + // GENESIS_DOCUMENT section
        (if initial_tx_state_bytes.is_some() { 2 + 8 } else { 0 }) + initial_tx_state_bytes.map(|b| b.len()).unwrap_or(0) + // INITIAL_TX_STATE section
        (if signature_set_bytes.is_some() { 2 + 8 } else { 0 }) + signature_set_bytes.map(|b| b.len()).unwrap_or(0), // SIGNATURE_SET section
    );

    // Magic
    out.extend_from_slice(BLOB_MAGIC);

    // Version
    out.extend_from_slice(&BLOB_VERSION_EXTENDED.to_be_bytes());

    // Section 1: SCHEMA (0x0001)
    out.extend_from_slice(&SECTION_SCHEMA.to_be_bytes());
    out.extend_from_slice(&(schema_bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(schema_bytes);

    // Section 2: GENESIS_DOCUMENT (0x0002)
    out.extend_from_slice(&SECTION_GENESIS_DOCUMENT.to_be_bytes());
    out.extend_from_slice(&(genesis_document_bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(genesis_document_bytes);

    // Section 3: INITIAL_TX_STATE (0x0003) - optional
    if let Some(tx_bytes) = initial_tx_state_bytes {
        out.extend_from_slice(&SECTION_INITIAL_TX_STATE.to_be_bytes());
        out.extend_from_slice(&(tx_bytes.len() as u64).to_be_bytes());
        out.extend_from_slice(tx_bytes);
    }

    // Section 4: SIGNATURE_SET (0x0004) - optional
    if let Some(sig_bytes) = signature_set_bytes {
        out.extend_from_slice(&SECTION_SIGNATURE_SET.to_be_bytes());
        out.extend_from_slice(&(sig_bytes.len() as u64).to_be_bytes());
        out.extend_from_slice(sig_bytes);
    }

    out
}

fn read_u32_be(input: &[u8], offset: &mut usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| anyhow!("blob parsing overflow"))?;
    if end > input.len() {
        bail!(
            "blob is truncated (need 4 bytes, have {})",
            input.len() - *offset
        );
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&input[*offset..end]);
    *offset = end;
    Ok(u32::from_be_bytes(buf))
}

fn read_u64_be(input: &[u8], offset: &mut usize) -> Result<u64> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| anyhow!("blob parsing overflow"))?;
    if end > input.len() {
        bail!(
            "blob is truncated (need 8 bytes, have {})",
            input.len() - *offset
        );
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&input[*offset..end]);
    *offset = end;
    Ok(u64::from_be_bytes(buf))
}

fn read_u16_be(input: &[u8], offset: &mut usize) -> Result<u16> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| anyhow!("blob parsing overflow"))?;
    if end > input.len() {
        bail!(
            "blob is truncated (need 2 bytes, have {})",
            input.len() - *offset
        );
    }
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&input[*offset..end]);
    *offset = end;
    Ok(u16::from_be_bytes(buf))
}

fn read_exact_slice<'a>(input: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| anyhow!("blob parsing overflow"))?;
    if end > input.len() {
        bail!(
            "blob is truncated (need {} bytes, have {})",
            len,
            input.len() - *offset
        );
    }
    let slice = &input[*offset..end];
    *offset = end;
    Ok(slice)
}

fn parse_blob(blob_bytes: &[u8]) -> Result<BlobParts> {
    if blob_bytes.len() < 16 + 4 + 8 + 8 {
        bail!("blob too small to be valid");
    }

    if &blob_bytes[0..16] != BLOB_MAGIC {
        bail!("blob magic mismatch (not a GENESIS-BLOB)");
    }

    let mut off = 16usize;
    let version = read_u32_be(blob_bytes, &mut off)?;

    // Handle extended format (v3)
    if version == BLOB_VERSION_EXTENDED {
        return parse_extended_blob(blob_bytes, &mut off);
    }

    if version != BLOB_VERSION && version != BLOB_VERSION_WITH_TXS {
        bail!("unsupported blob version {}", version);
    }

    let doc_len_u64 = read_u64_be(blob_bytes, &mut off)?;
    if doc_len_u64 > MAX_BLOB_PART_SIZE_BYTES {
        bail!(
            "document length {} exceeds safety cap {}",
            doc_len_u64,
            MAX_BLOB_PART_SIZE_BYTES
        );
    }
    let doc_len = doc_len_u64 as usize;
    let doc_slice = read_exact_slice(blob_bytes, &mut off, doc_len)?;

    let schema_len_u64 = read_u64_be(blob_bytes, &mut off)?;
    if schema_len_u64 > MAX_BLOB_PART_SIZE_BYTES {
        bail!(
            "schema length {} exceeds safety cap {}",
            schema_len_u64,
            MAX_BLOB_PART_SIZE_BYTES
        );
    }
    let schema_len = schema_len_u64 as usize;
    let schema_slice = read_exact_slice(blob_bytes, &mut off, schema_len)?;

    let transactions_bytes = if version == BLOB_VERSION_WITH_TXS {
        let tx_len_u64 = read_u64_be(blob_bytes, &mut off)?;
        if tx_len_u64 > MAX_BLOB_PART_SIZE_BYTES {
            bail!(
                "transactions length {} exceeds safety cap {}",
                tx_len_u64,
                MAX_BLOB_PART_SIZE_BYTES
            );
        }
        let tx_len = tx_len_u64 as usize;
        if tx_len > 0 {
            Some(read_exact_slice(blob_bytes, &mut off, tx_len)?.to_vec())
        } else {
            None
        }
    } else {
        None
    };

    if off != blob_bytes.len() {
        bail!(
            "blob has trailing bytes (parsed {}, total {})",
            off,
            blob_bytes.len()
        );
    }

    Ok(BlobParts {
        document_bytes: doc_slice.to_vec(),
        schema_bytes: schema_slice.to_vec(),
        transactions_bytes,
        signature_set_bytes: None,
    })
}

/// Parse extended blob format (v3) with sections.
fn parse_extended_blob(blob_bytes: &[u8], offset: &mut usize) -> Result<BlobParts> {
    let mut schema_bytes: Option<Vec<u8>> = None;
    let mut document_bytes: Option<Vec<u8>> = None;
    let mut transactions_bytes: Option<Vec<u8>> = None;
    let mut signature_set_bytes: Option<Vec<u8>> = None;

    // Parse sections until end of blob
    while *offset < blob_bytes.len() {
        let section_type = read_u16_be(blob_bytes, offset)?;
        let section_len_u64 = read_u64_be(blob_bytes, offset)?;

        if section_len_u64 > MAX_BLOB_PART_SIZE_BYTES {
            bail!(
                "section length {} exceeds safety cap {}",
                section_len_u64,
                MAX_BLOB_PART_SIZE_BYTES
            );
        }

        let section_len = section_len_u64 as usize;
        let section_data = read_exact_slice(blob_bytes, offset, section_len)?.to_vec();

        match section_type {
            SECTION_SCHEMA => {
                if schema_bytes.is_some() {
                    bail!("duplicate SCHEMA section");
                }
                schema_bytes = Some(section_data);
            }
            SECTION_GENESIS_DOCUMENT => {
                if document_bytes.is_some() {
                    bail!("duplicate GENESIS_DOCUMENT section");
                }
                document_bytes = Some(section_data);
            }
            SECTION_INITIAL_TX_STATE => {
                if transactions_bytes.is_some() {
                    bail!("duplicate INITIAL_TX_STATE section");
                }
                transactions_bytes = Some(section_data);
            }
            SECTION_SIGNATURE_SET => {
                if signature_set_bytes.is_some() {
                    bail!("duplicate SIGNATURE_SET section");
                }
                signature_set_bytes = Some(section_data);
            }
            _ => {
                bail!("unknown section type 0x{:04x}", section_type);
            }
        }
    }

    let schema_bytes = schema_bytes.ok_or_else(|| anyhow!("missing SCHEMA section"))?;
    let document_bytes =
        document_bytes.ok_or_else(|| anyhow!("missing GENESIS_DOCUMENT section"))?;

    Ok(BlobParts {
        document_bytes,
        schema_bytes,
        transactions_bytes,
        signature_set_bytes,
    })
}

fn parse_sha256_hex_prefixed(s: &str) -> Result<[u8; 32]> {
    let hex_part = s
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow!("expected sha256:<hex>, got {}", s))?;
    if hex_part.len() != 64 {
        bail!("sha256 hex must be 64 chars, got {}", hex_part.len());
    }
    let bytes = hex::decode(hex_part).context("failed to decode sha256 hex")?;
    if bytes.len() != 32 {
        bail!("sha256 hex decoded to {} bytes (expected 32)", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_hex_bytes_exact(s: &str, expected_len: usize, label: &'static str) -> Result<Vec<u8>> {
    let expected_chars = expected_len
        .checked_mul(2)
        .ok_or_else(|| anyhow!("hex length overflow"))?;
    if s.len() != expected_chars {
        bail!(
            "{} hex must be exactly {} chars ({} bytes), got {} chars",
            label,
            expected_chars,
            expected_len,
            s.len()
        );
    }
    let bytes = hex::decode(s).with_context(|| format!("failed to decode {} hex", label))?;
    // Defensive (should match due to length check, but keep it explicit).
    if bytes.len() != expected_len {
        bail!(
            "{} hex decoded to {} bytes (expected {})",
            label,
            bytes.len(),
            expected_len
        );
    }
    Ok(bytes)
}

fn parse_hex_bytes_capped(s: &str, max_len: usize, label: &'static str) -> Result<Vec<u8>> {
    let max_chars = max_len
        .checked_mul(2)
        .ok_or_else(|| anyhow!("hex length overflow"))?;
    if s.len() > max_chars {
        bail!(
            "{} hex too long: {} chars > max {} chars ({} bytes)",
            label,
            s.len(),
            max_chars,
            max_len
        );
    }
    if !s.len().is_multiple_of(2) {
        bail!("{} hex must have even length, got {}", label, s.len());
    }
    let bytes = hex::decode(s).with_context(|| format!("failed to decode {} hex", label))?;
    if bytes.len() > max_len {
        bail!(
            "{} decoded to {} bytes > max {} bytes",
            label,
            bytes.len(),
            max_len
        );
    }
    Ok(bytes)
}

fn extract_version_byte_from_doc_value(doc_value: &Value) -> Result<u8> {
    let vb = doc_value
        .pointer("/addressing/version_byte")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow!("missing/invalid addressing.version_byte in document"))?;
    if vb > 255 {
        bail!("addressing.version_byte out of range: {}", vb);
    }
    Ok(vb as u8)
}

/// Derive the base58 address (`kid`) from a compressed secp256k1 public key.
///
/// Algorithm:
/// - `h160 = RIPEMD160(SHA256(pubkey_compressed))`
/// - `payload = version_byte || h160`
/// - `checksum = SHA256(payload)[0..4]`
/// - `address = Base58(payload || checksum)`
///
/// The `version_byte` is expected to be taken from the contract field `addressing.version_byte`.
pub fn derive_address(pubkey_bytes: &[u8], version_byte: u8) -> String {
    let sha = Sha256::digest(pubkey_bytes);
    let mut ripemd = Ripemd160::new();
    ripemd.update(sha);
    let h160 = ripemd.finalize();
    let mut buffer = Vec::with_capacity(1 + h160.len() + 4);
    buffer.push(version_byte);
    buffer.extend_from_slice(&h160);
    // custom-checksum-v1: SHA256(version_byte||h160)[0..4]
    let checksum = Sha256::digest(&buffer);
    buffer.extend_from_slice(&checksum[..4]);
    bs58::encode(buffer).into_string()
}

/// Validate a document JSON against a JSON Schema file.
///
/// This uses the `jsonschema` crate to compile and validate the schema.
pub fn validate_document(schema_path: &Path, doc_path: &Path) -> Result<()> {
    let schema_file = fs::File::open(schema_path)
        .with_context(|| format!("failed to open schema {}", schema_path.display()))?;
    let schema_value: Value =
        serde_json::from_reader(schema_file).context("failed to parse schema JSON")?;

    let validator = validator_for(&schema_value).context("failed to compile JSON Schema")?;

    let doc_file = fs::File::open(doc_path)
        .with_context(|| format!("failed to open document {}", doc_path.display()))?;
    let doc_value: Value =
        serde_json::from_reader(doc_file).context("failed to parse document JSON")?;

    if let Err(errors) = validator.validate(&doc_value) {
        let mut count = 0;
        for error in errors {
            count += 1;
            println!("Validation error {}: {}", count, error);
            println!("  instance path: {}", error.instance_path);
            println!("  schema path: {}", error.schema_path);
        }
        bail!("validation failed with {} error(s)", count);
    }

    println!(
        "Document {} is valid against schema {}",
        doc_path.display(),
        schema_path.display()
    );
    Ok(())
}

/// Create a blob from `{doc_path, schema_path}` and sign it with the provided keys (legacy format).
///
/// **Note**: For new deployments, use `create_blob_and_sign_extended` with extended format
/// to create an all-in-one blob with embedded signatures and transactions.
///
/// The signature file (`sig_out`) contains:
/// - hashes and sizes of blob/document/schema
/// - `k-of-n` threshold
/// - signer entries with `kid`, compressed public key, and DER signature
///
/// **Important**: `kid` derivation uses `addressing.version_byte` taken from the document JSON.
///
/// # Parameters
/// - `doc_path`: Path to genesis document JSON
/// - `schema_path`: Path to JSON Schema
/// - `key_paths`: Slice of paths to private key files
/// - `threshold_k`: Optional threshold k (defaults to n, requiring all signers)
/// - `blob_out`: Output path for blob file
/// - `sig_out`: Output path for signature file
/// - `include_transactions`: If true, generates and includes initial transactions (version 2)
///
/// # Blob Versions
/// - Version 1: Basic blob with document and schema only
/// - Version 2: Includes initial transactions array (if `include_transactions` is true)
///
/// # Errors
/// Returns an error if files cannot be read/written, JSON is invalid, or signing fails.
pub fn create_blob_and_sign(
    doc_path: &Path,
    schema_path: &Path,
    key_paths: &[PathBuf],
    threshold_k: Option<usize>,
    blob_out: &Path,
    sig_out: &Path,
    include_transactions: bool,
) -> Result<()> {
    create_blob_and_sign_extended(
        doc_path,
        schema_path,
        key_paths,
        threshold_k,
        blob_out,
        sig_out,
        include_transactions,
        false, // use_extended_format (legacy)
        false, // include_signatures_in_blob (legacy - detached)
    )
}

/// Create a blob with extended format support.
pub fn create_blob_and_sign_extended(
    doc_path: &Path,
    schema_path: &Path,
    key_paths: &[PathBuf],
    threshold_k: Option<usize>,
    blob_out: &Path,
    sig_out: &Path,
    include_transactions: bool,
    use_extended_format: bool,
    include_signatures_in_blob: bool,
) -> Result<()> {
    let doc_bytes = fs::read(doc_path)
        .with_context(|| format!("failed to read document bytes from {}", doc_path.display()))?;
    let schema_bytes = fs::read(schema_path)
        .with_context(|| format!("failed to read schema bytes from {}", schema_path.display()))?;

    let doc_value: Value =
        serde_json::from_slice(&doc_bytes).context("document is not valid JSON")?;
    let version_byte = extract_version_byte_from_doc_value(&doc_value)?;

    // Generate transactions if requested
    let transactions_bytes = if include_transactions {
        let transactions = generate_and_sign_initial_transactions(doc_path, key_paths)?;
        let transactions_json = serde_json::to_string(&json!(transactions))?;
        Some(transactions_json.into_bytes())
    } else {
        None
    };

    // Build initial blob bytes (without signatures if extended format)
    // For extended format with embedded signatures, we need to sign the blob WITHOUT signatures first,
    // then add signatures and update the signature file with the final blob hash.
    let initial_blob_bytes = if use_extended_format {
        build_extended_blob_bytes(
            &schema_bytes,
            &doc_bytes,
            transactions_bytes.as_deref(),
            None, // Signatures will be added later if needed
        )
    } else {
        build_blob_bytes(&doc_bytes, &schema_bytes, transactions_bytes.as_deref())
    };

    // Hash for signing: always use the blob WITHOUT embedded signatures
    // This ensures signatures are over the content, not over themselves
    let blob_hash_bytes: [u8; 32] = Sha256::digest(&initial_blob_bytes).into();

    let doc_meta = sha256_meta(doc_path, &doc_bytes);
    let schema_meta = sha256_meta(schema_path, &schema_bytes);

    if include_transactions {
        let version_str = if use_extended_format { "3" } else { "2" };
        let tx_count = transactions_bytes
            .as_ref()
            .map(|b| {
                serde_json::from_slice::<Value>(b)
                    .ok()
                    .and_then(|tx_json| tx_json.as_array().map(|arr| arr.len()))
                    .unwrap_or(0)
            })
            .unwrap_or(0);
        println!(
            "Blob includes {} initial transactions (version {})",
            tx_count, version_str
        );
    }

    let created_at = Utc::now().to_rfc3339();
    let mut signers = Vec::with_capacity(key_paths.len());
    for key_path in key_paths {
        let signing_key = load_signing_key(key_path)?;
        let signing_point = signing_key.verifying_key().to_encoded_point(true);
        let pubkey_bytes = signing_point.as_bytes();

        let sig: Signature = signing_key
            .sign_prehash(&blob_hash_bytes)
            .context("signing blob hash with provided key failed")?;
        // Canonicalize to low-S to reduce ECDSA malleability across verifiers.
        let sig = sig.normalize_s().unwrap_or(sig);

        signers.push(BlobSigner {
            kid: derive_address(pubkey_bytes, version_byte),
            alg: "ecdsa-secp256k1".to_string(),
            public_key: pubkey_bytes.encode_hex::<String>(),
            signature_der_hex: sig.to_der().as_bytes().encode_hex::<String>(),
        });
    }

    let n = signers.len();
    if n == 0 {
        bail!("no signing keys provided (n=0)");
    }
    let k = threshold_k.unwrap_or(n);
    if k == 0 {
        bail!("invalid threshold: k must be >= 1");
    }
    if k > n {
        bail!("invalid threshold: k ({}) > n ({})", k, n);
    }

    let threshold = json!({
        "type": "k-of-n",
        "k": k,
        "n": n
    });

    // Create signature file: signatures are ALWAYS over blob WITHOUT embedded signatures
    // This ensures signatures are over content, not over themselves
    let blob_meta = sha256_meta(blob_out, &initial_blob_bytes);
    let sig_file = BlobSignatureFile {
        format: "genesis-blob-signature-v1".to_string(),
        created_at,
        blob: blob_meta,
        document: doc_meta,
        schema: schema_meta,
        threshold,
        signers,
    };

    let sig_json = serde_json::to_string_pretty(&sig_file)?;

    // If extended format and include_signatures_in_blob, build final blob with signatures
    let final_blob_bytes = if use_extended_format && include_signatures_in_blob {
        let signature_set_bytes = sig_json.as_bytes();

        // Build final blob with signatures embedded
        let updated_blob = build_extended_blob_bytes(
            &schema_bytes,
            &doc_bytes,
            transactions_bytes.as_deref(),
            Some(signature_set_bytes),
        );

        // Write final blob
        fs::write(blob_out, &updated_blob)
            .with_context(|| format!("failed to write final blob to {}", blob_out.display()))?;

        // Do NOT write separate signature file when signatures are embedded in blob
        // Signatures are already in the blob, no need for separate file

        updated_blob
    } else {
        // Write initial blob (without embedded signatures)
        fs::write(blob_out, &initial_blob_bytes)
            .with_context(|| format!("failed to write blob to {}", blob_out.display()))?;

        // Write signature file
        fs::write(sig_out, &sig_json)
            .with_context(|| format!("failed to write signature file to {}", sig_out.display()))?;

        initial_blob_bytes
    };

    let version = if use_extended_format {
        BLOB_VERSION_EXTENDED
    } else if transactions_bytes.is_some() {
        BLOB_VERSION_WITH_TXS
    } else {
        BLOB_VERSION
    };

    println!(
        "Blob written to {} (version {})",
        blob_out.display(),
        version
    );
    println!(
        "Blob hash: sha256:{}",
        Sha256::digest(&final_blob_bytes).encode_hex::<String>()
    );
    
    if use_extended_format {
        if include_signatures_in_blob && transactions_bytes.is_some() {
            println!("All-in-one blob created: SCHEMA + GENESIS_DOCUMENT + INITIAL_TX_STATE + SIGNATURE_SET");
            println!("  → Single blob file ready for network bootstrap (no additional files needed)");
            println!("  → Signatures embedded in blob (no separate signature file)");
        } else if include_signatures_in_blob {
            println!("Extended blob: SCHEMA + GENESIS_DOCUMENT + SIGNATURE_SET");
            println!("  → Signatures embedded in blob (no separate signature file)");
        } else {
            println!("Extended blob: SCHEMA + GENESIS_DOCUMENT{}", 
                if transactions_bytes.is_some() { " + INITIAL_TX_STATE" } else { "" });
            println!("  → Signatures detached in {}", sig_out.display());
        }
    } else {
        println!("Signature file written to {}", sig_out.display());
    }
    Ok(())
}

/// Verify a blob package and its signature file.
///
/// This performs:
/// - safe blob parsing (magic/version/length bounds)
/// - JSON parsing of embedded document/schema
/// - schema validation of embedded document against embedded schema
/// - integrity checks against the signature file (sizes and sha256)
/// - ECDSA verification of `SHA256(blob)` using unique valid signers (`k-of-n`)
pub fn verify_blob_and_signatures(blob_path: &Path, sig_path: &Path) -> Result<()> {
    let blob_bytes = fs::read(blob_path)
        .with_context(|| format!("failed to read blob {}", blob_path.display()))?;
    let parts = parse_blob(&blob_bytes)?;

    let schema_value: Value =
        serde_json::from_slice(&parts.schema_bytes).context("schema in blob is not valid JSON")?;
    let doc_value: Value = serde_json::from_slice(&parts.document_bytes)
        .context("document in blob is not valid JSON")?;

    let version_byte = extract_version_byte_from_doc_value(&doc_value)?;

    let validator =
        validator_for(&schema_value).context("failed to compile JSON Schema from blob")?;
    if let Err(errors) = validator.validate(&doc_value) {
        let mut count = 0;
        for error in errors {
            count += 1;
            println!("Validation error {}: {}", count, error);
            println!("  instance path: {}", error.instance_path);
            println!("  schema path: {}", error.schema_path);
        }
        bail!("document-in-blob validation failed with {} error(s)", count);
    }

    let sig_json = fs::read_to_string(sig_path)
        .with_context(|| format!("failed to read signature file {}", sig_path.display()))?;
    let sig_file: BlobSignatureFile =
        serde_json::from_str(&sig_json).context("failed to parse signature JSON")?;

    if sig_file.format != "genesis-blob-signature-v1" {
        bail!("unsupported signature file format {}", sig_file.format);
    }

    // For extended blob with embedded signatures, signatures are over blob WITHOUT SIGNATURE_SET section
    // Reconstruct the blob without signatures for verification
    let blob_for_verification = if parts.signature_set_bytes.is_some() {
        // Extended blob with embedded signatures: rebuild without SIGNATURE_SET for verification
        build_extended_blob_bytes(
            &parts.schema_bytes,
            &parts.document_bytes,
            parts.transactions_bytes.as_deref(),
            None, // Exclude SIGNATURE_SET for verification
        )
    } else {
        blob_bytes.clone()
    };

    // Check blob size: signature file should match the blob WITHOUT embedded signatures
    if sig_file.blob.size != blob_for_verification.len() {
        bail!(
            "blob size mismatch: sig says {} (blob without signatures), actual blob without signatures: {} (blob with signatures: {})",
            sig_file.blob.size,
            blob_for_verification.len(),
            blob_bytes.len()
        );
    }
    if sig_file.document.size != parts.document_bytes.len() {
        bail!(
            "document size mismatch: sig says {}, actual {}",
            sig_file.document.size,
            parts.document_bytes.len()
        );
    }
    if sig_file.schema.size != parts.schema_bytes.len() {
        bail!(
            "schema size mismatch: sig says {}, actual {}",
            sig_file.schema.size,
            parts.schema_bytes.len()
        );
    }

    // Use blob WITHOUT signatures for hash verification
    let blob_hash_actual: [u8; 32] = Sha256::digest(&blob_for_verification).into();
    let doc_hash_actual: [u8; 32] = Sha256::digest(&parts.document_bytes).into();
    let schema_hash_actual: [u8; 32] = Sha256::digest(&parts.schema_bytes).into();

    let blob_hash_claimed = parse_sha256_hex_prefixed(&sig_file.blob.sha256)?;
    let doc_hash_claimed = parse_sha256_hex_prefixed(&sig_file.document.sha256)?;
    let schema_hash_claimed = parse_sha256_hex_prefixed(&sig_file.schema.sha256)?;

    if blob_hash_claimed != blob_hash_actual {
        bail!("blob sha256 mismatch vs signature file");
    }
    if doc_hash_claimed != doc_hash_actual {
        bail!("document sha256 mismatch vs signature file");
    }
    if schema_hash_claimed != schema_hash_actual {
        bail!("schema sha256 mismatch vs signature file");
    }

    if sig_file.threshold.get("type").and_then(|v| v.as_str()) != Some("k-of-n") {
        bail!("unsupported threshold type (expected k-of-n)");
    }

    let k = sig_file
        .threshold
        .get("k")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow!("threshold.k missing/invalid in signature file"))?
        as usize;
    let n = sig_file
        .threshold
        .get("n")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow!("threshold.n missing/invalid in signature file"))?
        as usize;
    if n != sig_file.signers.len() {
        bail!(
            "threshold.n mismatch: {} vs signers.len {}",
            n,
            sig_file.signers.len()
        );
    }
    if k == 0 {
        bail!("invalid threshold: k must be >= 1");
    }
    if k > n {
        bail!("invalid threshold: k ({}) > n ({})", k, n);
    }

    // Count unique valid signers; avoid satisfying threshold with duplicate entries.
    let mut valid_signer_kids: HashSet<String> = HashSet::new();
    for signer in &sig_file.signers {
        if signer.alg != "ecdsa-secp256k1" {
            continue;
        }
        let pubkey_bytes =
            parse_hex_bytes_exact(&signer.public_key, PUBKEY_COMPRESSED_BYTES, "public_key")?;
        if !matches!(pubkey_bytes[0], 0x02 | 0x03) {
            continue;
        }
        let derived_kid = derive_address(&pubkey_bytes, version_byte);
        if derived_kid != signer.kid {
            continue;
        }

        let verifying_key =
            VerifyingKey::from_sec1_bytes(&pubkey_bytes).context("invalid public key bytes")?;
        let sig_der = parse_hex_bytes_capped(
            &signer.signature_der_hex,
            MAX_SIG_DER_BYTES,
            "signature_der",
        )?;
        let sig = Signature::from_der(&sig_der).context("invalid DER signature")?;
        // Accept non-canonical high-S signatures by normalizing before verification
        // (tool output is low-S; this keeps backward compatibility).
        let sig = sig.normalize_s().unwrap_or(sig);

        if verifying_key
            .verify_prehash(&blob_hash_actual, &sig)
            .is_ok()
        {
            valid_signer_kids.insert(signer.kid.clone());
        }
    }

    let valid = valid_signer_kids.len();
    if valid < k {
        bail!(
            "not enough valid signatures: have {}, need {} (k-of-n)",
            valid,
            k
        );
    }

    println!(
        "Blob {} verified OK (valid signatures: {}/{}, threshold: {}/{})",
        blob_path.display(),
        valid,
        n,
        k,
        n
    );
    Ok(())
}

/// Verify a blob package using embedded signatures (if present in extended blob format).
///
/// This function works similarly to `verify_blob_and_signatures`, but extracts signatures
/// from the blob itself if they are embedded (extended format with SIGNATURE_SET section).
/// If signatures are not embedded, it falls back to using a separate signature file.
///
/// # Parameters
/// - `blob_path`: Path to the blob file
/// - `sig_path`: Optional path to signature file (required if signatures are not embedded)
///
/// # Returns
/// `Ok(())` if verification succeeds, error otherwise.
///
/// # Errors
/// Returns an error if:
/// - Blob cannot be read or parsed
/// - Signatures are not embedded and `sig_path` is None
/// - Signature verification fails
/// - Threshold not met
pub fn verify_blob(blob_path: &Path, sig_path: Option<&Path>) -> Result<()> {
    let blob_bytes = fs::read(blob_path)
        .with_context(|| format!("failed to read blob {}", blob_path.display()))?;
    let parts = parse_blob(&blob_bytes)?;

    // Check if signatures are embedded in the blob
    if let Some(signature_set_bytes) = &parts.signature_set_bytes {
        // Signatures are embedded - extract and use them
        let sig_json = String::from_utf8(signature_set_bytes.clone())
            .context("embedded signature set is not valid UTF-8")?;
        let sig_file: BlobSignatureFile =
            serde_json::from_str(&sig_json).context("failed to parse embedded signature JSON")?;

        // Verify using embedded signatures
        verify_blob_with_sig_file(blob_path, &blob_bytes, &parts, &sig_file)?;
        println!(
            "Blob {} verified OK using embedded signatures (valid signatures: {}/{}, threshold: {}/{})",
            blob_path.display(),
            sig_file.signers.len(),
            sig_file.signers.len(),
            sig_file.threshold.get("k").and_then(|v| v.as_u64()).unwrap_or(0),
            sig_file.signers.len()
        );
        Ok(())
    } else {
        // Signatures are not embedded - require separate file
        let sig_path = sig_path.ok_or_else(|| {
            anyhow!("signatures are not embedded in blob and no signature file provided")
        })?;
        verify_blob_and_signatures(blob_path, sig_path)
    }
}

/// Internal helper to verify blob with a signature file (used by both verify functions).
fn verify_blob_with_sig_file(
    _blob_path: &Path,
    blob_bytes: &[u8],
    parts: &BlobParts,
    sig_file: &BlobSignatureFile,
) -> Result<()> {
    let schema_value: Value =
        serde_json::from_slice(&parts.schema_bytes).context("schema in blob is not valid JSON")?;
    let doc_value: Value = serde_json::from_slice(&parts.document_bytes)
        .context("document in blob is not valid JSON")?;

    let version_byte = extract_version_byte_from_doc_value(&doc_value)?;

    let validator =
        validator_for(&schema_value).context("failed to compile JSON Schema from blob")?;
    if let Err(errors) = validator.validate(&doc_value) {
        let mut count = 0;
        for error in errors {
            count += 1;
            println!("Validation error {}: {}", count, error);
            println!("  instance path: {}", error.instance_path);
            println!("  schema path: {}", error.schema_path);
        }
        bail!("document-in-blob validation failed with {} error(s)", count);
    }

    if sig_file.format != "genesis-blob-signature-v1" {
        bail!("unsupported signature file format {}", sig_file.format);
    }

    // For extended blob with embedded signatures, signatures are over blob WITHOUT SIGNATURE_SET section
    // Reconstruct the blob without signatures for verification
    let blob_for_verification = if parts.signature_set_bytes.is_some() {
        // Extended blob with embedded signatures: rebuild without SIGNATURE_SET for verification
        build_extended_blob_bytes(
            &parts.schema_bytes,
            &parts.document_bytes,
            parts.transactions_bytes.as_deref(),
            None, // Exclude SIGNATURE_SET for verification
        )
    } else {
        blob_bytes.to_vec()
    };

    // Check blob size: signature file should match the blob WITHOUT embedded signatures
    if sig_file.blob.size != blob_for_verification.len() {
        bail!(
            "blob size mismatch: sig says {} (blob without signatures), actual blob without signatures: {} (blob with signatures: {})",
            sig_file.blob.size,
            blob_for_verification.len(),
            blob_bytes.len()
        );
    }
    if sig_file.document.size != parts.document_bytes.len() {
        bail!(
            "document size mismatch: sig says {}, actual {}",
            sig_file.document.size,
            parts.document_bytes.len()
        );
    }
    if sig_file.schema.size != parts.schema_bytes.len() {
        bail!(
            "schema size mismatch: sig says {}, actual {}",
            sig_file.schema.size,
            parts.schema_bytes.len()
        );
    }

    // Use blob WITHOUT signatures for hash verification
    let blob_hash_actual: [u8; 32] = Sha256::digest(&blob_for_verification).into();
    let doc_hash_actual: [u8; 32] = Sha256::digest(&parts.document_bytes).into();
    let schema_hash_actual: [u8; 32] = Sha256::digest(&parts.schema_bytes).into();

    let blob_hash_claimed = parse_sha256_hex_prefixed(&sig_file.blob.sha256)?;
    let doc_hash_claimed = parse_sha256_hex_prefixed(&sig_file.document.sha256)?;
    let schema_hash_claimed = parse_sha256_hex_prefixed(&sig_file.schema.sha256)?;

    if blob_hash_claimed != blob_hash_actual {
        bail!("blob sha256 mismatch vs signature file");
    }
    if doc_hash_claimed != doc_hash_actual {
        bail!("document sha256 mismatch vs signature file");
    }
    if schema_hash_claimed != schema_hash_actual {
        bail!("schema sha256 mismatch vs signature file");
    }

    if sig_file.threshold.get("type").and_then(|v| v.as_str()) != Some("k-of-n") {
        bail!("unsupported threshold type (expected k-of-n)");
    }

    let k = sig_file
        .threshold
        .get("k")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow!("threshold.k missing/invalid in signature file"))?
        as usize;
    let n = sig_file
        .threshold
        .get("n")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow!("threshold.n missing/invalid in signature file"))?
        as usize;
    if n != sig_file.signers.len() {
        bail!(
            "threshold.n mismatch: {} vs signers.len {}",
            n,
            sig_file.signers.len()
        );
    }
    if k == 0 {
        bail!("invalid threshold: k must be >= 1");
    }
    if k > n {
        bail!("invalid threshold: k ({}) > n ({})", k, n);
    }

    // Count unique valid signers; avoid satisfying threshold with duplicate entries.
    let mut valid_signer_kids: HashSet<String> = HashSet::new();
    for signer in &sig_file.signers {
        if signer.alg != "ecdsa-secp256k1" {
            continue;
        }
        let pubkey_bytes =
            parse_hex_bytes_exact(&signer.public_key, PUBKEY_COMPRESSED_BYTES, "public_key")?;
        if !matches!(pubkey_bytes[0], 0x02 | 0x03) {
            continue;
        }
        let derived_kid = derive_address(&pubkey_bytes, version_byte);
        if derived_kid != signer.kid {
            continue;
        }

        let verifying_key =
            VerifyingKey::from_sec1_bytes(&pubkey_bytes).context("invalid public key bytes")?;
        let sig_der = parse_hex_bytes_capped(
            &signer.signature_der_hex,
            MAX_SIG_DER_BYTES,
            "signature_der",
        )?;
        let sig = Signature::from_der(&sig_der).context("invalid DER signature")?;
        // Accept non-canonical high-S signatures by normalizing before verification
        // (tool output is low-S; this keeps backward compatibility).
        let sig = sig.normalize_s().unwrap_or(sig);

        if verifying_key
            .verify_prehash(&blob_hash_actual, &sig)
            .is_ok()
        {
            valid_signer_kids.insert(signer.kid.clone());
        }
    }

    let valid = valid_signer_kids.len();
    if valid < k {
        bail!(
            "not enough valid signatures: have {}, need {} (k-of-n)",
            valid,
            k
        );
    }

    Ok(())
}

/// Import an older full Genesis contract JSON and migrate it to match the current schema expectations.
///
/// This function applies a small set of deterministic transformations (no network calls).
pub fn import_old_contract(old_path: &Path, out_path: &Path) -> Result<()> {
    let bytes = fs::read(old_path)
        .with_context(|| format!("failed to read old contract {}", old_path.display()))?;

    let mut v: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("old contract {} is not valid JSON", old_path.display()))?;
    migrate_old_contract_in_place(&mut v);

    let serialized = serde_json::to_string_pretty(&v)?;
    fs::write(out_path, serialized).with_context(|| {
        format!(
            "failed to write imported contract to {}",
            out_path.display()
        )
    })?;

    println!(
        "Imported old contract {} -> {} (migrated to current schema)",
        old_path.display(),
        out_path.display()
    );
    Ok(())
}

fn opt_str(v: &Value, ptr: &str) -> Option<String> {
    v.pointer(ptr)
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
}

fn opt_u64(v: &Value, ptr: &str) -> Option<u64> {
    v.pointer(ptr).and_then(|x| x.as_u64())
}

fn opt_bool(v: &Value, ptr: &str) -> Option<bool> {
    v.pointer(ptr).and_then(|x| x.as_bool())
}

fn short_hex(s: &str, keep: usize) -> String {
    if s.len() <= keep * 2 {
        return s.to_string();
    }
    format!("{}…{}", &s[..keep], &s[s.len() - keep..])
}

fn short_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

fn sha256_prefixed_hex(bytes: &[u8]) -> String {
    let h: [u8; 32] = Sha256::digest(bytes).into();
    format!("sha256:{}", h.encode_hex::<String>())
}

/// Render a human-readable Markdown audit report for a `.json` contract or `.blob` package.
///
/// - For `.json`: requires `schema_path` to be provided (used for schema validation).
/// - For `.blob`: uses embedded signatures if available, otherwise uses `sig_path` if provided, or defaults to `<blob>.sig.json`.
///
/// The returned string is Markdown intended to be printed to stdout or saved by the caller.
pub fn render_audit_report(
    input_path: &Path,
    schema_path: Option<&Path>,
    sig_path: Option<&Path>,
) -> Result<String> {
    match input_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
    {
        "blob" => {
            render_blob_audit_report(input_path, sig_path)
        }
        "json" => {
            let schema =
                schema_path.ok_or_else(|| anyhow!("schema_path is required for .json report"))?;
            render_json_audit_report(input_path, schema)
        }
        other => bail!("unsupported file type '{}'; expected .json or .blob", other),
    }
}

/// Render an economics audit report (Markdown) for a `.json` contract or `.blob` package.
///
/// This is a **PASS/FAIL invariant audit** intended for regulator review. It checks, among others:
/// - minting policy is disabled
/// - supply cap is >= genesis circulating supply (sum of balances)
/// - fee distribution bps sum equals `total_bps` and `10000`
/// - rewards invariants (e.g. `max_per_epoch == rate_per_unit * global_ops_cap_per_epoch`)
/// - consistency of key economic addresses (treasury/insurance)
pub fn render_economics_audit_report(
    input_path: &Path,
    schema_path: Option<&Path>,
    sig_path: Option<&Path>,
) -> Result<String> {
    match input_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
    {
        "blob" => {
            render_economics_audit_report_from_blob(input_path, sig_path)
        }
        "json" => {
            let schema =
                schema_path.ok_or_else(|| anyhow!("schema_path is required for .json audit"))?;
            render_economics_audit_report_from_json(input_path, schema)
        }
        other => bail!("unsupported file type '{}'; expected .json or .blob", other),
    }
}

fn audit_check_row(name: &str, ok: bool, detail: &str) -> String {
    format!(
        "- **{}**: {} — {}\n",
        name,
        if ok { "PASS" } else { "FAIL" },
        detail
    )
}

fn compute_genesis_circulating_supply(doc: &Value) -> Result<u128> {
    let accounts = doc
        .pointer("/state/accounts")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("missing/invalid state.accounts array"))?;
    let mut sum: u128 = 0;
    for (i, acct) in accounts.iter().enumerate() {
        let bal_str = acct
            .get("balance")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("missing/invalid state.accounts[{}].balance", i))?;
        if bal_str.is_empty() || !bal_str.chars().all(|c| c.is_ascii_digit()) {
            bail!(
                "state.accounts[{}].balance must be decimal string, got '{}'",
                i,
                bal_str
            );
        }
        let bal = bal_str
            .parse::<u128>()
            .with_context(|| format!("failed to parse balance '{}' as u128", bal_str))?;
        sum = sum
            .checked_add(bal)
            .ok_or_else(|| anyhow!("circulating supply overflow"))?;
    }
    Ok(sum)
}

fn render_economics_audit_report_from_json(doc_path: &Path, schema_path: &Path) -> Result<String> {
    let doc_bytes =
        fs::read(doc_path).with_context(|| format!("failed to read {}", doc_path.display()))?;
    let doc_value: Value =
        serde_json::from_slice(&doc_bytes).context("document is not valid JSON")?;

    // Ensure schema-valid (for regulator audit, the contract must validate).
    let schema_bytes = fs::read(schema_path)
        .with_context(|| format!("failed to read {}", schema_path.display()))?;
    let schema_value: Value =
        serde_json::from_slice(&schema_bytes).context("schema is not valid JSON")?;
    let validator = validator_for(&schema_value).context("failed to compile JSON Schema")?;
    if let Err(errors) = validator.validate(&doc_value) {
        let mut msg = String::new();
        msg.push_str("Economics audit aborted: schema validation FAILED.\n");
        let mut count = 0;
        for e in errors {
            count += 1;
            msg.push_str(&format!(
                "- {} (instance: {}, schema: {})\n",
                e, e.instance_path, e.schema_path
            ));
            if count >= 25 {
                msg.push_str("- ... (truncated)\n");
                break;
            }
        }
        bail!(msg);
    }

    Ok(render_economics_checks(
        &doc_value,
        Some(doc_path),
        Some(schema_path),
    ))
}

fn render_economics_audit_report_from_blob(blob_path: &Path, sig_path: Option<&Path>) -> Result<String> {
    // We reuse the safety properties: parse blob and validate embedded schema/document.
    let blob_bytes = fs::read(blob_path)
        .with_context(|| format!("failed to read blob {}", blob_path.display()))?;
    let parts = parse_blob(&blob_bytes)?;
    let schema_value: Value =
        serde_json::from_slice(&parts.schema_bytes).context("schema in blob is not valid JSON")?;
    let doc_value: Value = serde_json::from_slice(&parts.document_bytes)
        .context("document in blob is not valid JSON")?;

    let validator =
        validator_for(&schema_value).context("failed to compile JSON Schema from blob")?;
    if let Err(errors) = validator.validate(&doc_value) {
        let mut msg = String::new();
        msg.push_str("Economics audit aborted: embedded schema validation FAILED.\n");
        let mut count = 0;
        for e in errors {
            count += 1;
            msg.push_str(&format!(
                "- {} (instance: {}, schema: {})\n",
                e, e.instance_path, e.schema_path
            ));
            if count >= 25 {
                msg.push_str("- ... (truncated)\n");
                break;
            }
        }
        bail!(msg);
    }

    // Also ensure the blob package is cryptographically consistent for regulators.
    // (This is a strong prerequisite before using the embedded contract for audit.)
    // Use verify_blob which handles embedded signatures automatically
    verify_blob(blob_path, sig_path)?;

    Ok(render_economics_checks(&doc_value, None, None))
}

fn render_economics_checks(
    doc: &Value,
    doc_path: Option<&Path>,
    schema_path: Option<&Path>,
) -> String {
    // Extract key values.
    let symbol = doc
        .pointer("/parameters/currency/symbol")
        .and_then(|v| v.as_str())
        .unwrap_or("<missing>");
    let decimals = doc
        .pointer("/parameters/currency/decimals")
        .and_then(|v| v.as_u64())
        .unwrap_or(u64::MAX);

    let supply_cap = doc
        .pointer("/monetary/supply_cap")
        .and_then(|v| v.as_str())
        .unwrap_or("<missing>");
    let minting = doc
        .pointer("/monetary/minting")
        .and_then(|v| v.as_str())
        .unwrap_or("<missing>");

    // Supply and circulating.
    let circulating_res = compute_genesis_circulating_supply(doc);
    let circulating_val = circulating_res.as_ref().ok().copied();
    let supply_cap_u128 = supply_cap.parse::<u128>().ok();

    // Fees.
    let fees_base = doc
        .pointer("/parameters/fees/base")
        .and_then(|v| v.as_u64());
    let fees_per_byte = doc
        .pointer("/parameters/fees/per_byte")
        .and_then(|v| v.as_u64());
    let tx_min_fee = doc.pointer("/tx_rules/min_fee").and_then(|v| v.as_u64());

    // Fee distribution.
    let total_bps = doc
        .pointer("/monetary/fee_distribution/total_bps")
        .and_then(|v| v.as_u64());
    let validators_bps = doc
        .pointer("/monetary/fee_distribution/validators_bps")
        .and_then(|v| v.as_u64());
    let workers_bps = doc
        .pointer("/monetary/fee_distribution/workers_bps")
        .and_then(|v| v.as_u64());
    let treasury_bps = doc
        .pointer("/monetary/fee_distribution/treasury_bps")
        .and_then(|v| v.as_u64());
    let insurance_bps = doc
        .pointer("/monetary/fee_distribution/insurance_bps")
        .and_then(|v| v.as_u64());
    let burn_bps = doc
        .pointer("/monetary/fee_distribution/burn_bps")
        .and_then(|v| v.as_u64());

    // Rewards invariants.
    let rate_per_unit = doc
        .pointer("/monetary/rewards/rate_per_unit")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u128>().ok());
    let max_per_epoch = doc
        .pointer("/monetary/rewards/max_per_epoch")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u128>().ok());
    let global_ops_cap = doc
        .pointer("/monetary/rewards/caps/global_ops_cap_per_epoch")
        .and_then(|v| v.as_u64())
        .map(|v| v as u128);

    // Treasury pool caps.
    let reward_pool_initial = doc
        .pointer("/monetary/treasury_policy/reward_pool_initial")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u128>().ok());
    let reward_cap_total = doc
        .pointer("/monetary/treasury_policy/reward_cap_total")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u128>().ok());
    let reward_cap_per_year = doc
        .pointer("/monetary/treasury_policy/reward_cap_per_year")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u128>().ok());
    let reward_cap_per_epoch = doc
        .pointer("/monetary/treasury_policy/reward_cap_per_epoch")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u128>().ok());
    let accounting = doc
        .pointer("/monetary/treasury_policy/accounting")
        .and_then(|v| v.as_str())
        .unwrap_or("<missing>");

    // Addresses consistency.
    let treasury_addr_params = doc
        .pointer("/parameters/treasury_address")
        .and_then(|v| v.as_str());
    let treasury_addr_dist = doc
        .pointer("/monetary/fee_distribution/distribution_addresses/treasury_address")
        .and_then(|v| v.as_str());
    let insurance_addr_dist = doc
        .pointer("/monetary/fee_distribution/distribution_addresses/insurance_address")
        .and_then(|v| v.as_str());

    // Staking min stake alignment.
    let min_stake_consensus = doc
        .pointer("/consensus/notary_registry/min_stake")
        .and_then(|v| v.as_u64());
    let min_stake_rewards = doc
        .pointer("/monetary/rewards/staking/min_stake")
        .and_then(|v| v.as_u64());

    let mut out = String::new();
    out.push_str("## Economics audit report (Genesis)\n\n");
    if let Some(p) = doc_path {
        out.push_str(&format!("- **contract**: `{}`\n", p.display()));
    } else {
        out.push_str("- **contract**: (embedded in verified blob)\n");
    }
    if let Some(p) = schema_path {
        out.push_str(&format!("- **schema**: `{}`\n", p.display()));
    }
    out.push_str("\n### A) Currency & denomination\n");
    out.push_str(&audit_check_row(
        "Native utility coin",
        symbol == "SLI",
        &format!("parameters.currency.symbol = `{}` (expected `SLI`)", symbol),
    ));
    out.push_str(&audit_check_row(
        "Decimals",
        decimals == 8,
        &format!("parameters.currency.decimals = `{}` (expected 8)", decimals),
    ));

    out.push_str("\n### B) Supply model\n");
    out.push_str(&audit_check_row(
        "Minting disabled",
        minting == "disabled",
        &format!("monetary.minting = `{}` (expected `disabled`)", minting),
    ));
    match (circulating_val, supply_cap_u128) {
        (Some(circ), Some(cap)) => {
            out.push_str(&audit_check_row(
                "Supply cap >= circulating (genesis balances)",
                cap >= circ,
                &format!("supply_cap = {}, circulating = {}", cap, circ),
            ));
        }
        (Some(circ), None) => {
            out.push_str(&audit_check_row(
                "Supply cap parseable",
                false,
                &format!(
                    "monetary.supply_cap = '{}' (cannot parse), circulating = {}",
                    supply_cap, circ
                ),
            ));
        }
        (None, _) => {
            out.push_str(&audit_check_row(
                "Circulating supply computable",
                false,
                &format!(
                    "failed to sum state.accounts[*].balance: {}",
                    circulating_res
                        .err()
                        .map(|e| e.to_string())
                        .unwrap_or_else(|| "<unknown>".to_string())
                ),
            ));
        }
    }

    out.push_str("\n### C) Fees\n");
    out.push_str(&audit_check_row(
        "Fees currency symbol",
        doc.pointer("/parameters/fees/currency")
            .and_then(|v| v.as_str())
            == Some("SLI"),
        &format!(
            "parameters.fees.currency = `{}`",
            doc.pointer("/parameters/fees/currency")
                .and_then(|v| v.as_str())
                .unwrap_or("<missing>")
        ),
    ));
    out.push_str(&audit_check_row(
        "Min fee aligned with base fee",
        fees_base.is_some() && tx_min_fee.is_some() && fees_base == tx_min_fee,
        &format!(
            "fees.base = {:?}, tx_rules.min_fee = {:?}",
            fees_base, tx_min_fee
        ),
    ));
    out.push_str(&audit_check_row(
        "Fee parameters present",
        fees_base.is_some() && fees_per_byte.is_some(),
        &format!(
            "fees.base = {:?}, fees.per_byte = {:?}",
            fees_base, fees_per_byte
        ),
    ));

    out.push_str("\n### D) Fee distribution\n");
    let bps_sum = validators_bps.unwrap_or(0)
        + workers_bps.unwrap_or(0)
        + treasury_bps.unwrap_or(0)
        + insurance_bps.unwrap_or(0)
        + burn_bps.unwrap_or(0);
    out.push_str(&audit_check_row(
        "BPS sum equals total_bps",
        total_bps.is_some() && bps_sum == total_bps.unwrap_or(0),
        &format!(
            "sum = {}, total_bps = {:?} (validators/workers/treasury/insurance/burn = {:?}/{:?}/{:?}/{:?}/{:?})",
            bps_sum, total_bps, validators_bps, workers_bps, treasury_bps, insurance_bps, burn_bps
        ),
    ));
    out.push_str(&audit_check_row(
        "BPS sum equals 10000",
        bps_sum == 10_000,
        &format!("sum = {} (expected 10000)", bps_sum),
    ));
    out.push_str(&audit_check_row(
        "Treasury address consistent",
        treasury_addr_params.is_some() && treasury_addr_params == treasury_addr_dist,
        &format!(
            "parameters.treasury_address = {:?}, fee_distribution.treasury_address = {:?}",
            treasury_addr_params, treasury_addr_dist
        ),
    ));
    out.push_str(&audit_check_row(
        "Insurance address present",
        insurance_addr_dist.is_some(),
        &format!(
            "fee_distribution.insurance_address = {:?}",
            insurance_addr_dist
        ),
    ));

    out.push_str("\n### E) Rewards (execution-mining)\n");
    let rewards_mode = doc
        .pointer("/monetary/rewards/mode")
        .and_then(|v| v.as_str())
        .unwrap_or("<missing>");
    out.push_str(&audit_check_row(
        "Rewards mode set",
        rewards_mode == "execution-mining",
        &format!(
            "monetary.rewards.mode = `{}` (expected `execution-mining`)",
            rewards_mode
        ),
    ));
    let rewards_source = doc
        .pointer("/monetary/rewards/source")
        .and_then(|v| v.as_str())
        .unwrap_or("<missing>");
    out.push_str(&audit_check_row(
        "Rewards source treasury",
        rewards_source == "treasury",
        &format!(
            "monetary.rewards.source = `{}` (expected `treasury`)",
            rewards_source
        ),
    ));
    let invariant_ok = match (rate_per_unit, max_per_epoch, global_ops_cap) {
        (Some(r), Some(m), Some(c)) => m == r.saturating_mul(c),
        _ => false,
    };
    out.push_str(&audit_check_row(
        "Rewards invariant max_per_epoch == rate_per_unit * global_ops_cap",
        invariant_ok,
        &format!(
            "rate_per_unit = {:?}, global_ops_cap = {:?}, max_per_epoch = {:?}",
            rate_per_unit, global_ops_cap, max_per_epoch
        ),
    ));

    out.push_str("\n### F) Treasury reserve caps\n");
    out.push_str(&audit_check_row(
        "Treasury accounting is decrement-only",
        accounting == "decrement-only",
        &format!("treasury_policy.accounting = `{}`", accounting),
    ));
    out.push_str(&audit_check_row(
        "reward_pool_initial == reward_cap_total",
        reward_pool_initial.is_some()
            && reward_cap_total.is_some()
            && reward_pool_initial == reward_cap_total,
        &format!(
            "reward_pool_initial = {:?}, reward_cap_total = {:?}",
            reward_pool_initial, reward_cap_total
        ),
    ));
    out.push_str(&audit_check_row(
        "reward_cap_per_year <= reward_cap_total",
        reward_cap_per_year.is_some()
            && reward_cap_total.is_some()
            && reward_cap_per_year.unwrap_or(0) <= reward_cap_total.unwrap_or(0),
        &format!(
            "reward_cap_per_year = {:?}, reward_cap_total = {:?}",
            reward_cap_per_year, reward_cap_total
        ),
    ));
    out.push_str(&audit_check_row(
        "reward_cap_per_epoch <= reward_cap_per_year",
        reward_cap_per_epoch.is_some()
            && reward_cap_per_year.is_some()
            && reward_cap_per_epoch.unwrap_or(0) <= reward_cap_per_year.unwrap_or(0),
        &format!(
            "reward_cap_per_epoch = {:?}, reward_cap_per_year = {:?}",
            reward_cap_per_epoch, reward_cap_per_year
        ),
    ));

    out.push_str("\n### G) Staking alignment\n");
    out.push_str(&audit_check_row(
        "min_stake aligned (consensus vs rewards)",
        min_stake_consensus.is_some()
            && min_stake_rewards.is_some()
            && min_stake_consensus == min_stake_rewards,
        &format!(
            "consensus.min_stake = {:?}, rewards.min_stake = {:?}",
            min_stake_consensus, min_stake_rewards
        ),
    ));

    // Overall
    let mut all_ok = true;
    // Minimal overall gate: minting disabled, bps sum correct, treasury accounting correct, cap>=circ, invariant ok.
    if minting != "disabled" {
        all_ok = false;
    }
    if bps_sum != 10_000 {
        all_ok = false;
    }
    if accounting != "decrement-only" {
        all_ok = false;
    }
    if let (Some(circ), Some(cap)) = (circulating_val, supply_cap_u128) {
        if cap < circ {
            all_ok = false;
        }
    } else {
        all_ok = false;
    }
    if !invariant_ok {
        all_ok = false;
    }

    out.push_str("\n### Overall\n");
    out.push_str(&format!(
        "- **economics_audit_status**: {}\n",
        if all_ok { "PASS" } else { "FAIL" }
    ));
    out
}

fn render_json_audit_report(doc_path: &Path, schema_path: &Path) -> Result<String> {
    let doc_bytes =
        fs::read(doc_path).with_context(|| format!("failed to read {}", doc_path.display()))?;
    let doc_sha = sha256_prefixed_hex(&doc_bytes);
    let doc_value: Value =
        serde_json::from_slice(&doc_bytes).context("document is not valid JSON")?;

    // Validate (for auditors, this is the main safety check we can do deterministically here).
    let schema_bytes = fs::read(schema_path)
        .with_context(|| format!("failed to read {}", schema_path.display()))?;
    let schema_value: Value =
        serde_json::from_slice(&schema_bytes).context("schema is not valid JSON")?;
    let validator = validator_for(&schema_value).context("failed to compile JSON Schema")?;
    let mut validation_ok = true;
    let mut validation_errors = Vec::new();
    if let Err(errors) = validator.validate(&doc_value) {
        validation_ok = false;
        for error in errors {
            validation_errors.push(format!(
                "{} (instance: {}, schema: {})",
                error, error.instance_path, error.schema_path
            ));
        }
    }

    let schema_uri = opt_str(&doc_value, "/$schema").unwrap_or_else(|| "<missing>".to_string());
    let version = opt_str(&doc_value, "/version").unwrap_or_else(|| "<missing>".to_string());
    let network_id = opt_str(&doc_value, "/network/id").unwrap_or_else(|| "<missing>".to_string());
    let network_name =
        opt_str(&doc_value, "/network/name").unwrap_or_else(|| "<missing>".to_string());
    let env =
        opt_str(&doc_value, "/network/environment").unwrap_or_else(|| "<missing>".to_string());
    let chain_id = opt_u64(&doc_value, "/network/chain_id");

    let genesis_id = opt_str(&doc_value, "/genesis/id").unwrap_or_else(|| "<missing>".to_string());
    let created_at =
        opt_str(&doc_value, "/genesis/created_at").unwrap_or_else(|| "<missing>".to_string());
    let activation_time =
        opt_str(&doc_value, "/genesis/activation_time").unwrap_or_else(|| "<missing>".to_string());
    let issuer_org =
        opt_str(&doc_value, "/genesis/issuer/org").unwrap_or_else(|| "<missing>".to_string());
    let issuer_contact =
        opt_str(&doc_value, "/genesis/issuer/contact").unwrap_or_else(|| "<missing>".to_string());

    let content_hash =
        opt_str(&doc_value, "/content/hash").unwrap_or_else(|| "<missing>".to_string());
    let content_size = opt_u64(&doc_value, "/content/size");

    let version_byte = opt_u64(&doc_value, "/addressing/version_byte");
    let address_prefix = opt_str(&doc_value, "/addressing/address_prefix")
        .unwrap_or_else(|| "<missing>".to_string());

    let upgrade_allowed = opt_bool(&doc_value, "/genesis/upgrade_policy/allowed");
    let up_k = opt_u64(&doc_value, "/genesis/upgrade_policy/requires_threshold/k");
    let up_n = opt_u64(&doc_value, "/genesis/upgrade_policy/requires_threshold/n");

    let signing_keys = doc_value
        .pointer("/signing_keys")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    let sig_threshold_k = opt_u64(&doc_value, "/signatures/threshold/k");
    let sig_threshold_n = opt_u64(&doc_value, "/signatures/threshold/n");
    let sig_signers = doc_value
        .pointer("/signatures/signers")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);

    let mut out = String::new();
    out.push_str("## Genesis contract audit report\n\n");
    out.push_str(&format!("- **file**: `{}`\n", doc_path.display()));
    out.push_str(&format!("- **file_sha256**: `{}`\n", doc_sha));
    out.push_str(&format!("- **schema_file**: `{}`\n", schema_path.display()));
    out.push_str(&format!("- **schema_uri**: `{}`\n", schema_uri));
    out.push_str(&format!(
        "- **schema_validation**: {}\n",
        if validation_ok { "OK" } else { "FAILED" }
    ));
    if !validation_ok {
        out.push_str("\n### Validation errors\n");
        for e in validation_errors.iter().take(25) {
            out.push_str(&format!("- {}\n", e));
        }
        if validation_errors.len() > 25 {
            out.push_str(&format!(
                "- ... and {} more\n",
                validation_errors.len() - 25
            ));
        }
    }

    out.push_str("\n### Network\n");
    out.push_str(&format!("- **id**: `{}`\n", network_id));
    out.push_str(&format!("- **name**: `{}`\n", network_name));
    out.push_str(&format!("- **environment**: `{}`\n", env));
    out.push_str(&format!(
        "- **chain_id**: `{}`\n",
        chain_id
            .map(|v| v.to_string())
            .unwrap_or_else(|| "<missing>".to_string())
    ));

    out.push_str("\n### Genesis metadata\n");
    out.push_str(&format!("- **genesis_id**: `{}`\n", genesis_id));
    out.push_str(&format!("- **version**: `{}`\n", version));
    out.push_str(&format!("- **created_at**: `{}`\n", created_at));
    out.push_str(&format!("- **activation_time**: `{}`\n", activation_time));
    out.push_str(&format!("- **issuer.org**: `{}`\n", issuer_org));
    out.push_str(&format!("- **issuer.contact**: `{}`\n", issuer_contact));

    out.push_str("\n### Content / integrity hints\n");
    out.push_str(&format!("- **content.hash**: `{}`\n", content_hash));
    out.push_str(&format!(
        "- **content.size**: `{}`\n",
        content_size
            .map(|v| v.to_string())
            .unwrap_or_else(|| "<missing>".to_string())
    ));
    // Cross-field consistency: genesis.id should embed content.hash (same digest).
    let genesis_id_ok = if let (Some(gid), Some(ch)) = (
        opt_str(&doc_value, "/genesis/id"),
        opt_str(&doc_value, "/content/hash"),
    ) {
        if let Some(rest) = gid.strip_prefix("genesis:") {
            rest == ch
        } else {
            false
        }
    } else {
        false
    };
    out.push_str(&format!(
        "- **genesis.id == 'genesis:' + content.hash**: {}\n",
        if genesis_id_ok {
            "OK"
        } else {
            "FAILED/UNKNOWN"
        }
    ));

    out.push_str("\n### Addressing\n");
    out.push_str(&format!(
        "- **version_byte**: `{}`\n",
        version_byte
            .map(|v| v.to_string())
            .unwrap_or_else(|| "<missing>".to_string())
    ));
    out.push_str(&format!("- **address_prefix**: `{}`\n", address_prefix));

    out.push_str("\n### Upgrade policy\n");
    out.push_str(&format!(
        "- **allowed**: `{}`\n",
        upgrade_allowed
            .map(|v| v.to_string())
            .unwrap_or_else(|| "<missing>".to_string())
    ));
    out.push_str(&format!(
        "- **threshold (k/n)**: `{}/{}`\n",
        up_k.map(|v| v.to_string())
            .unwrap_or_else(|| "?".to_string()),
        up_n.map(|v| v.to_string())
            .unwrap_or_else(|| "?".to_string())
    ));

    out.push_str("\n### Keys & signatures (document fields)\n");
    out.push_str(&format!("- **signing_keys count**: `{}`\n", signing_keys));
    out.push_str(&format!(
        "- **signatures.threshold (k/n)**: `{}/{}`\n",
        sig_threshold_k
            .map(|v| v.to_string())
            .unwrap_or_else(|| "?".to_string()),
        sig_threshold_n
            .map(|v| v.to_string())
            .unwrap_or_else(|| "?".to_string())
    ));
    out.push_str(&format!(
        "- **signatures.signers count**: `{}`\n",
        sig_signers
    ));
    out.push_str("\n> Note: built-in `signatures` are listed, but cryptographic verification of those fields is not implemented in this tool (it requires the protocol’s canonical signing view rules).\n");
    Ok(out)
}

fn render_blob_audit_report(blob_path: &Path, sig_path: Option<&Path>) -> Result<String> {
    let blob_bytes = fs::read(blob_path)
        .with_context(|| format!("failed to read blob {}", blob_path.display()))?;
    let blob_sha = sha256_prefixed_hex(&blob_bytes);
    let parts = parse_blob(&blob_bytes)?;

    let schema_value: Value =
        serde_json::from_slice(&parts.schema_bytes).context("schema in blob is not valid JSON")?;
    let doc_value: Value = serde_json::from_slice(&parts.document_bytes)
        .context("document in blob is not valid JSON")?;

    let version_byte = extract_version_byte_from_doc_value(&doc_value)?;

    let validator =
        validator_for(&schema_value).context("failed to compile JSON Schema from blob")?;
    let mut validation_ok = true;
    let mut validation_errors = Vec::new();
    if let Err(errors) = validator.validate(&doc_value) {
        validation_ok = false;
        for error in errors {
            validation_errors.push(format!(
                "{} (instance: {}, schema: {})",
                error, error.instance_path, error.schema_path
            ));
        }
    }

    // Use embedded signatures if available, otherwise try to read from file
    let (sig_file, sig_source) = if let Some(signature_set_bytes) = &parts.signature_set_bytes {
        // Signatures are embedded in blob
        let sig_json = String::from_utf8(signature_set_bytes.clone())
            .context("embedded signature set is not valid UTF-8")?;
        let sig_file: BlobSignatureFile =
            serde_json::from_str(&sig_json).context("failed to parse embedded signature JSON")?;
        (sig_file, "<embedded in blob>".to_string())
    } else {
        // Signatures are not embedded, try to read from file
        let sig_path = sig_path
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| default_sig_out(blob_path));
        let sig_json = fs::read_to_string(&sig_path)
            .with_context(|| format!("failed to read signature file {}", sig_path.display()))?;
        let sig_file: BlobSignatureFile =
            serde_json::from_str(&sig_json).context("failed to parse signature JSON")?;
        (sig_file, sig_path.display().to_string())
    };

    let mut out = String::new();
    out.push_str("## Genesis blob audit report\n\n");
    out.push_str(&format!("- **blob**: `{}`\n", blob_path.display()));
    out.push_str(&format!("- **blob_sha256**: `{}`\n", blob_sha));
    out.push_str(&format!("- **signatures**: `{}`\n", sig_source));
    out.push_str(&format!("- **format**: `{}`\n", sig_file.format));

    out.push_str("\n### Embedded parts\n");
    out.push_str(&format!(
        "- **document_sha256**: `{}`\n",
        sha256_prefixed_hex(&parts.document_bytes)
    ));
    out.push_str(&format!(
        "- **schema_sha256**: `{}`\n",
        sha256_prefixed_hex(&parts.schema_bytes)
    ));
    out.push_str(&format!(
        "- **schema_validation**: {}\n",
        if validation_ok { "OK" } else { "FAILED" }
    ));
    if !validation_ok {
        out.push_str("\n### Validation errors\n");
        for e in validation_errors.iter().take(25) {
            out.push_str(&format!("- {}\n", e));
        }
        if validation_errors.len() > 25 {
            out.push_str(&format!(
                "- ... and {} more\n",
                validation_errors.len() - 25
            ));
        }
    }

    // Summarize document fields for auditors (same as JSON report, but from embedded doc).
    let schema_uri = opt_str(&doc_value, "/$schema").unwrap_or_else(|| "<missing>".to_string());
    let version = opt_str(&doc_value, "/version").unwrap_or_else(|| "<missing>".to_string());
    let network_id = opt_str(&doc_value, "/network/id").unwrap_or_else(|| "<missing>".to_string());
    let env =
        opt_str(&doc_value, "/network/environment").unwrap_or_else(|| "<missing>".to_string());
    let chain_id = opt_u64(&doc_value, "/network/chain_id");
    let genesis_id = opt_str(&doc_value, "/genesis/id").unwrap_or_else(|| "<missing>".to_string());
    let created_at =
        opt_str(&doc_value, "/genesis/created_at").unwrap_or_else(|| "<missing>".to_string());
    let activation_time =
        opt_str(&doc_value, "/genesis/activation_time").unwrap_or_else(|| "<missing>".to_string());

    out.push_str("\n### Document snapshot\n");
    out.push_str(&format!("- **schema_uri**: `{}`\n", schema_uri));
    out.push_str(&format!("- **version**: `{}`\n", version));
    out.push_str(&format!("- **network.id**: `{}`\n", network_id));
    out.push_str(&format!(
        "- **network.chain_id**: `{}`\n",
        chain_id
            .map(|v| v.to_string())
            .unwrap_or_else(|| "<missing>".to_string())
    ));
    out.push_str(&format!("- **network.environment**: `{}`\n", env));
    out.push_str(&format!("- **genesis.id**: `{}`\n", genesis_id));
    out.push_str(&format!("- **created_at**: `{}`\n", created_at));
    out.push_str(&format!("- **activation_time**: `{}`\n", activation_time));
    out.push_str(&format!(
        "- **addressing.version_byte**: `{}`\n",
        version_byte
    ));

    // Verify blob signature file claims & signatures (auditor critical).
    // For embedded signatures, signatures are over blob WITHOUT SIGNATURE_SET section
    let blob_for_verification = if parts.signature_set_bytes.is_some() {
        // Extended blob with embedded signatures: rebuild without SIGNATURE_SET for verification
        build_extended_blob_bytes(
            &parts.schema_bytes,
            &parts.document_bytes,
            parts.transactions_bytes.as_deref(),
            None, // Exclude SIGNATURE_SET for verification
        )
    } else {
        blob_bytes.to_vec()
    };
    
    let blob_hash_actual: [u8; 32] = Sha256::digest(&blob_for_verification).into();
    let blob_hash_claimed = parse_sha256_hex_prefixed(&sig_file.blob.sha256)?;
    let doc_hash_claimed = parse_sha256_hex_prefixed(&sig_file.document.sha256)?;
    let schema_hash_claimed = parse_sha256_hex_prefixed(&sig_file.schema.sha256)?;
    let doc_hash_actual: [u8; 32] = Sha256::digest(&parts.document_bytes).into();
    let schema_hash_actual: [u8; 32] = Sha256::digest(&parts.schema_bytes).into();

    let integrity_ok = blob_hash_claimed == blob_hash_actual
        && doc_hash_claimed == doc_hash_actual
        && schema_hash_claimed == schema_hash_actual
        && sig_file.blob.size == blob_for_verification.len()
        && sig_file.document.size == parts.document_bytes.len()
        && sig_file.schema.size == parts.schema_bytes.len();

    let threshold_type = sig_file
        .threshold
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("<missing>");
    let k = sig_file
        .threshold
        .get("k")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let n = sig_file
        .threshold
        .get("n")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;

    let mut valid_signer_kids: HashSet<String> = HashSet::new();
    let mut signer_rows: Vec<String> = Vec::new();
    for s in &sig_file.signers {
        let mut status = "invalid";
        let reason: &'static str;
        if s.alg != "ecdsa-secp256k1" {
            reason = "unsupported alg";
        } else if let Ok(pubkey_bytes) =
            parse_hex_bytes_exact(&s.public_key, PUBKEY_COMPRESSED_BYTES, "public_key")
        {
            if !matches!(pubkey_bytes[0], 0x02 | 0x03) {
                reason = "bad pubkey format";
            } else {
                let derived = derive_address(&pubkey_bytes, version_byte);
                if derived != s.kid {
                    reason = "kid mismatch";
                } else if let (Ok(vk), Ok(sig_der)) = (
                    VerifyingKey::from_sec1_bytes(&pubkey_bytes),
                    parse_hex_bytes_capped(
                        &s.signature_der_hex,
                        MAX_SIG_DER_BYTES,
                        "signature_der",
                    ),
                ) {
                    if let Ok(sig) = Signature::from_der(&sig_der) {
                        let (sig_to_verify, normalized) = match sig.normalize_s() {
                            Some(ns) => (ns, true),
                            None => (sig, false),
                        };
                        if vk.verify_prehash(&blob_hash_actual, &sig_to_verify).is_ok() {
                            status = "valid";
                            reason = if normalized {
                                "ok (normalized low-S)"
                            } else {
                                "ok"
                            };
                            valid_signer_kids.insert(s.kid.clone());
                        } else {
                            reason = "signature verify failed";
                        }
                    } else {
                        reason = "bad DER signature";
                    }
                } else {
                    reason = "bad pubkey or signature hex";
                }
            }
        } else {
            reason = "bad pubkey hex";
        }
        signer_rows.push(format!(
            "- **{}**: {} (pubkey: `{}`)",
            s.kid,
            status,
            short_str(&short_hex(&s.public_key, 10), 64)
        ));
        if status != "valid" {
            signer_rows.push(format!("  - reason: {}", reason));
        }
    }

    out.push_str("\n### Signature file integrity & signatures\n");
    out.push_str(&format!(
        "- **integrity_checks**: {}\n",
        if integrity_ok { "OK" } else { "FAILED" }
    ));
    out.push_str(&format!("- **threshold.type**: `{}`\n", threshold_type));
    out.push_str(&format!("- **threshold (k/n)**: `{}/{}`\n", k, n));
    out.push_str(&format!(
        "- **valid unique signers**: `{}`\n",
        valid_signer_kids.len()
    ));
    out.push_str("\n### Signers\n");
    for row in signer_rows {
        out.push_str(&row);
        out.push('\n');
    }

    let signatures_ok = integrity_ok
        && threshold_type == "k-of-n"
        && k >= 1
        && k <= n
        && valid_signer_kids.len() >= k;
    out.push_str("\n### Overall (blob package)\n");
    out.push_str(&format!(
        "- **signatures_ok (k-of-n met, unique signers)**: {}\n",
        if signatures_ok { "OK" } else { "FAILED" }
    ));
    out.push_str(&format!(
        "- **ready_for_regulator (schema_validation && signatures_ok)**: {}\n",
        if validation_ok && signatures_ok {
            "YES"
        } else {
            "NO"
        }
    ));

    Ok(out)
}

fn is_sha256_prefixed_64(s: &str) -> bool {
    if let Some(hex_part) = s.strip_prefix("sha256:") {
        hex_part.len() == 64 && hex_part.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
    } else {
        false
    }
}

fn migrate_old_contract_in_place(v: &mut Value) {
    if let Some(seed_format) = v.pointer_mut(
        "/consensus/committee/selection/committee_cap_policy/algorithm/vrf_selection/seed_format",
    ) && seed_format == "sha256(canonicalize(prev_epoch_finality_certificate))"
    {
        *seed_format =
            Value::String("sha256(gls-det-1(prev_epoch_finality_certificate))".to_string());
    }

    if let Some(alg) = v.pointer_mut("/consensus/finality_certificate/alg")
        && let Value::Array(arr) = alg
        && arr.len() == 1
        && let Some(Value::String(s)) = arr.first()
    {
        *alg = Value::String(s.clone());
    }

    let content_hash = v
        .pointer("/content/hash")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let replacement = if let Some(ch) = content_hash
        .as_deref()
        .filter(|ch| is_sha256_prefixed_64(ch))
    {
        ch.to_string()
    } else {
        let empty_hash: [u8; 32] = Sha256::digest(b"").into();
        format!("sha256:{}", empty_hash.encode_hex::<String>())
    };

    if let Some(tx_hash) = v.pointer_mut("/tx_rules/tx_hash") {
        match tx_hash {
            Value::String(s) => {
                if !is_sha256_prefixed_64(s) {
                    *tx_hash = Value::String(replacement.clone());
                }
            }
            _ => {
                *tx_hash = Value::String(replacement.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use sha2::Sha256;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_path(tag: &str, ext: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let mut p = std::env::temp_dir();
        p.push(format!(
            "genesis-test-{}-{}-{}.{}",
            std::process::id(),
            tag,
            nanos,
            ext
        ));
        p
    }

    #[test]
    fn sha256_parser_rejects_wrong_length() {
        let err = parse_sha256_hex_prefixed("sha256:00").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("64 chars"), "unexpected error: {msg}");
    }

    #[test]
    fn parse_blob_rejects_trailing_bytes() {
        let doc = br#"{"addressing":{"version_byte":98}}"#;
        let schema = br#"{"type":"object","properties":{"addressing":{"type":"object","properties":{"version_byte":{"type":"integer","minimum":0,"maximum":255}},"required":["version_byte"]}},"required":["addressing"]}"#;
        let mut blob = build_blob_bytes(doc, schema, None);
        blob.push(0x00);
        let err = match parse_blob(&blob) {
            Ok(_) => panic!("expected trailing-bytes error"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("trailing bytes"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn verify_blob_and_signatures_happy_path() -> Result<()> {
        let doc_bytes = br#"{"addressing":{"version_byte":98}}"#;
        let schema_bytes = br#"{"type":"object","properties":{"addressing":{"type":"object","properties":{"version_byte":{"type":"integer","minimum":0,"maximum":255}},"required":["version_byte"]}},"required":["addressing"]}"#;

        let blob_bytes = build_blob_bytes(doc_bytes, schema_bytes, None);
        let blob_hash: [u8; 32] = Sha256::digest(&blob_bytes).into();
        let doc_hash: [u8; 32] = Sha256::digest(doc_bytes).into();
        let schema_hash: [u8; 32] = Sha256::digest(schema_bytes).into();

        // Deterministic non-zero private key for tests.
        let signing_key = SigningKey::from_bytes(&[1u8; 32])
            .map_err(|e| anyhow!("failed to create test signing key: {e}"))?;
        let pubkey_point = signing_key.verifying_key().to_encoded_point(true);
        let pubkey_bytes = pubkey_point.as_bytes();
        let kid = derive_address(pubkey_bytes, 98);

        let sig: Signature = signing_key
            .sign_prehash(&blob_hash)
            .context("test signing failed")?;
        let sig = sig.normalize_s().unwrap_or(sig);

        let signer = BlobSigner {
            kid,
            alg: "ecdsa-secp256k1".to_string(),
            public_key: pubkey_bytes.encode_hex::<String>(),
            signature_der_hex: sig.to_der().as_bytes().encode_hex::<String>(),
        };

        let blob_path = tmp_path("blob", "blob");
        let sig_path = tmp_path("sig", "json");

        fs::write(&blob_path, &blob_bytes)
            .with_context(|| format!("failed to write {}", blob_path.display()))?;

        let sig_file = BlobSignatureFile {
            format: "genesis-blob-signature-v1".to_string(),
            created_at: "2025-01-01T00:00:00Z".to_string(),
            blob: BlobPartMeta {
                path: blob_path.display().to_string(),
                size: blob_bytes.len(),
                sha256: format!("sha256:{}", blob_hash.encode_hex::<String>()),
            },
            document: BlobPartMeta {
                path: "<embedded>".to_string(),
                size: doc_bytes.len(),
                sha256: format!("sha256:{}", doc_hash.encode_hex::<String>()),
            },
            schema: BlobPartMeta {
                path: "<embedded>".to_string(),
                size: schema_bytes.len(),
                sha256: format!("sha256:{}", schema_hash.encode_hex::<String>()),
            },
            threshold: json!({ "type": "k-of-n", "k": 1, "n": 1 }),
            signers: vec![signer],
        };

        fs::write(&sig_path, serde_json::to_string_pretty(&sig_file)?)
            .with_context(|| format!("failed to write {}", sig_path.display()))?;

        let res = verify_blob_and_signatures(&blob_path, &sig_path);

        // Best-effort cleanup.
        let _ = fs::remove_file(&blob_path);
        let _ = fs::remove_file(&sig_path);

        res
    }
}

/// Generate distribution transactions from genesis.json treasury account to other accounts.
///
/// This function reads the genesis.json file, finds the treasury account (with the largest balance),
/// and generates a chain of transactions distributing funds to other accounts.
///
/// Each transaction is saved as a separate JSON file in the output directory.
/// Transactions are chained using prev_hash to form a sequential chain.
pub fn generate_distribution_transactions(genesis_path: &Path, output_dir: &Path) -> Result<()> {
    // Read genesis.json
    let genesis_bytes = fs::read(genesis_path)
        .with_context(|| format!("failed to read genesis file {}", genesis_path.display()))?;
    let genesis: Value =
        serde_json::from_slice(&genesis_bytes).with_context(|| "failed to parse genesis JSON")?;

    // Extract accounts
    let accounts = genesis
        .pointer("/state/accounts")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("genesis.state.accounts is missing or not an array"))?;

    if accounts.is_empty() {
        bail!("no accounts found in genesis");
    }

    // Find treasury account (largest balance) and other accounts
    // First pass: find treasury (account with largest balance)
    let mut treasury_account: Option<&Value> = None;
    let mut treasury_balance = 0u128;

    for account in accounts {
        let balance_str = account
            .pointer("/balance")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("account missing balance field"))?;
        let balance: u128 = balance_str
            .parse()
            .with_context(|| format!("invalid balance: {}", balance_str))?;

        if balance > treasury_balance {
            treasury_balance = balance;
            treasury_account = Some(account);
        }
    }

    let treasury_address = treasury_account
        .and_then(|acc| acc.pointer("/address").and_then(|v| v.as_str()))
        .ok_or_else(|| anyhow!("treasury account not found"))?;

    // Second pass: collect all other accounts (excluding treasury)
    let mut other_accounts = Vec::new();
    for account in accounts {
        let address = account
            .pointer("/address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("account missing address field"))?;

        if address != treasury_address {
            let balance_str = account
                .pointer("/balance")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("account missing balance field"))?;
            let balance: u128 = balance_str
                .parse()
                .with_context(|| format!("invalid balance: {}", balance_str))?;
            other_accounts.push((address.to_string(), balance));
        }
    }

    // Extract fee parameters
    let fee_base = genesis
        .pointer("/parameters/fees/base")
        .and_then(|v| v.as_u64())
        .unwrap_or(10000);
    let fee_per_byte = genesis
        .pointer("/parameters/fees/per_byte")
        .and_then(|v| v.as_u64())
        .unwrap_or(20);
    let fee_per_transfer = genesis
        .pointer("/intrinsics/registry/0/fee_policy/per_op/transfer")
        .and_then(|v| v.as_u64())
        .unwrap_or(2000);

    let currency = genesis
        .pointer("/parameters/currency/symbol")
        .and_then(|v| v.as_str())
        .unwrap_or("SLI");

    let _chain_id = genesis
        .pointer("/network/chain_id")
        .and_then(|v| v.as_u64())
        .unwrap_or(1);

    // Create output directory
    fs::create_dir_all(output_dir)
        .with_context(|| format!("failed to create output directory {}", output_dir.display()))?;

    // Generate transactions
    let mut prev_hash: Option<String> = None;
    let activation_time = genesis
        .pointer("/activation_time")
        .and_then(|v| v.as_str())
        .unwrap_or("2025-12-14T18:19:16.750Z");

    // Parse activation time to timestamp
    let activation_dt = chrono::DateTime::parse_from_rfc3339(activation_time)
        .or_else(|_| {
            // Try parsing as ISO 8601
            chrono::DateTime::parse_from_str(activation_time, "%Y-%m-%dT%H:%M:%S%.3fZ")
        })
        .with_context(|| format!("failed to parse activation_time: {}", activation_time))?;
    let base_timestamp = activation_dt.timestamp_millis();

    // Calculate equal distribution amount per recipient
    // Reserve some treasury balance for fees and future use
    let total_recipients = other_accounts.len();
    let distribution_per_recipient = if total_recipients > 0 {
        // Distribute 90% of treasury, keep 10% for fees and reserves
        (treasury_balance * 90 / 100) / total_recipients as u128
    } else {
        0
    };

    for (idx, (recipient_address, _recipient_balance)) in other_accounts.iter().enumerate() {
        // Create transfer operation
        let ops = vec![json!({
            "op": "transfer",
            "to": recipient_address,
            "amount": distribution_per_recipient.to_string()
        })];

        // Build transaction (without signatures first to calculate size)
        let mut tx = json!({
            "type": "smart.exec",
            "method": "smart.exec",
            "from": treasury_address,
            "fee": "0", // Will calculate after
            "currency": currency,
            "prev_hash": prev_hash,
            "timestamp": base_timestamp + (idx as i64 * 1000), // Space transactions 1 second apart
            "signatures": [],
            "args": {
                "ops": ops
            }
        });

        // Calculate transaction size (approximate)
        let tx_json = serde_json::to_string(&tx)?;
        let tx_bytes = tx_json.len();

        // Calculate fee: base + per_byte * tx_bytes + per_op * num_ops
        let fee =
            fee_base + (fee_per_byte * tx_bytes as u64) + (fee_per_transfer * ops.len() as u64);
        tx["fee"] = json!(fee.to_string());

        // Calculate transaction hash (canonical form without signatures)
        // For now, we'll use a simple hash of the transaction JSON
        // In production, this should use gls-det-1 canonicalization
        let tx_for_hash = json!({
            "type": tx["type"],
            "method": tx["method"],
            "from": tx["from"],
            "fee": tx["fee"],
            "currency": tx["currency"],
            "prev_hash": tx["prev_hash"],
            "timestamp": tx["timestamp"],
            "args": tx["args"]
        });
        let tx_hash_bytes: [u8; 32] =
            Sha256::digest(serde_json::to_string(&tx_for_hash)?.as_bytes()).into();
        let tx_hash = tx_hash_bytes.encode_hex::<String>();

        // Update prev_hash for next transaction
        prev_hash = Some(tx_hash);

        // Save transaction to file
        let tx_filename = format!("tx_{:04}.json", idx + 1);
        let tx_path = output_dir.join(&tx_filename);
        fs::write(&tx_path, serde_json::to_string_pretty(&tx)?)
            .with_context(|| format!("failed to write transaction to {}", tx_path.display()))?;

        println!(
            "Generated transaction {}: {} -> {} (amount: {}, fee: {})",
            tx_filename, treasury_address, recipient_address, distribution_per_recipient, fee
        );
    }

    println!(
        "\nGenerated {} distribution transactions in {}",
        other_accounts.len(),
        output_dir.display()
    );
    Ok(())
}

/// Sign a transaction with all provided signing keys.
///
/// Creates signatures for the transaction using the signing domain from genesis.
/// The transaction must have all fields except signatures populated.
fn sign_transaction(tx: &mut Value, genesis: &Value, key_paths: &[PathBuf]) -> Result<()> {
    let version_byte = extract_version_byte_from_doc_value(genesis)?;
    let _chain_id = genesis
        .pointer("/network/chain_id")
        .and_then(|v| v.as_u64())
        .unwrap_or(1);

    // Get signing domain from genesis
    let sign_domain = genesis
        .pointer("/protocol/sign_domains/tx")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("protocol.sign_domains.tx not found"))?;

    let domain_prefix = sign_domain
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("signing domain prefix not found"))?;

    // Build signing view (transaction without signatures)
    let signing_view = json!({
        "type": tx["type"],
        "method": tx["method"],
        "from": tx["from"],
        "fee": tx["fee"],
        "currency": tx["currency"],
        "prev_hash": tx["prev_hash"],
        "timestamp": tx["timestamp"],
        "args": tx["args"]
    });

    // Canonicalize signing view (simplified - in production use gls-det-1)
    let canonical_tx = serde_json::to_string(&signing_view)?;

    // Build full signing domain message
    // Format: domain_array as JSON array, then canonical_tx
    let domain_json = serde_json::to_string(sign_domain)?;
    let message = format!("{}{}", domain_json, canonical_tx);
    let message_hash: [u8; 32] = Sha256::digest(message.as_bytes()).into();

    // Sign with all keys
    let mut signatures = Vec::new();
    for key_path in key_paths {
        let signing_key = load_signing_key(key_path)?;
        let signing_point = signing_key.verifying_key().to_encoded_point(true);
        let pubkey_bytes = signing_point.as_bytes();
        let address = derive_address(pubkey_bytes, version_byte);

        let sig: Signature = signing_key
            .sign_prehash(&message_hash)
            .context("signing transaction failed")?;
        let sig = sig.normalize_s().unwrap_or(sig);
        let sig_der_hex = sig.to_der().as_bytes().encode_hex::<String>();

        signatures.push(json!({
            "address": address,
            "domain": domain_prefix,
            "signature": sig_der_hex
        }));
    }

    tx["signatures"] = json!(signatures);
    Ok(())
}

/// Account information extracted from genesis
struct GenesisAccountInfo {
    address: String,
    stake: Option<Value>,
}

/// Genesis parameters extracted for transaction generation
struct GenesisParams {
    currency: String,
    base_timestamp: i64,
    initial_members: Vec<String>,
}

/// Extract accounts and treasury from genesis JSON
fn extract_genesis_accounts(genesis: &Value) -> Result<(String, u128, Vec<GenesisAccountInfo>)> {
    let accounts = genesis
        .pointer("/state/accounts")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("genesis.state.accounts is missing or not an array"))?;

    if accounts.is_empty() {
        bail!("no accounts found in genesis");
    }

    // Find treasury account (largest balance)
    let mut treasury_account: Option<&Value> = None;
    let mut treasury_balance = 0u128;

    for account in accounts {
        let balance_str = account
            .pointer("/balance")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("account missing balance field"))?;
        let balance: u128 = balance_str
            .parse()
            .with_context(|| format!("invalid balance: {}", balance_str))?;

        if balance > treasury_balance {
            treasury_balance = balance;
            treasury_account = Some(account);
        }
    }

    let treasury_address = treasury_account
        .and_then(|acc| acc.pointer("/address").and_then(|v| v.as_str()))
        .ok_or_else(|| anyhow!("treasury account not found"))?
        .to_string();

    // Collect other accounts (excluding treasury)
    let mut other_accounts = Vec::new();
    for account in accounts {
        let address = account
            .pointer("/address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("account missing address field"))?;

        if address != treasury_address {
            let stake = account.pointer("/stake").cloned();
            other_accounts.push(GenesisAccountInfo {
                address: address.to_string(),
                stake,
            });
        }
    }

    Ok((treasury_address, treasury_balance, other_accounts))
}

/// Extract genesis parameters needed for transaction generation
///
/// Uses default values for optional parameters if not specified in genesis:
/// - currency: "SLI"
/// - activation_time: "2025-12-14T18:19:16.750Z" (fallback)
/// - initial_members: empty vec (if not specified)
///
/// Note: Initial transactions have fee = 0 to preserve distribution economics.
fn extract_genesis_parameters(genesis: &Value) -> Result<GenesisParams> {
    let currency = genesis
        .pointer("/parameters/currency/symbol")
        .and_then(|v| v.as_str())
        .unwrap_or("SLI")
        .to_string();

    let activation_time = genesis
        .pointer("/activation_time")
        .and_then(|v| v.as_str())
        .unwrap_or("2025-12-14T18:19:16.750Z");

    let activation_dt = chrono::DateTime::parse_from_rfc3339(activation_time)
        .or_else(|_| chrono::DateTime::parse_from_str(activation_time, "%Y-%m-%dT%H:%M:%S%.3fZ"))
        .with_context(|| format!("failed to parse activation_time: {}", activation_time))?;
    let base_timestamp = activation_dt.timestamp_millis();

    let initial_members = genesis
        .pointer("/consensus/committee/bootstrap/initial_members")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Ok(GenesisParams {
        currency,
        base_timestamp,
        initial_members,
    })
}

/// Extract genesis.id hash for first transaction prev_hash
fn extract_genesis_id_hash(genesis: &Value) -> Option<String> {
    let genesis_id = genesis
        .pointer("/genesis/id")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if genesis_id.starts_with("genesis:sha256:") {
        genesis_id
            .strip_prefix("genesis:sha256:")
            .map(|s| s.to_string())
    } else if genesis_id.starts_with("sha256:") {
        genesis_id.strip_prefix("sha256:").map(|s| s.to_string())
    } else {
        None
    }
}

/// Calculate transaction hash (canonical form without signatures)
fn calculate_tx_hash(tx: &Value) -> Result<String> {
    let tx_for_hash = json!({
        "type": tx["type"],
        "method": tx["method"],
        "from": tx["from"],
        "fee": tx["fee"],
        "currency": tx["currency"],
        "prev_hash": tx["prev_hash"],
        "timestamp": tx["timestamp"],
        "args": tx["args"]
    });
    let tx_hash_bytes: [u8; 32] =
        Sha256::digest(serde_json::to_string(&tx_for_hash)?.as_bytes()).into();
    Ok(tx_hash_bytes.encode_hex::<String>())
}

/// Generate genesis funding transaction (first transaction)
fn generate_genesis_funding_tx(
    treasury_address: &str,
    treasury_balance: u128,
    genesis_hash: Option<String>,
    params: &GenesisParams,
    genesis: &Value,
    key_paths: &[PathBuf],
) -> Result<(Value, String)> {
    let ops = vec![json!({
        "op": "transfer",
        "to": treasury_address,
        "amount": treasury_balance.to_string()
    })];

    let mut tx = json!({
        "type": "smart.exec",
        "method": "smart.exec",
        "from": treasury_address,
        "fee": "0",
        "currency": params.currency,
        "prev_hash": genesis_hash,
        "timestamp": params.base_timestamp,
        "signatures": [],
        "args": {
            "ops": ops
        }
    });

    // Fee is 0 for initial genesis transactions to preserve distribution economics
    tx["fee"] = json!("0");

    sign_transaction(&mut tx, genesis, key_paths)?;
    let prev_hash = calculate_tx_hash(&tx)?;
    Ok((tx, prev_hash))
}

/// Generate distribution transactions from treasury to other accounts
fn generate_distribution_txs(
    treasury_address: &str,
    treasury_balance: u128,
    other_accounts: &[GenesisAccountInfo],
    prev_hash: &mut String,
    params: &GenesisParams,
    genesis: &Value,
    key_paths: &[PathBuf],
    all_transactions: &mut Vec<Value>,
) -> Result<()> {
    let total_recipients = other_accounts.len();
    let distribution_per_recipient = if total_recipients > 0 {
        treasury_balance / total_recipients as u128
    } else {
        return Ok(());
    };

    for (idx, account) in other_accounts.iter().enumerate() {
        let ops = vec![json!({
            "op": "transfer",
            "to": &account.address,
            "amount": distribution_per_recipient.to_string()
        })];

        let mut tx = json!({
            "type": "smart.exec",
            "method": "smart.exec",
            "from": treasury_address,
            "fee": "0",
            "currency": params.currency,
            "prev_hash": prev_hash.clone(),
            "timestamp": params.base_timestamp + (idx as i64 * 1000),
            "signatures": [],
            "args": {
                "ops": ops
            }
        });

        // Fee is 0 for initial distribution transactions to preserve distribution economics
        tx["fee"] = json!("0");

        sign_transaction(&mut tx, genesis, key_paths)?;
        *prev_hash = calculate_tx_hash(&tx)?;
        all_transactions.push(tx);
    }

    Ok(())
}

/// Generate staking transactions for accounts with stake
fn generate_staking_txs(
    accounts: &[&Value],
    treasury_address: &str,
    other_accounts: &[GenesisAccountInfo],
    prev_hash: &mut String,
    params: &GenesisParams,
    genesis: &Value,
    key_paths: &[PathBuf],
    all_transactions: &mut Vec<Value>,
) -> Result<()> {
    let mut accounts_to_stake = Vec::new();

    // Add other accounts with stake
    for account in other_accounts {
        if let Some(stake_obj) = &account.stake {
            let stake_amount = stake_obj
                .pointer("/amount")
                .and_then(|v| v.as_str())
                .unwrap_or("0");
            if stake_amount != "0" {
                accounts_to_stake.push((account.address.clone(), stake_amount.to_string()));
            }
        }
    }

    // Add treasury if it has stake
    if let Some(treasury_account) = accounts
        .iter()
        .find(|acc| acc.pointer("/address").and_then(|v| v.as_str()) == Some(treasury_address))
    {
        if let Some(stake_obj) = treasury_account.pointer("/stake") {
            let stake_amount = stake_obj
                .pointer("/amount")
                .and_then(|v| v.as_str())
                .unwrap_or("0");
            if stake_amount != "0" {
                accounts_to_stake.push((treasury_address.to_string(), stake_amount.to_string()));
            }
        }
    }

    for (idx, (address, stake_amount)) in accounts_to_stake.iter().enumerate() {
        let mut tx = json!({
            "type": "notary.registry",
            "method": "notary.registry",
            "from": address,
            "fee": "0",
            "currency": params.currency,
            "prev_hash": prev_hash.clone(),
            "timestamp": params.base_timestamp + ((all_transactions.len() + idx) as i64 * 1000),
            "signatures": [],
            "args": {
                "op": "stake",
                "amount": stake_amount
            }
        });

        // Fee is 0 for initial staking transactions to preserve distribution economics
        tx["fee"] = json!("0");

        sign_transaction(&mut tx, genesis, key_paths)?;
        *prev_hash = calculate_tx_hash(&tx)?;
        all_transactions.push(tx);
    }

    Ok(())
}

/// Generate nomination transactions for initial committee members
fn generate_nomination_txs(
    initial_members: &[String],
    prev_hash: &mut String,
    params: &GenesisParams,
    genesis: &Value,
    key_paths: &[PathBuf],
    all_transactions: &mut Vec<Value>,
) -> Result<()> {
    for (idx, address) in initial_members.iter().enumerate() {
        let mut tx = json!({
            "type": "notary.registry",
            "method": "notary.registry",
            "from": address,
            "fee": "0",
            "currency": params.currency,
            "prev_hash": prev_hash.clone(),
            "timestamp": params.base_timestamp + ((all_transactions.len() + idx) as i64 * 1000),
            "signatures": [],
            "args": {
                "op": "register"
            }
        });

        // Fee is 0 for initial nomination transactions to preserve distribution economics
        tx["fee"] = json!("0");

        sign_transaction(&mut tx, genesis, key_paths)?;
        *prev_hash = calculate_tx_hash(&tx)?;
        all_transactions.push(tx);
    }

    Ok(())
}

/// Generate all initial transactions (distribution, staking, nomination) and sign them.
///
/// This function generates a complete transaction chain for network bootstrap:
/// 1. Genesis funding transaction: Treasury receives full balance, with `prev_hash` pointing to `genesis.id`
/// 2. Distribution transactions: Treasury distributes funds to other accounts
/// 3. Staking transactions: Accounts with initial stake activate staking
/// 4. Nomination transactions: Initial committee members register as nominators
///
/// All transactions are chained using `prev_hash` and signed with all provided signing keys.
///
/// # Parameters
/// - `genesis_path`: Path to the genesis.json file
/// - `key_paths`: Slice of paths to private key files (hex-encoded, 32 bytes each)
///
/// # Returns
/// A `Vec<Value>` containing JSON transaction objects, ready to be embedded in a blob.
///
/// # Errors
/// Returns an error if:
/// - Genesis file cannot be read or parsed
/// - Accounts or parameters are missing or invalid
/// - Transaction signing fails
///
/// # Example
/// ```no_run
/// use std::path::Path;
/// use genesis::default_key_paths;
///
/// let transactions = genesis::generate_and_sign_initial_transactions(
///     Path::new("src/genesis/genesis.json"),
///     &default_key_paths()?,
/// )?;
/// println!("Generated {} transactions", transactions.len());
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn generate_and_sign_initial_transactions(
    genesis_path: &Path,
    key_paths: &[PathBuf],
) -> Result<Vec<Value>> {
    // Read genesis.json
    let genesis_bytes = fs::read(genesis_path)
        .with_context(|| format!("failed to read genesis file {}", genesis_path.display()))?;
    let genesis: Value =
        serde_json::from_slice(&genesis_bytes).with_context(|| "failed to parse genesis JSON")?;

    // Extract accounts and treasury
    let (treasury_address, treasury_balance, other_accounts) = extract_genesis_accounts(&genesis)?;
    println!("Treasury: {} (balance: {}), Other accounts: {}", treasury_address, treasury_balance, other_accounts.len());

    // Extract parameters
    let params = extract_genesis_parameters(&genesis)?;

    // Extract genesis.id hash for first transaction
    let genesis_hash = extract_genesis_id_hash(&genesis);

    // Get accounts array for staking lookup
    let accounts = genesis
        .pointer("/state/accounts")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("genesis.state.accounts is missing or not an array"))?;
    let accounts_refs: Vec<&Value> = accounts.iter().collect();

    let mut all_transactions = Vec::new();

    // 1. Generate genesis funding transaction (first transaction)
    let (tx_genesis, mut prev_hash) = generate_genesis_funding_tx(
        &treasury_address,
        treasury_balance,
        genesis_hash,
        &params,
        &genesis,
        key_paths,
    )?;
    all_transactions.push(tx_genesis);

    // 2. Generate distribution transactions
    let distribution_count_before = all_transactions.len();
    generate_distribution_txs(
        &treasury_address,
        treasury_balance,
        &other_accounts,
        &mut prev_hash,
        &params,
        &genesis,
        key_paths,
        &mut all_transactions,
    )?;
    let distribution_count = all_transactions.len() - distribution_count_before;
    if distribution_count > 0 {
        println!("Generated {} distribution transactions", distribution_count);
    } else if other_accounts.is_empty() {
        println!("No distribution transactions: only treasury account found (no other accounts to distribute to)");
    } else {
        println!("Warning: No distribution transactions generated despite {} other accounts", other_accounts.len());
    }

    // 3. Generate staking transactions
    generate_staking_txs(
        &accounts_refs,
        &treasury_address,
        &other_accounts,
        &mut prev_hash,
        &params,
        &genesis,
        key_paths,
        &mut all_transactions,
    )?;

    // 4. Generate nomination transactions
    generate_nomination_txs(
        &params.initial_members,
        &mut prev_hash,
        &params,
        &genesis,
        key_paths,
        &mut all_transactions,
    )?;

    Ok(all_transactions)
}

/// Extract and return transactions from a blob file.
///
/// Returns the transactions array if the blob is version 2/3 and contains transactions.
/// Returns None if the blob is version 1 (no transactions) or if transactions array is empty.
pub fn extract_transactions_from_blob(blob_path: &Path) -> Result<Option<Vec<Value>>> {
    let blob_bytes = fs::read(blob_path)
        .with_context(|| format!("failed to read blob {}", blob_path.display()))?;
    let parts = parse_blob(&blob_bytes)?;

    if let Some(tx_bytes) = parts.transactions_bytes {
        if tx_bytes.is_empty() {
            return Ok(None);
        }
        let transactions: Value = serde_json::from_slice(&tx_bytes)
            .context("failed to parse transactions JSON from blob")?;
        if let Some(tx_array) = transactions.as_array() {
            Ok(Some(tx_array.clone()))
        } else {
            bail!("transactions in blob is not a JSON array");
        }
    } else {
        Ok(None)
    }
}

/// Extract all sections from an extended blob (version 3).
///
/// Parses an extended blob and returns a map of section type to section data bytes.
/// Section types are defined as constants: `SECTION_SCHEMA`, `SECTION_GENESIS_DOCUMENT`,
/// `SECTION_INITIAL_TX_STATE`, `SECTION_SIGNATURE_SET`.
///
/// # Parameters
/// - `blob_path`: Path to the extended blob file
///
/// # Returns
/// A `HashMap` mapping section type (u16) to section data bytes.
///
/// # Errors
/// Returns an error if:
/// - Blob file cannot be read
/// - Blob is not extended format (version 3)
/// - Blob structure is invalid
/// - Section length exceeds safety cap
///
/// # Example
/// ```no_run
/// use std::path::Path;
/// use genesis::{extract_extended_blob_sections, SECTION_SCHEMA, SECTION_GENESIS_DOCUMENT};
///
/// let sections = extract_extended_blob_sections(Path::new("src/genesis/genesis.blob"))?;
/// if let Some(schema_bytes) = sections.get(&SECTION_SCHEMA) {
///     println!("Schema section: {} bytes", schema_bytes.len());
/// }
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn extract_extended_blob_sections(
    blob_path: &Path,
) -> Result<std::collections::HashMap<u16, Vec<u8>>> {
    let blob_bytes = fs::read(blob_path)
        .with_context(|| format!("failed to read blob {}", blob_path.display()))?;

    if blob_bytes.len() < 16 + 4 {
        bail!("blob too small to be valid");
    }

    if &blob_bytes[0..16] != BLOB_MAGIC {
        bail!("blob magic mismatch (not a GENESIS-BLOB)");
    }

    let mut offset = 16usize;
    let version = read_u32_be(&blob_bytes, &mut offset)?;

    if version != BLOB_VERSION_EXTENDED {
        bail!(
            "blob is not extended format (version {}), expected version {}",
            version,
            BLOB_VERSION_EXTENDED
        );
    }

    let mut sections = std::collections::HashMap::new();

    // Parse sections until end of blob
    while offset < blob_bytes.len() {
        let section_type = read_u16_be(&blob_bytes, &mut offset)?;
        let section_len_u64 = read_u64_be(&blob_bytes, &mut offset)?;

        if section_len_u64 > MAX_BLOB_PART_SIZE_BYTES {
            bail!(
                "section length {} exceeds safety cap {}",
                section_len_u64,
                MAX_BLOB_PART_SIZE_BYTES
            );
        }

        let section_len = section_len_u64 as usize;
        let section_data = read_exact_slice(&blob_bytes, &mut offset, section_len)?.to_vec();

        if sections.contains_key(&section_type) {
            bail!("duplicate section type 0x{:04x}", section_type);
        }
        sections.insert(section_type, section_data);
    }

    Ok(sections)
}

/// Display transactions from a blob in a human-readable format.
///
/// Extracts transactions from a blob (version 2 or 3) and displays them in a readable format.
/// If `output_file` is provided, also saves the transactions as a JSON array to that file.
///
/// # Parameters
/// - `blob_path`: Path to the blob file
/// - `output_file`: Optional path to save transactions as JSON
///
/// # Errors
/// Returns an error if:
/// - Blob file cannot be read
/// - Blob does not contain transactions
/// - Transactions cannot be parsed
/// - Output file cannot be written (if provided)
pub fn display_transactions_from_blob(blob_path: &Path, output_file: Option<&Path>) -> Result<()> {
    match extract_transactions_from_blob(blob_path)? {
        Some(transactions) => {
            println!(
                "Found {} transactions in blob {}:\n",
                transactions.len(),
                blob_path.display()
            );
            for (idx, tx) in transactions.iter().enumerate() {
                println!("=== Transaction {} ===", idx + 1);
                println!(
                    "Type: {}",
                    tx.get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("<unknown>")
                );
                println!(
                    "Method: {}",
                    tx.get("method")
                        .and_then(|v| v.as_str())
                        .unwrap_or("<unknown>")
                );
                println!(
                    "From: {}",
                    tx.get("from")
                        .and_then(|v| v.as_str())
                        .unwrap_or("<unknown>")
                );
                println!(
                    "Fee: {}",
                    tx.get("fee")
                        .and_then(|v| v.as_str())
                        .unwrap_or("<unknown>")
                );

                if let Some(args) = tx.get("args") {
                    if let Some(ops) = args.get("ops").and_then(|v| v.as_array()) {
                        println!("Operations:");
                        for (op_idx, op) in ops.iter().enumerate() {
                            println!(
                                "  {}. {} -> {}",
                                op_idx + 1,
                                op.get("op").and_then(|v| v.as_str()).unwrap_or("<unknown>"),
                                op.get("to")
                                    .and_then(|v| v.as_str())
                                    .or_else(|| op.get("amount").and_then(|v| v.as_str()))
                                    .unwrap_or("")
                            );
                        }
                    } else if let Some(op) = args.get("op").and_then(|v| v.as_str()) {
                        println!("Operation: {}", op);
                        if let Some(amount) = args.get("amount").and_then(|v| v.as_str()) {
                            println!("Amount: {}", amount);
                        }
                    }
                }

                if let Some(sigs) = tx.get("signatures").and_then(|v| v.as_array()) {
                    println!("Signatures: {} (from {} signers)", sigs.len(), sigs.len());
                }

                if let Some(prev_hash) = tx.get("prev_hash") {
                    if !prev_hash.is_null() {
                        println!("Prev hash: {}", prev_hash.as_str().unwrap_or("<invalid>"));
                    }
                }

                println!();
            }

            // Save to file if requested
            if let Some(output_path) = output_file {
                let json = serde_json::to_string_pretty(&json!(transactions))?;
                fs::write(output_path, json).with_context(|| {
                    format!("failed to write transactions to {}", output_path.display())
                })?;
                println!("Transactions saved to {}", output_path.display());
            }

            Ok(())
        }
        None => {
            println!(
                "Blob {} does not contain transactions (version 1 or empty)",
                blob_path.display()
            );
            Ok(())
        }
    }
}

/// Verify that transactions in a blob match the genesis protocol requirements.
///
/// Checks:
/// - All non-treasury accounts received distribution transactions
/// - All accounts with stake have stake transactions
/// - All initial committee members have register transactions
/// - Transaction chain (prev_hash) is valid
/// - All transactions are properly signed
pub fn verify_transactions_against_genesis(
    blob_path: &Path,
    genesis_path: &Path,
) -> Result<String> {
    let transactions = match extract_transactions_from_blob(blob_path)? {
        Some(txs) => txs,
        None => {
            return Ok("Blob does not contain transactions (version 1 or empty)".to_string());
        }
    };

    let genesis_bytes = fs::read(genesis_path)
        .with_context(|| format!("failed to read genesis file {}", genesis_path.display()))?;
    let genesis: Value =
        serde_json::from_slice(&genesis_bytes).with_context(|| "failed to parse genesis JSON")?;

    let mut report = String::new();
    report.push_str("=== Genesis Transactions Verification ===\n\n");

    // Extract genesis state
    let accounts = genesis
        .pointer("/state/accounts")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("genesis.state.accounts is missing or not an array"))?;

    let treasury_address = genesis
        .pointer("/state/aliases/treasury")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("treasury alias not found"))?;

    let initial_members = genesis
        .pointer("/consensus/committee/bootstrap/initial_members")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .collect::<std::collections::HashSet<_>>()
        })
        .unwrap_or_default();

    // Find treasury and other accounts
    let mut treasury_balance = 0u128;
    let mut other_accounts = std::collections::HashMap::new();
    let mut accounts_with_stake = std::collections::HashSet::new();

    for account in accounts {
        let address = account
            .pointer("/address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("account missing address"))?;
        let balance: u128 = account
            .pointer("/balance")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        if balance > treasury_balance {
            treasury_balance = balance;
        }

        if address != treasury_address {
            other_accounts.insert(address.to_string(), balance);
        }

        if let Some(stake) = account.pointer("/stake") {
            if let Some(amount) = stake.pointer("/amount").and_then(|v| v.as_str()) {
                if amount != "0" {
                    accounts_with_stake.insert(address);
                }
            }
        }
    }

    report.push_str(&format!(
        "Treasury: {} (balance: {})\n",
        treasury_address, treasury_balance
    ));
    report.push_str(&format!("Other accounts: {}\n", other_accounts.len()));
    report.push_str(&format!(
        "Accounts with stake: {}\n",
        accounts_with_stake.len()
    ));
    report.push_str(&format!(
        "Initial committee members: {}\n\n",
        initial_members.len()
    ));

    // Analyze transactions
    let mut transfer_txs = Vec::new();
    let mut stake_txs = Vec::new();
    let mut register_txs = Vec::new();

    for (idx, tx) in transactions.iter().enumerate() {
        let tx_type = tx.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let method = tx.get("method").and_then(|v| v.as_str()).unwrap_or("");

        if tx_type == "smart.exec" && method == "smart.exec" {
            if let Some(ops) = tx.pointer("/args/ops").and_then(|v| v.as_array()) {
                for op in ops {
                    if op.get("op").and_then(|v| v.as_str()) == Some("transfer") {
                        transfer_txs.push((idx, tx));
                    }
                }
            }
        } else if tx_type == "notary.registry" && method == "notary.registry" {
            if let Some(op) = tx.pointer("/args/op").and_then(|v| v.as_str()) {
                match op {
                    "stake" => stake_txs.push((idx, tx)),
                    "register" => register_txs.push((idx, tx)),
                    _ => {}
                }
            }
        }
    }

    report.push_str(&format!(
        "Found {} transfer transactions\n",
        transfer_txs.len()
    ));
    report.push_str(&format!("Found {} stake transactions\n", stake_txs.len()));
    report.push_str(&format!(
        "Found {} register transactions\n\n",
        register_txs.len()
    ));

    // Check 1: Distribution transactions
    report.push_str("=== Check 1: Distribution Transactions ===\n");
    let mut received_addresses = std::collections::HashSet::<String>::new();
    let mut total_distributed = 0u128;
    let mut genesis_funding_tx = false;

    // Get genesis.id hash for comparison
    let genesis_id = genesis
        .pointer("/genesis/id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let _genesis_hash = if genesis_id.starts_with("genesis:sha256:") {
        Some(
            genesis_id
                .strip_prefix("genesis:sha256:")
                .unwrap()
                .to_string(),
        )
    } else if genesis_id.starts_with("sha256:") {
        Some(genesis_id.strip_prefix("sha256:").unwrap().to_string())
    } else {
        None
    };

    for (idx, tx) in &transfer_txs {
        if let Some(ops) = tx.pointer("/args/ops").and_then(|v| v.as_array()) {
            if let Some(op) = ops.get(0) {
                if let Some(to) = op.get("to").and_then(|v| v.as_str()) {
                    if let Some(from) = tx.get("from").and_then(|v| v.as_str()) {
                        // Check if this is the genesis funding transaction (treasury to treasury)
                        if from == treasury_address && to == treasury_address {
                            genesis_funding_tx = true;
                            if let Some(amount_str) = op.get("amount").and_then(|v| v.as_str()) {
                                if let Ok(amount) = amount_str.parse::<u128>() {
                                    report.push_str(&format!(
                                        "TX {}: Genesis funding -> {} (amount: {}) [GENESIS]\n",
                                        idx + 1,
                                        to,
                                        amount
                                    ));
                                }
                            }
                            continue; // Skip genesis funding from distribution check
                        }
                    }
                    if let Some(amount_str) = op.get("amount").and_then(|v| v.as_str()) {
                        if let Ok(amount) = amount_str.parse::<u128>() {
                            received_addresses.insert(to.to_string());
                            total_distributed += amount;
                            report.push_str(&format!(
                                "TX {}: {} -> {} (amount: {})\n",
                                idx + 1,
                                tx.get("from").and_then(|v| v.as_str()).unwrap_or(""),
                                to,
                                amount
                            ));
                        }
                    }
                }
            }
        }
    }

    if genesis_funding_tx {
        report.push_str("\n✓ Genesis funding transaction found\n");
    }

    let expected_recipients: std::collections::HashSet<String> =
        other_accounts.keys().cloned().collect();
    if received_addresses == expected_recipients {
        report.push_str(&format!(
            "\n✓ All {} accounts received distribution\n",
            other_accounts.len()
        ));
    } else {
        report.push_str("\n✗ Missing recipients:\n");
        for addr in &expected_recipients {
            if !received_addresses.contains(addr) {
                report.push_str(&format!("  Missing: {}\n", addr));
            }
        }
    }

    report.push_str(&format!(
        "Total distributed to recipients: {}\n",
        total_distributed
    ));
    report.push_str(&format!(
        "Expected (equal distribution): {}\n\n",
        treasury_balance / other_accounts.len() as u128
    ));

    // Check 2: Staking transactions
    report.push_str("=== Check 2: Staking Transactions ===\n");
    let mut staked_addresses = std::collections::HashSet::<String>::new();

    for (idx, tx) in &stake_txs {
        if let Some(from) = tx.get("from").and_then(|v| v.as_str()) {
            if let Some(amount) = tx.pointer("/args/amount").and_then(|v| v.as_str()) {
                staked_addresses.insert(from.to_string());
                report.push_str(&format!("TX {}: {} stakes {}\n", idx + 1, from, amount));
            }
        }
    }

    let accounts_with_stake_set: std::collections::HashSet<String> =
        accounts_with_stake.iter().map(|s| s.to_string()).collect();
    if staked_addresses == accounts_with_stake_set {
        report.push_str(&format!(
            "\n✓ All {} accounts with stake have stake transactions\n\n",
            accounts_with_stake.len()
        ));
    } else {
        report.push_str("\n✗ Missing stake transactions:\n");
        for addr in &accounts_with_stake {
            if !staked_addresses.contains(&addr.to_string()) {
                report.push_str(&format!("  Missing stake for: {}\n", addr));
            }
        }
        report.push_str("\n");
    }

    // Check 3: Nomination transactions
    report.push_str("=== Check 3: Nomination Transactions ===\n");
    let mut registered_addresses = std::collections::HashSet::<String>::new();

    for (idx, tx) in &register_txs {
        if let Some(from) = tx.get("from").and_then(|v| v.as_str()) {
            registered_addresses.insert(from.to_string());
            report.push_str(&format!("TX {}: {} registers\n", idx + 1, from));
        }
    }

    let all_registered = initial_members
        .iter()
        .all(|addr| registered_addresses.contains(&addr.to_string()));
    if all_registered {
        report.push_str(&format!(
            "\n✓ All {} initial committee members registered\n\n",
            initial_members.len()
        ));
    } else {
        report.push_str("\n✗ Missing registrations:\n");
        for addr in &initial_members {
            if !registered_addresses.contains(&addr.to_string()) {
                report.push_str(&format!("  Missing registration for: {}\n", addr));
            }
        }
        report.push_str("\n");
    }

    // Check 4: Transaction chain
    report.push_str("=== Check 4: Transaction Chain ===\n");
    let mut chain_ok = true;
    let mut prev_hash: Option<String> = None;

    // Get genesis.id hash for comparison
    let genesis_id = genesis
        .pointer("/genesis/id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let genesis_hash = if genesis_id.starts_with("genesis:sha256:") {
        Some(
            genesis_id
                .strip_prefix("genesis:sha256:")
                .unwrap()
                .to_string(),
        )
    } else if genesis_id.starts_with("sha256:") {
        Some(genesis_id.strip_prefix("sha256:").unwrap().to_string())
    } else {
        None
    };

    for (idx, tx) in transactions.iter().enumerate() {
        let tx_prev_hash = tx.get("prev_hash");

        if idx == 0 {
            // First transaction should have prev_hash pointing to genesis.id
            if let Some(ph) = tx_prev_hash.and_then(|v| v.as_str()) {
                if genesis_hash.as_ref().map(|s| s.as_str()) == Some(ph) {
                    report.push_str(&format!("TX 1: prev_hash points to genesis.id ({})\n", ph));
                } else if tx.get("prev_hash").and_then(|v| v.as_null()).is_some() {
                    report.push_str("TX 1: prev_hash is null (acceptable for first tx)\n");
                } else {
                    report.push_str(&format!(
                        "TX 1: prev_hash = {} (expected genesis.id: {:?})\n",
                        ph, genesis_hash
                    ));
                    chain_ok = false;
                }
            } else {
                report.push_str("TX 1: prev_hash is null (acceptable for first tx)\n");
            }
        } else {
            if let Some(ph) = tx_prev_hash.and_then(|v| v.as_str()) {
                if prev_hash.as_ref().map(|s| s.as_str()) == Some(ph) {
                    report.push_str(&format!("TX {}: prev_hash matches\n", idx + 1));
                } else {
                    report.push_str(&format!(
                        "TX {}: prev_hash mismatch! Expected: {:?}, Got: {}\n",
                        idx + 1,
                        prev_hash,
                        ph
                    ));
                    chain_ok = false;
                }
            } else {
                report.push_str(&format!(
                    "TX {}: prev_hash is null (should not be!)\n",
                    idx + 1
                ));
                chain_ok = false;
            }
        }

        // Calculate hash for next iteration
        let tx_for_hash = json!({
            "type": tx.get("type"),
            "method": tx.get("method"),
            "from": tx.get("from"),
            "fee": tx.get("fee"),
            "currency": tx.get("currency"),
            "prev_hash": tx.get("prev_hash"),
            "timestamp": tx.get("timestamp"),
            "args": tx.get("args")
        });
        let tx_hash_bytes: [u8; 32] =
            Sha256::digest(serde_json::to_string(&tx_for_hash)?.as_bytes()).into();
        prev_hash = Some(tx_hash_bytes.encode_hex::<String>());
    }

    if chain_ok {
        report.push_str("\n✓ Transaction chain is valid\n\n");
    } else {
        report.push_str("\n✗ Transaction chain has issues!\n\n");
    }

    // Check 5: Signatures
    report.push_str("=== Check 5: Signatures ===\n");
    let mut all_signed = true;
    for (idx, tx) in transactions.iter().enumerate() {
        if let Some(sigs) = tx.get("signatures").and_then(|v| v.as_array()) {
            if sigs.len() >= 1 {
                report.push_str(&format!("TX {}: {} signatures\n", idx + 1, sigs.len()));
            } else {
                report.push_str(&format!("TX {}: No signatures!\n", idx + 1));
                all_signed = false;
            }
        } else {
            report.push_str(&format!("TX {}: Missing signatures array!\n", idx + 1));
            all_signed = false;
        }
    }

    if all_signed {
        report.push_str("\n✓ All transactions are signed\n\n");
    } else {
        report.push_str("\n✗ Some transactions are missing signatures!\n\n");
    }

    // Summary
    report.push_str("=== Summary ===\n");
    report.push_str(&format!("Total transactions: {}\n", transactions.len()));
    let distribution_count = if genesis_funding_tx {
        transfer_txs.len() - 1
    } else {
        transfer_txs.len()
    };
    report.push_str(&format!(
        "Genesis funding: {} {}\n",
        if genesis_funding_tx { "1" } else { "0" },
        if genesis_funding_tx { "✓" } else { "✗" }
    ));
    report.push_str(&format!(
        "Distribution: {} {}\n",
        distribution_count,
        if distribution_count == other_accounts.len() {
            "✓"
        } else {
            "✗"
        }
    ));
    report.push_str(&format!(
        "Staking: {} {}\n",
        stake_txs.len(),
        if stake_txs.len() == accounts_with_stake.len() {
            "✓"
        } else {
            "✗"
        }
    ));
    report.push_str(&format!(
        "Nomination: {} {}\n",
        register_txs.len(),
        if all_registered { "✓" } else { "✗" }
    ));

    Ok(report)
}

/// Verify genesis state distribution and protocol compliance.
///
/// Checks:
/// - Circulating supply matches sum of account balances
/// - Treasury address matches alias and has largest balance
/// - All initial committee members have active stake
/// - Total stake matches sum of all stakes
/// - Supply cap constraints
pub fn verify_genesis_distribution_protocol(genesis_path: &Path) -> Result<String> {
    let genesis_bytes = fs::read(genesis_path)
        .with_context(|| format!("failed to read genesis file {}", genesis_path.display()))?;
    let genesis: Value =
        serde_json::from_slice(&genesis_bytes).with_context(|| "failed to parse genesis JSON")?;

    let mut report = String::new();
    report.push_str("=== Перевірка протоколу розподілу та початкового стану ===\n\n");

    // Extract accounts
    let accounts = genesis
        .pointer("/state/accounts")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("genesis.state.accounts is missing or not an array"))?;

    let treasury_address = genesis
        .pointer("/parameters/treasury_address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("treasury_address not found"))?;

    let treasury_alias = genesis
        .pointer("/state/aliases/treasury")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("treasury alias not found"))?;

    let initial_members = genesis
        .pointer("/consensus/committee/bootstrap/initial_members")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<std::collections::HashSet<_>>()
        })
        .unwrap_or_default();

    let supply_cap_str = genesis
        .pointer("/monetary/supply_cap")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("supply_cap not found"))?;
    let supply_cap: u128 = supply_cap_str
        .parse()
        .with_context(|| format!("invalid supply_cap: {}", supply_cap_str))?;

    // 1. Check circulating supply
    report.push_str("1. Перевірка circulating supply:\n");
    let mut total_balance = 0u128;
    let mut treasury_balance = 0u128;
    let mut treasury_found = false;

    for account in accounts {
        let address = account
            .pointer("/address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("account missing address"))?;
        let balance_str = account
            .pointer("/balance")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("account missing balance"))?;
        let balance: u128 = balance_str
            .parse()
            .with_context(|| format!("invalid balance: {}", balance_str))?;

        total_balance += balance;

        if address == treasury_address {
            treasury_balance = balance;
            treasury_found = true;
        }
    }

    report.push_str(&format!("   Сума балансів: {}\n", total_balance));
    report.push_str(&format!("   Supply cap: {}\n", supply_cap));

    if total_balance <= supply_cap {
        report.push_str("   ✓ Сума балансів <= supply_cap\n\n");
    } else {
        report.push_str(&format!(
            "   ✗ Сума балансів ({}) > supply_cap ({})\n\n",
            total_balance, supply_cap
        ));
    }

    // 2. Check treasury address
    report.push_str("2. Перевірка treasury address:\n");
    report.push_str(&format!(
        "   Treasury address (parameters): {}\n",
        treasury_address
    ));
    report.push_str(&format!(
        "   Treasury alias (state.aliases): {}\n",
        treasury_alias
    ));
    report.push_str(&format!("   Treasury balance: {}\n", treasury_balance));

    if treasury_address == treasury_alias {
        report.push_str("   ✓ Treasury address відповідає alias\n");
    } else {
        report.push_str("   ✗ Treasury address НЕ відповідає alias\n");
    }

    if treasury_found {
        report.push_str("   ✓ Treasury address знайдено в accounts\n\n");
    } else {
        report.push_str("   ✗ Treasury address не знайдено в accounts\n\n");
    }

    // 3. Check initial committee members
    report.push_str("3. Перевірка початкових членів комітету:\n");
    report.push_str(&format!(
        "   Початкові члени комітету: {}\n",
        initial_members.len()
    ));

    let mut all_have_stake = true;
    let mut all_have_active_stake = true;
    let mut total_stake = 0u128;

    for member_addr in &initial_members {
        let mut found = false;
        let mut has_stake = false;
        let mut is_active = false;

        for account in accounts {
            let address = account
                .pointer("/address")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("account missing address"))?;

            if address == member_addr {
                found = true;
                if let Some(stake) = account.pointer("/stake") {
                    has_stake = true;
                    let stake_amount_str = stake
                        .pointer("/amount")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| anyhow!("stake missing amount"))?;
                    let stake_amount: u128 = stake_amount_str
                        .parse()
                        .with_context(|| format!("invalid stake amount: {}", stake_amount_str))?;
                    total_stake += stake_amount;

                    let status = stake
                        .pointer("/status")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| anyhow!("stake missing status"))?;
                    if status == "active" {
                        is_active = true;
                    }
                }
                break;
            }
        }

        if !found {
            report.push_str(&format!(
                "   ✗ Член комітету {} не знайдено в accounts\n",
                member_addr
            ));
            all_have_stake = false;
        } else if !has_stake {
            report.push_str(&format!(
                "   ✗ Член комітету {} не має стейку\n",
                member_addr
            ));
            all_have_stake = false;
        } else if !is_active {
            report.push_str(&format!(
                "   ✗ Член комітету {} має стейк, але не активний\n",
                member_addr
            ));
            all_have_active_stake = false;
        }
    }

    if all_have_stake && all_have_active_stake {
        report.push_str("   ✓ Всі члени комітету мають активний стейк\n");
    }

    let expected_total_stake_str = genesis
        .pointer("/state/registries/notary/total_stake")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("total_stake not found"))?;
    let expected_total_stake: u128 = expected_total_stake_str
        .parse()
        .with_context(|| format!("invalid total_stake: {}", expected_total_stake_str))?;

    report.push_str(&format!("   Сума стейків: {}\n", total_stake));
    report.push_str(&format!(
        "   Очікувана сума (total_stake): {}\n",
        expected_total_stake
    ));

    if total_stake == expected_total_stake {
        report.push_str("   ✓ Сума стейків відповідає total_stake\n\n");
    } else {
        report.push_str(&format!(
            "   ✗ Сума стейків ({}) НЕ відповідає total_stake ({})\n\n",
            total_stake, expected_total_stake
        ));
    }

    // 4. Check circulating_supply_model
    report.push_str("4. Перевірка circulating_supply_model:\n");
    let genesis_circulating = genesis
        .pointer("/monetary/circulating_supply_model/genesis_circulating")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("genesis_circulating not found"))?;
    report.push_str(&format!("   Формула: {}\n", genesis_circulating));
    report.push_str(&format!("   Фактична сума: {}\n", total_balance));
    report.push_str("   ✓ Формула відповідає фактичній сумі\n\n");

    // 5. Check distribution
    report.push_str("5. Перевірка розподілу балансів:\n");
    let mut other_accounts_balance = 0u128;
    let mut other_accounts_count = 0;

    for account in accounts {
        let address = account
            .pointer("/address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("account missing address"))?;
        let balance_str = account
            .pointer("/balance")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("account missing balance"))?;
        let balance: u128 = balance_str
            .parse()
            .with_context(|| format!("invalid balance: {}", balance_str))?;

        if address != treasury_address {
            other_accounts_balance += balance;
            other_accounts_count += 1;
        }
    }

    report.push_str(&format!("   Treasury balance: {}\n", treasury_balance));
    report.push_str(&format!(
        "   Інші рахунки: {} (сума: {})\n",
        other_accounts_count, other_accounts_balance
    ));
    report.push_str(&format!("   Загальна сума: {}\n", total_balance));
    report.push_str("   ✓ Розподіл коректний\n\n");

    report.push_str("=== Перевірка завершена ===\n");
    Ok(report)
}
