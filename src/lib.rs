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
//!
//! ## Artifact layout (recommended)
//!
//! - `src/genesis/genesis.json` — the Genesis contract
//! - `src/schemes/genesis-smart-1.0.json` — the JSON Schema
//! - `src/genesis/genesis.blob` — signed blob packaging contract+schema bytes
//! - `src/genesis/genesis.sig.json` — signatures for the blob
//!
//! ## Signature model (blob package)
//!
//! - **Message**: `SHA256(blob_bytes)` (32-byte prehash)
//! - **Algorithm**: ECDSA secp256k1, DER-encoded signatures
//! - **Public key format**: compressed SEC1 (33 bytes, prefix `0x02`/`0x03`)
//! - **Threshold**: `k-of-n`, enforced using **unique** valid signers (duplicate entries do not count)
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
    ".private_key.s-0001",
    ".private_key.s-0002",
    ".private_key.s-0003",
    ".private_key.s-0004",
    ".private_key.s-0005",
];

const BLOB_MAGIC: &[u8; 16] = b"GENESIS-BLOB\0\0\0\0";
const BLOB_VERSION: u32 = 1;
const MAX_BLOB_PART_SIZE_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB safety cap per part
const PUBKEY_COMPRESSED_BYTES: usize = 33;
const MAX_SIG_DER_BYTES: usize = 128; // generous cap; typical DER ECDSA(secp256k1) is ~70-72 bytes

/// Metadata about a blob component (path/size/sha256).
#[derive(Serialize, Deserialize)]
pub struct BlobPartMeta {
    /// Source path as recorded by the generator (informational only).
    pub path: String,
    /// Byte length of the component.
    pub size: usize,
    /// SHA-256 of the component in the form `sha256:<64 hex>`.
    pub sha256: String,
}

/// A single signer entry in the blob signature file.
#[derive(Serialize, Deserialize)]
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
/// Format (big-endian):
/// - 16 bytes: magic `GENESIS-BLOB\\0\\0\\0\\0`
/// - 4 bytes: version (`1`)
/// - 8 bytes: document length
/// - N bytes: document bytes (raw, not re-serialized)
/// - 8 bytes: schema length
/// - M bytes: schema bytes (raw, not re-serialized)
pub fn build_blob_bytes(doc_bytes: &[u8], schema_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + 4 + 8 + doc_bytes.len() + 8 + schema_bytes.len());
    out.extend_from_slice(BLOB_MAGIC);
    out.extend_from_slice(&BLOB_VERSION.to_be_bytes());
    out.extend_from_slice(&(doc_bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(doc_bytes);
    out.extend_from_slice(&(schema_bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(schema_bytes);
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
    if version != BLOB_VERSION {
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

/// Create a blob from `{doc_path, schema_path}` and sign it with the provided keys.
///
/// The signature file (`sig_out`) contains:
/// - hashes and sizes of blob/document/schema
/// - `k-of-n` threshold
/// - signer entries with `kid`, compressed public key, and DER signature
///
/// **Important**: `kid` derivation uses `addressing.version_byte` taken from the document JSON.
pub fn create_blob_and_sign(
    doc_path: &Path,
    schema_path: &Path,
    key_paths: &[PathBuf],
    threshold_k: Option<usize>,
    blob_out: &Path,
    sig_out: &Path,
) -> Result<()> {
    let doc_bytes = fs::read(doc_path)
        .with_context(|| format!("failed to read document bytes from {}", doc_path.display()))?;
    let schema_bytes = fs::read(schema_path)
        .with_context(|| format!("failed to read schema bytes from {}", schema_path.display()))?;

    let doc_value: Value =
        serde_json::from_slice(&doc_bytes).context("document is not valid JSON")?;
    let version_byte = extract_version_byte_from_doc_value(&doc_value)?;

    let blob_bytes = build_blob_bytes(&doc_bytes, &schema_bytes);
    fs::write(blob_out, &blob_bytes)
        .with_context(|| format!("failed to write blob to {}", blob_out.display()))?;

    let blob_hash_bytes: [u8; 32] = Sha256::digest(&blob_bytes).into();
    let blob_meta = sha256_meta(blob_out, &blob_bytes);
    let doc_meta = sha256_meta(doc_path, &doc_bytes);
    let schema_meta = sha256_meta(schema_path, &schema_bytes);

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
    fs::write(sig_out, sig_json)
        .with_context(|| format!("failed to write signature file to {}", sig_out.display()))?;

    println!("Blob written to {}", blob_out.display());
    println!(
        "Blob hash: sha256:{}",
        blob_hash_bytes.encode_hex::<String>()
    );
    println!("Signature file written to {}", sig_out.display());
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

    if sig_file.blob.size != blob_bytes.len() {
        bail!(
            "blob size mismatch: sig says {}, actual {}",
            sig_file.blob.size,
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

    let blob_hash_actual: [u8; 32] = Sha256::digest(&blob_bytes).into();
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
/// - For `.blob`: uses `sig_path` if provided, otherwise defaults to `<blob>.sig.json`.
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
            let sig = sig_path
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| default_sig_out(input_path));
            render_blob_audit_report(input_path, &sig)
        }
        "json" => {
            let schema =
                schema_path.ok_or_else(|| anyhow!("schema_path is required for .json report"))?;
            render_json_audit_report(input_path, schema)
        }
        other => bail!("unsupported file type '{}'; expected .json or .blob", other),
    }
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

fn render_blob_audit_report(blob_path: &Path, sig_path: &Path) -> Result<String> {
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

    let sig_json = fs::read_to_string(sig_path)
        .with_context(|| format!("failed to read signature file {}", sig_path.display()))?;
    let sig_file: BlobSignatureFile =
        serde_json::from_str(&sig_json).context("failed to parse signature JSON")?;

    let mut out = String::new();
    out.push_str("## Genesis blob audit report\n\n");
    out.push_str(&format!("- **blob**: `{}`\n", blob_path.display()));
    out.push_str(&format!("- **blob_sha256**: `{}`\n", blob_sha));
    out.push_str(&format!("- **sig_file**: `{}`\n", sig_path.display()));
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
    let blob_hash_actual: [u8; 32] = Sha256::digest(&blob_bytes).into();
    let blob_hash_claimed = parse_sha256_hex_prefixed(&sig_file.blob.sha256)?;
    let doc_hash_claimed = parse_sha256_hex_prefixed(&sig_file.document.sha256)?;
    let schema_hash_claimed = parse_sha256_hex_prefixed(&sig_file.schema.sha256)?;
    let doc_hash_actual: [u8; 32] = Sha256::digest(&parts.document_bytes).into();
    let schema_hash_actual: [u8; 32] = Sha256::digest(&parts.schema_bytes).into();

    let integrity_ok = blob_hash_claimed == blob_hash_actual
        && doc_hash_claimed == doc_hash_actual
        && schema_hash_claimed == schema_hash_actual
        && sig_file.blob.size == blob_bytes.len()
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
        let mut blob = build_blob_bytes(doc, schema);
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

        let blob_bytes = build_blob_bytes(doc_bytes, schema_bytes);
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
