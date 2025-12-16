// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Pavlo Chabanov, Gliesereum Ukraine LLC
// Main Developer & Author: Pavlo Chabanov

use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::Parser;

#[derive(Parser)]
#[command(
    name = "genesis",
    about = "Genesis tooling: validate, blob+sign, verify, import"
)]
struct Args {
    /// Private key files (hex, 32 bytes) used to sign the blob. Defaults to the five keys in repo root.
    #[arg(long = "key-file", value_name = "PATH")]
    key_files: Vec<PathBuf>,

    /// Validate supplied document against the schema and then produce blob+signature.
    #[arg(long = "validate", value_name = "FILE")]
    validate_doc: Option<PathBuf>,

    /// JSON Schema file to validate against.
    #[arg(long = "schema", default_value = "src/schemes/genesis-smart-1.0.json")]
    schema: PathBuf,

    /// Output path for the generated blob when validating (defaults to <document>.blob).
    #[arg(long = "blob-out", value_name = "PATH")]
    blob_out: Option<PathBuf>,

    /// Output path for the blob signature JSON (defaults to <blob-out>.sig.json).
    #[arg(long = "sig-out", value_name = "PATH")]
    sig_out: Option<PathBuf>,

    /// Threshold k for signatures in the generated signature file (k-of-n).
    ///
    /// Defaults to `n` (all provided keys must sign), i.e. `k=n`.
    #[arg(long = "threshold-k", value_name = "K")]
    threshold_k: Option<usize>,

    /// Verify a previously created blob and its signature file.
    #[arg(long = "verify-blob", value_name = "FILE")]
    verify_blob: Option<PathBuf>,

    /// Signature JSON to use for verification (defaults to <blob>.sig.json).
    #[arg(long = "sig", value_name = "FILE")]
    sig: Option<PathBuf>,

    /// Import an old full genesis contract JSON, migrate it to the current schema, then validate and blob+sign it.
    #[arg(long = "import-old", value_name = "FILE")]
    import_old: Option<PathBuf>,

    /// Output path for imported genesis JSON.
    #[arg(
        long = "import-out",
        default_value = "src/genesis/genesis.from-old.json",
        value_name = "FILE"
    )]
    import_out: PathBuf,

    /// Human-readable audit report for a contract (.json) or blob (.blob).
    #[arg(long = "report", value_name = "FILE")]
    report: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if let Some(path) = &args.report {
        let sig_path = args.sig.clone();
        let report = genesis::render_audit_report(path, Some(&args.schema), sig_path.as_deref())?;
        println!("{report}");
        return Ok(());
    }

    if let Some(old_path) = &args.import_old {
        genesis::import_old_contract(old_path, &args.import_out)?;
        genesis::validate_document(&args.schema, &args.import_out)?;

        let key_paths = if args.key_files.is_empty() {
            genesis::default_key_paths()?
        } else {
            args.key_files.clone()
        };

        let blob_out = args
            .blob_out
            .clone()
            .unwrap_or_else(|| genesis::default_blob_out(&args.import_out));
        let sig_out = args
            .sig_out
            .clone()
            .unwrap_or_else(|| genesis::default_sig_out(&blob_out));

        genesis::create_blob_and_sign(
            &args.import_out,
            &args.schema,
            &key_paths,
            args.threshold_k,
            &blob_out,
            &sig_out,
        )?;
        return Ok(());
    }

    if let Some(doc_path) = &args.validate_doc {
        genesis::validate_document(&args.schema, doc_path)?;

        let key_paths = if args.key_files.is_empty() {
            genesis::default_key_paths()?
        } else {
            args.key_files.clone()
        };

        let blob_out = args
            .blob_out
            .clone()
            .unwrap_or_else(|| genesis::default_blob_out(doc_path));
        let sig_out = args
            .sig_out
            .clone()
            .unwrap_or_else(|| genesis::default_sig_out(&blob_out));

        genesis::create_blob_and_sign(
            doc_path,
            &args.schema,
            &key_paths,
            args.threshold_k,
            &blob_out,
            &sig_out,
        )?;
        return Ok(());
    }

    if let Some(blob_path) = &args.verify_blob {
        let sig_path = args
            .sig
            .clone()
            .unwrap_or_else(|| genesis::default_sig_out(blob_path));
        genesis::verify_blob_and_signatures(blob_path, &sig_path)?;
        return Ok(());
    }

    bail!("No action specified. Use --report, --validate, --verify-blob, or --import-old.")
}
