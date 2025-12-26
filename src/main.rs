// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Pavlo Chabanov, Gliesereum Ukraine LLC
// Main Developer & Author: Pavlo Chabanov

use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::Parser;
use genesis::{SECTION_GENESIS_DOCUMENT, SECTION_INITIAL_TX_STATE, SECTION_SCHEMA, SECTION_SIGNATURE_SET};
use serde_json::Value;

#[derive(Parser)]
#[command(
    name = "genesis",
    about = "Genesis tooling: create blob, verify, import"
)]
struct Args {
    /// Private key files (hex, 32 bytes) used to sign the blob. Defaults to the five keys in repo root.
    #[arg(long = "key-file", value_name = "PATH")]
    key_files: Vec<PathBuf>,

    /// Create a signed blob from the document.
    /// 
    /// This command:
    /// - Validates the document against the schema
    /// - Generates initial distribution transactions
    /// - Creates a signed blob with embedded signatures (by default)
    #[arg(long = "create-blob", value_name = "FILE")]
    create_blob_doc: Option<PathBuf>,

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
    ///
    /// If the blob contains embedded signatures (extended format), the signature file is optional.
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

    /// Economics audit report (PASS/FAIL invariants) for a contract (.json) or blob (.blob).
    #[arg(long = "economics-audit", value_name = "FILE")]
    economics_audit: Option<PathBuf>,


    /// Use legacy blob format (version 1 or 2) instead of extended format.
    /// By default, extended format (version 3) with all-in-one blob is used.
    #[arg(long = "legacy-format")]
    legacy_format: bool,

    /// Exclude initial transactions from the blob.
    /// By default, transactions are included for network bootstrap.
    #[arg(long = "no-transactions")]
    no_transactions: bool,

    /// Keep signatures in a separate file instead of embedding in blob.
    /// By default, signatures are embedded for all-in-one blob.
    #[arg(long = "detached-signatures")]
    detached_signatures: bool,

    /// Extract and display transactions from a blob file.
    #[arg(long = "extract-transactions", value_name = "BLOB_FILE")]
    extract_transactions: Option<PathBuf>,

    /// Output file for extracted transactions (JSON format).
    /// Used with --extract-transactions to save transactions to a file.
    #[arg(long = "tx-output", value_name = "FILE")]
    tx_output: Option<PathBuf>,

    /// Verify transactions in a blob against genesis protocol requirements.
    #[arg(long = "verify-transactions", value_name = "BLOB_FILE")]
    verify_transactions: Option<PathBuf>,

    /// Genesis file to use for transaction verification.
    /// Used with --verify-transactions.
    #[arg(
        long = "genesis-file",
        default_value = "src/genesis/genesis.json",
        value_name = "FILE"
    )]
    genesis_file: PathBuf,

    /// Verify genesis state distribution and protocol compliance.
    #[arg(long = "verify-distribution", value_name = "GENESIS_FILE")]
    verify_distribution: Option<PathBuf>,

    /// Extract and display all sections from an extended blob (version 3).
    #[arg(long = "extract-sections", value_name = "BLOB_FILE")]
    extract_sections: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if let Some(path) = &args.economics_audit {
        let sig_path = args.sig.clone();
        let report =
            genesis::render_economics_audit_report(path, Some(&args.schema), sig_path.as_deref())?;
        println!("{report}");
        return Ok(());
    }

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
            !args.no_transactions,
        )?;
        return Ok(());
    }

    if let Some(doc_path) = &args.create_blob_doc {
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

        // Default: extended format with embedded signatures and transactions (all-in-one blob)
        let use_extended_format = !args.legacy_format;
        let include_transactions = !args.no_transactions;
        let include_signatures_in_blob = !args.detached_signatures;

        if use_extended_format {
            genesis::create_blob_and_sign_extended(
                doc_path,
                &args.schema,
                &key_paths,
                args.threshold_k,
                &blob_out,
                &sig_out,
                include_transactions,
                true, // use_extended_format
                include_signatures_in_blob,
            )?;
        } else {
            genesis::create_blob_and_sign(
                doc_path,
                &args.schema,
                &key_paths,
                args.threshold_k,
                &blob_out,
                &sig_out,
                include_transactions,
            )?;
        }
        return Ok(());
    }

    if let Some(blob_path) = &args.verify_blob {
        // Try to verify with embedded signatures first, fall back to separate file if needed
        let sig_path = args.sig.clone();
        match genesis::verify_blob(blob_path, sig_path.as_deref()) {
            Ok(()) => return Ok(()),
            Err(e) if e.to_string().contains("signatures are not embedded") => {
                // Signatures not embedded, use separate file
                let sig_path = sig_path.unwrap_or_else(|| genesis::default_sig_out(blob_path));
                genesis::verify_blob_and_signatures(blob_path, &sig_path)?;
                return Ok(());
            }
            Err(e) => return Err(e),
        }
    }


    if let Some(blob_path) = &args.extract_transactions {
        genesis::display_transactions_from_blob(blob_path, args.tx_output.as_deref())?;
        return Ok(());
    }

    if let Some(blob_path) = &args.verify_transactions {
        let report = genesis::verify_transactions_against_genesis(blob_path, &args.genesis_file)?;
        println!("{}", report);
        return Ok(());
    }

    if let Some(genesis_path) = &args.verify_distribution {
        let report = genesis::verify_genesis_distribution_protocol(genesis_path)?;
        println!("{}", report);
        return Ok(());
    }

    if let Some(blob_path) = &args.extract_sections {
        let sections = genesis::extract_extended_blob_sections(blob_path)?;
        println!("=== Extended Blob Sections ===\n");
        for (section_type, data) in &sections {
            let section_name = match *section_type {
                SECTION_SCHEMA => "SCHEMA",
                SECTION_GENESIS_DOCUMENT => "GENESIS_DOCUMENT",
                SECTION_INITIAL_TX_STATE => "INITIAL_TX_STATE",
                SECTION_SIGNATURE_SET => "SIGNATURE_SET",
                _ => "UNKNOWN",
            };
            println!("Section 0x{:04x} ({})", section_type, section_name);
            println!("  Size: {} bytes", data.len());

            // Try to parse as JSON for display
            if let Ok(json_value) = serde_json::from_slice::<Value>(data) {
                if section_type == &SECTION_INITIAL_TX_STATE {
                    if let Some(tx_array) = json_value.as_array() {
                        println!("  Transactions: {}", tx_array.len());
                    }
                } else if section_type == &SECTION_SIGNATURE_SET {
                    if let Some(signers_array) =
                        json_value.pointer("/signers").and_then(|v| v.as_array())
                    {
                        println!("  Signers: {}", signers_array.len());
                    }
                } else {
                    println!("  Type: JSON");
                }
            } else {
                println!("  Type: Binary");
            }
            println!();
        }
        return Ok(());
    }

    bail!(
        "No action specified. Use --report, --create-blob, --verify-blob, --import-old, --extract-transactions, --verify-transactions, --verify-distribution, or --extract-sections."
    )
}
