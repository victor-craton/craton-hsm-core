// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
#![deny(unsafe_code)]
// CK_ULONG is u32 on Windows and u64 elsewhere; `u64::from` is needed for portability.
#![allow(clippy::useless_conversion)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

mod admin_core;
mod commands;
mod config;
mod error;
mod fsutil;
mod output;
mod prompt;
mod sys;

use clap::{Parser, Subcommand};
use commands::audit::ExportFormat;
use commands::Ctx;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "craton-hsm-admin",
    version,
    about = "Craton HSM Admin CLI",
    after_help = error::EXIT_CODE_HELP
)]
struct Cli {
    /// Path to the craton_hsm.toml config file. Must exist, be owned by the
    /// invoking user or root and not be group/world-writable. Relative paths
    /// inside it are resolved against its directory.
    #[arg(long, global = true, default_value = config::DEFAULT_CONFIG_PATH)]
    config: PathBuf,

    /// Output in JSON format (where supported)
    #[arg(long, global = true, default_value_t = false)]
    json: bool,

    /// Skip typed confirmation prompts (authentication is still required)
    #[arg(long, global = true, default_value_t = false)]
    yes: bool,

    /// Read PINs and passphrases from standard input, one per line, instead
    /// of the terminal (automation; secrets are never accepted from argv or
    /// the environment). Typed confirmations then also come from stdin
    /// unless --yes is given.
    #[arg(long, global = true, default_value_t = false)]
    secrets_from_stdin: bool,

    /// Increase diagnostic verbosity on stderr (-v info, -vv debug).
    /// RUST_LOG=<level> is also honoured. Default: warn.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Token management
    Token {
        #[command(subcommand)]
        action: TokenAction,
    },
    /// Key management
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
    /// PIN management
    Pin {
        #[command(subcommand)]
        action: PinAction,
    },
    /// Audit log inspection (reads and verifies the persisted log)
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },
    /// Show HSM status
    Status,
    /// Create an encrypted backup of all token objects (SO login required)
    Backup {
        /// Output backup file path
        #[arg(long)]
        output: PathBuf,
        /// Allow writing a backup that contains no objects
        #[arg(long, default_value_t = false)]
        allow_empty: bool,
        /// Replace an existing output file
        #[arg(long, default_value_t = false)]
        force: bool,
        /// Also export keys with CKA_EXTRACTABLE=FALSE (disaster recovery;
        /// bypasses the object export policy — requires the typed
        /// confirmation and is recorded in the audit log)
        #[arg(long, default_value_t = false)]
        include_non_extractable: bool,
    },
    /// Restore token objects from an encrypted backup (SO login required)
    Restore {
        /// Input backup file path
        #[arg(long)]
        input: PathBuf,
        /// Only decrypt and validate the backup; do not restore or consume it
        #[arg(long, default_value_t = false)]
        verify_only: bool,
    },
}

#[derive(Subcommand)]
enum TokenAction {
    /// Initialize the token (destroys all objects; SO PIN required if already initialized)
    Init {
        /// Token label (1-32 printable ASCII characters)
        #[arg(long)]
        label: String,
    },
    /// Display token information
    Info,
}

#[derive(Subcommand)]
enum KeyAction {
    /// List keys visible to the authenticated role
    List {
        /// Role to authenticate as
        #[arg(long, value_enum, default_value_t = admin_core::Role::User)]
        role: admin_core::Role,
    },
    /// Import a raw AES key (16, 24 or 32 bytes) as a sensitive token object (User login)
    Import {
        /// Path to the raw key file
        #[arg(long)]
        file: PathBuf,
        /// Key label (1-32 printable ASCII characters)
        #[arg(long)]
        label: String,
        /// Key type
        #[arg(long = "type", value_enum)]
        key_type: commands::key::ImportKeyType,
    },
    /// Delete a key (typed confirmation required)
    Delete {
        /// Key handle
        #[arg(long)]
        handle: u64,
        /// Role to authenticate as (private objects require USER)
        #[arg(long, value_enum)]
        role: admin_core::Role,
    },
}

#[derive(Subcommand)]
enum PinAction {
    /// Change the User or SO PIN
    Change {
        /// Role whose PIN is changed
        #[arg(long = "user-type", value_enum, default_value_t = admin_core::Role::User)]
        role: admin_core::Role,
    },
    /// Reset the User PIN (requires SO authentication)
    Reset,
}

#[derive(Subcommand)]
enum AuditAction {
    /// Show the most recent audit entries (SO login required)
    Dump {
        /// Number of recent entries to show
        #[arg(long, default_value_t = 50)]
        last: usize,
    },
    /// Export the audit log as a JSON array (SO login required)
    ExportJson,
    /// Export the audit log as NDJSON for SIEM ingestion (SO login required)
    ExportNdjson,
    /// Export the audit log in syslog RFC 5424 format (SO login required)
    ExportSyslog,
    /// Verify the hash chain of the persisted audit log and its rotated generations
    VerifyChain,
}

/// Install a stderr tracing subscriber so that the core library's security
/// warnings (tamper detection, lockout corruption, replay rejection, config
/// errors) are visible (H5-09).
fn init_tracing(verbose: u8) {
    use tracing_subscriber::filter::LevelFilter;
    let from_env = std::env::var("RUST_LOG")
        .ok()
        .and_then(|v| v.trim().parse::<LevelFilter>().ok());
    let level = match verbose {
        0 => from_env.unwrap_or(LevelFilter::WARN),
        1 => LevelFilter::INFO,
        _ => LevelFilter::DEBUG,
    };
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(level)
        .with_target(false)
        .try_init();
}

fn run(cli: Cli) -> error::CliResult {
    prompt::set_secrets_from_stdin(cli.secrets_from_stdin);
    let ctx = Ctx {
        config_path: cli.config,
        json: cli.json,
        yes: cli.yes,
    };
    match cli.command {
        Commands::Token { action } => match action {
            TokenAction::Init { label } => commands::token::init(&ctx, &label),
            TokenAction::Info => commands::token::info(&ctx),
        },
        Commands::Key { action } => match action {
            KeyAction::List { role } => commands::key::list(&ctx, role),
            KeyAction::Import {
                file,
                label,
                key_type,
            } => commands::key::import(&ctx, &file, &label, key_type),
            KeyAction::Delete { handle, role } => commands::key::delete(&ctx, handle, role),
        },
        Commands::Pin { action } => match action {
            PinAction::Change { role } => commands::pin::change(&ctx, role),
            PinAction::Reset => commands::pin::reset(&ctx),
        },
        Commands::Audit { action } => match action {
            AuditAction::Dump { last } => commands::audit::dump(&ctx, last),
            AuditAction::ExportJson => commands::audit::export(&ctx, ExportFormat::Json),
            AuditAction::ExportNdjson => commands::audit::export(&ctx, ExportFormat::Ndjson),
            AuditAction::ExportSyslog => commands::audit::export(&ctx, ExportFormat::Syslog),
            AuditAction::VerifyChain => commands::audit::verify_chain(&ctx),
        },
        Commands::Status => commands::token::status(&ctx),
        Commands::Backup {
            output,
            allow_empty,
            force,
            include_non_extractable,
        } => commands::backup::create_backup(
            &ctx,
            &output,
            commands::backup::BackupOptions {
                allow_empty,
                force,
                include_non_extractable,
            },
        ),
        Commands::Restore { input, verify_only } => {
            commands::backup::restore_backup(&ctx, &input, verify_only)
        }
    }
}

fn main() {
    let cli = Cli::parse();
    init_tracing(cli.verbose);
    sys::harden_process();

    if let Err(e) = run(cli) {
        eprintln!("Error: {}", output::escape_display(&e.to_string()));
        std::process::exit(e.exit_code());
    }
}
