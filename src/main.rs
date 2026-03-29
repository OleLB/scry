mod config;
mod events;
mod modules;
mod orchestrator;
mod printer;
mod report;
mod store;
mod tool_paths;
mod wordlist;

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use clap::Parser;
use colored::Colorize;

use config::Config;
use events::make_channel;
use store::{FindingStore, SharedStore};

const REQUIRED_TOOLS: &[&str] = &[
    "httpx",
    "feroxbuster",
    "katana",
    "ffuf",
    "whatweb",
    "EyeWitness.py",
];

fn check_dependencies(tool_paths: &tool_paths::ToolPaths) -> bool {
    let missing: Vec<&str> = REQUIRED_TOOLS
        .iter()
        .filter(|&&t| which::which(tool_paths::effective_program(t, tool_paths)).is_err())
        .copied()
        .collect();

    if missing.is_empty() {
        return true;
    }

    eprintln!("{}", "Missing required tools:".red().bold());
    for tool in &missing {
        let program = tool_paths::effective_program(tool, tool_paths);
        if program == *tool {
            eprintln!("  {} {}", "✗".red(), tool);
        } else {
            eprintln!("  {} {} (configured as: {})", "✗".red(), tool, program);
        }
    }
    eprintln!(
        "\nEnsure missing tools are installed and in PATH, or map them in \
        ~/.config/scry/scry.conf:\n\
        \n    EyeWitness.py='/path/to/EyeWitness.py'\
        \n    whatweb='ruby /opt/tools/WhatWeb/whatweb'\
        \n    httpx=/usr/local/bin/httpx\n"
    );
    false
}

#[tokio::main]
async fn main() {
    let mut config = Config::parse();
    config.tool_paths = tool_paths::load();
    config.seclists_base = config.tool_paths
        .get("seclists")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/usr/share/wordlists/seclists"));
    let config = Arc::new(config);

    if !check_dependencies(&config.tool_paths) {
        std::process::exit(1);
    }

    if wordlist::seclists_available(&config.seclists_base) {
        eprintln!("{}", format!("[+] SecLists found at {} — using high-quality wordlists", config.seclists_base.display()).green());
    } else {
        eprintln!("{}", format!("[!] SecLists not found at {} — falling back to bundled common.txt", config.seclists_base.display()).yellow());
        eprintln!("    Set a custom path in ~/.config/scry/scry.conf: seclists=/path/to/seclists");
    }

    let cancel = Arc::new(AtomicBool::new(false));
    let skip_ferox = Arc::new(AtomicBool::new(false));

    let skip_signal = skip_ferox.clone();
    let cancel_signal = cancel.clone();
    // Spawn Ctrl+C handler: first press skips feroxbuster, second cancels everything.
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        eprintln!("\n{}", "[!] Ctrl+C — stopping feroxbuster and continuing scan. Press again to cancel.".yellow());
        skip_signal.store(true, Ordering::Relaxed);

        tokio::signal::ctrl_c().await.ok();
        eprintln!("\n{}", "[!] Cancelling scan — generating partial report...".yellow());
        cancel_signal.store(true, Ordering::Relaxed);
    });

    let store: SharedStore = Arc::new(tokio::sync::Mutex::new(FindingStore::default()));
    let (tx, rx_printer) = make_channel();
    let rx_store = tx.subscribe();

    // Launch printer and store subscribers
    let printer_handle = tokio::spawn(printer::run_printer(rx_printer));
    let store_handle = tokio::spawn(store::run_store(rx_store, store.clone()));

    // Run all phases
    orchestrator::run(config.clone(), store.clone(), tx.clone(), cancel.clone(), skip_ferox.clone()).await;

    // Signal subscribers to stop by dropping tx
    drop(tx);

    // Wait for subscribers to drain
    let _ = printer_handle.await;
    let _ = store_handle.await;

    // Generate report unless skipped
    if !config.no_report {
        let locked = store.lock().await;
        match report::generate(&locked, &config) {
            Ok(path) => eprintln!("{} {}", "Report written:".green().bold(), path.display()),
            Err(e) => eprintln!("{} {}", "Report error:".red(), e),
        }
    }
}
