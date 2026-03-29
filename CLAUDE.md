# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`scry` is a single-binary Rust CLI for CTF competitions and penetration testing. It orchestrates external security tools across three sequential phases of recon, streams findings in real time via a broadcast event bus, and generates a self-contained HTML report. Rust owns orchestration, parsing, the event bus, terminal output, JS secret scanning, and report generation — it does not reimplement what external tools already do well.

## Commands

```bash
cargo build                     # debug build
cargo build --release           # release build
cargo run -- --target example.com --port 443
cargo test                      # run all tests
cargo test <test_name>          # run a single test
cargo clippy                    # lint
```

## Architecture

### Execution phases

Three sequential phases; within each phase, modules run concurrently via `tokio::task::JoinSet`. Every module is wrapped in `tokio::time::timeout`.

- **Phase 1 — Passive recon**: ffuf (subdomains + vhosts), httpx (HTTP probe + header analysis + first-pass tech detection)
- **Phase 2 — Active discovery**: katana (crawl + robots/sitemap via `-known-files all`), feroxbuster (dirbust with augmented wordlist)
- **Phase 3 — Deep analysis**: JS secret scanner (pure Rust + reqwest), whatweb (tech fingerprinting), eyewitness (screenshots)
- **Report generation**: after all phases complete (or Ctrl+C), Tera renders a self-contained HTML file

### Event bus

`tokio::sync::broadcast` carries `FindingEvent` variants. Two subscribers:
1. **Printer task** — colored terminal output (`colored` crate): green=assets, red=secrets, yellow=alerts, cyan=tech, gray=status
2. **Store task** — appends to `FindingStore` for report generation

### Key design decisions

- **httpx replaces both HTTP probing and header analysis** — single NDJSON streaming pass handles live host filtering, titles, headers, and first-pass tech detection. Header analysis runs inline in the httpx parser; no second HTTP request.
- **Katana replaces a robots/sitemap module** — `-known-files all` handles this automatically.
- **ffuf uses plaintext + regex**, not JSON — ffuf's JSON mode writes a summary file at exit, not a stream. Use `-s` for clean real-time output.
- **httpx, feroxbuster, katana** use NDJSON streaming (parse line by line as child process runs). **WhatWeb and EyeWitness** are batch (wait for process exit, then ingest).
- **reqwest is used only in the JS scanner** to fetch `.js` file content — not for probing or header inspection.
- **Screenshots are base64-embedded** in the HTML report for a single self-contained file.
- **Wordlist augmentation**: katana phase 2 discoveries are path-segmented, merged with the bundled wordlist into a `tempfile::NamedTempFile`, then passed to feroxbuster. Tempfile auto-deletes on drop.

### Subprocess pattern (httpx, feroxbuster, katana)

```rust
let mut child = Command::new("toolname").args([...]).stdout(Stdio::piped()).stderr(Stdio::null()).spawn()?;
let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
while let Some(line) = lines.next_line().await? {
    if let Some(event) = parse_line(&line) { tx.send(event).ok(); }
}
child.wait().await?;
```

### Module timeout pattern

```rust
tx.send(FindingEvent::ModuleStart { name: name.into() }).ok();
match tokio::time::timeout(Duration::from_secs(config.module_timeout), run_module(...)).await {
    Ok(Ok(_))  => {},
    Ok(Err(e)) => eprintln!("[{}] error: {}", name, e),
    Err(_)     => tx.send(FindingEvent::Timeout { module: name.into() }).ok(),
}
tx.send(FindingEvent::ModuleEnd { name: name.into() }).ok();
```

## External tool dependencies

All must be in PATH at startup; the tool checks and exits with a clear error listing missing tools.

| Tool | Purpose | Output mode |
|---|---|---|
| `httpx` | HTTP probe + header analysis + tech detection | NDJSON stream |
| `feroxbuster` | Directory/endpoint bruteforce | NDJSON stream |
| `katana` | Web crawler (incl. robots/sitemap) | NDJSON stream |
| `ffuf` | Subdomain + vhost fuzzing | Plaintext stream (`-s`) |
| `whatweb` | Deep tech fingerprinting | JSON batch (wait for exit) |
| `eyewitness` | Screenshots | File-based (wait for exit) |

## Source layout

```
src/
├── main.rs                  # CLI parsing, dep check, runtime bootstrap, Ctrl+C handler
├── config.rs                # Config struct built from CLI args
├── orchestrator.rs          # Phase scheduler, JoinSet management
├── events.rs                # FindingEvent enum, broadcast channel setup
├── printer.rs               # Colored terminal output subscriber
├── store.rs                 # FindingStore, SharedStore, store subscriber task
├── wordlist.rs              # Augmented wordlist builder
├── modules/
│   ├── httpx.rs             # Streaming NDJSON probe + inline header analysis
│   ├── ffuf_subdomains.rs
│   ├── ffuf_vhosts.rs
│   ├── feroxbuster.rs
│   ├── katana.rs
│   ├── js_scanner.rs        # Pure Rust; patterns from SecretFinder project
│   ├── whatweb.rs
│   └── eyewitness.rs
└── report/
    ├── mod.rs               # Tera render logic, base64 screenshot embedding
    └── template.html        # Embedded at compile time via include_str!
wordlists/common.txt         # Bundled default wordlist
```

## JS secret scanner patterns

Patterns are sourced from the [SecretFinder](https://github.com/m4ll0k/SecretFinder) project. Port from `regex.py` — Python and Rust regex are mostly compatible; named groups change from `(?P<name>...)` to `(?<name>...)`. Compile all patterns once at startup into a `Vec<(String, Regex)>`; use `RegexSet` for fast multi-pattern matching.

## Ctrl+C handling

Register `tokio::signal::ctrl_c()` in main. On signal, set a shared `AtomicBool` cancellation flag. After signal, drain the store and generate a partial report.
