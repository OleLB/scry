# scry

A very light weight web scanner written in rust. This is NOT a vulnerability scanner, but rather a tool to quickly map out the structure and content of a website. The tool will show any discoveries as they are made and will also summarize all findings in an html report with screenshots of each discovered uniqe URL. The tool is made for CTF challenges.
The tool will search for:
    subdomains
    vhosts
    endpoints
    technology fingerprints
    passwords, api keys and other sensitive info left in .js files



## Features

- Three-phase recon pipeline with concurrent module execution per phase
- Real-time finding stream via broadcast event bus — results print as tools run
- Graceful Ctrl+C handling: first press skips feroxbuster and continues; second cancels and writes a partial report
- Self-contained HTML report with base64-embedded screenshots
- SecLists integration with automatic fallback to bundled wordlist
- Configurable tool paths for non-standard installations

## Dependencies

All tools must be in `PATH` (or mapped in `~/.config/scry/scry.conf`). scry will exit with a clear error listing any missing tools.

| Tool | Purpose |
|---|---|
| `httpx` | HTTP probe, header analysis, tech detection |
| `ffuf` | Subdomain and vhost fuzzing |
| `katana` | Web crawler (includes robots/sitemap via `-known-files all`) |
| `feroxbuster` | Directory/endpoint bruteforce |
| `whatweb` | Deep tech fingerprinting |
| `EyeWitness.py` | Screenshots |

## Installation

```bash
git clone <repo>
cd scry
cargo build --release
# Binary at target/release/scry
```

## Usage

```bash
# HTTPS on port 443 (default)
scry --target example.com

# Custom port (HTTP auto-detected for ports 80, 8080)
scry --target example.com --port 8080

# Force a protocol
scry --target example.com --port 8443 --protocol https

# Skip slow modules
scry --target example.com --skip eyewitness,whatweb

# Custom wordlist, custom output path
scry --target example.com --wordlist /path/to/words.txt --output report.html

# Terminal output only, no report
scry --target example.com --no-report

# Show raw tool output alongside parsed events
scry --target example.com --verbose
```

### All options

| Flag | Default | Description |
|---|---|---|
| `-t, --target` | *(required)* | Target domain |
| `-p, --port` | `443` | Target port |
| `--protocol` | auto | Force `http` or `https` |
| `-w, --wordlist` | bundled `common.txt` | Custom wordlist path |
| `-o, --output` | `recon_<target>_<timestamp>.html` | Report output path |
| `--module-timeout` | `300` | Per-module timeout in seconds |
| `--threads` | `50` | Concurrency hint passed to external tools |
| `--screenshot-dir` | `/tmp/scry-shots` | Directory for EyeWitness screenshots |
| `--skip` | | Comma-separated modules to skip |
| `--no-report` | | Skip report generation |
| `-v, --verbose` | | Show raw tool output |

## Configuration

Tool paths and SecLists location can be set in `~/.config/scry/scry.conf`:

```ini
# Custom paths for tools not in PATH
EyeWitness.py=/opt/tools/EyeWitness/EyeWitness.py
whatweb=ruby /opt/tools/WhatWeb/whatweb

# SecLists base directory (default: /usr/share/wordlists/seclists)
seclists=/opt/seclists
```

Lines may use optional single or double quotes around values. Lines starting with `#` are ignored.

## Execution phases

Modules within each phase run concurrently. Each module is wrapped in a configurable timeout.

**Phase 1 — Passive recon**
- `ffuf` — subdomain enumeration and vhost fuzzing
- `httpx` — HTTP probe, header analysis, first-pass tech detection

**Phase 2 — Active discovery**
- `katana` — web crawl, robots.txt, sitemap discovery
- `feroxbuster` — directory bruteforce with wordlist augmented by katana discoveries

**Phase 3 — Deep analysis**
- JS secret scanner — pure Rust, fetches and scans `.js` files for secrets (patterns from [SecretFinder](https://github.com/m4ll0k/SecretFinder))
- `whatweb` — deep tech fingerprinting
- `EyeWitness` — screenshots

## Terminal output colors

| Color | Meaning |
|---|---|
| Green | Assets (hosts, URLs, endpoints) |
| Red | Secrets |
| Yellow | Alerts and warnings |
| Cyan | Tech detections |
| Gray | Status messages |

## Building

```bash
cargo build           # debug
cargo build --release # release
cargo test            # run tests
cargo clippy          # lint
```
