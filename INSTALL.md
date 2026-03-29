# scry — Installation & Compilation

## Requirements

### Rust toolchain

Rust 1.70 or later is required. The recommended way to install and manage Rust is via [rustup](https://rustup.rs):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

Verify:

```bash
rustc --version   # should print 1.70.0 or later
cargo --version
```

### External tool dependencies

All six tools must be present in `PATH` before running `scry`. The binary checks for them at startup and exits with a list of anything missing. The exact command names that must be resolvable in `PATH` are shown in the table below.

| Command in PATH | Purpose | Install |
|---|---|---|
| `httpx` | HTTP probing, header analysis, tech detection | [projectdiscovery/httpx](https://github.com/projectdiscovery/httpx) |
| `feroxbuster` | Directory and endpoint bruteforce | [epi052/feroxbuster](https://github.com/epi052/feroxbuster) |
| `katana` | Web crawler | [projectdiscovery/katana](https://github.com/projectdiscovery/katana) |
| `ffuf` | Subdomain and vhost fuzzing | [ffuf/ffuf](https://github.com/ffuf/ffuf) |
| `whatweb` | Tech stack fingerprinting | [urbanadventurer/WhatWeb](https://github.com/urbanadventurer/WhatWeb) |
| `EyeWitness.py` | Screenshots | [RedSiege/EyeWitness](https://github.com/RedSiege/EyeWitness) |

> **Note:** EyeWitness is invoked as `EyeWitness.py`. After installation, ensure the script is executable and symlinked or copied into a directory on your `PATH` under that exact name.

**Quick install on Kali / Debian / Ubuntu:**

```bash
# Go-based tools (httpx, katana, ffuf)
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/ffuf/ffuf/v2@latest

# feroxbuster
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash

# WhatWeb
sudo apt install whatweb

# EyeWitness — clone and symlink EyeWitness.py onto PATH
git clone https://github.com/RedSiege/EyeWitness.git /opt/EyeWitness
cd /opt/EyeWitness/Python && pip install -r requirements.txt
sudo ln -sf /opt/EyeWitness/Python/EyeWitness.py /usr/local/bin/EyeWitness.py
sudo chmod +x /opt/EyeWitness/Python/EyeWitness.py
```

**On Arch Linux:**

```bash
# AUR helpers (yay / paru)
yay -S httpx-bin katana-bin ffuf feroxbuster-bin whatweb

# EyeWitness — same manual steps as above
git clone https://github.com/RedSiege/EyeWitness.git /opt/EyeWitness
cd /opt/EyeWitness/Python && pip install -r requirements.txt
sudo ln -sf /opt/EyeWitness/Python/EyeWitness.py /usr/local/bin/EyeWitness.py
sudo chmod +x /opt/EyeWitness/Python/EyeWitness.py
```

Make sure all tool directories are in your `PATH`. For Go tools (`$GOPATH/bin`, typically `~/go/bin`):

```bash
echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc
source ~/.bashrc
```

Verify everything is reachable before running `scry`:

```bash
which httpx feroxbuster katana ffuf whatweb EyeWitness.py
```

---

## SecLists (optional but strongly recommended)

`scry` automatically detects and uses [SecLists](https://github.com/danielmiessler/SecLists) when it is installed at the default path `/usr/share/wordlists/seclists/`. If found, it replaces the small bundled wordlist with purpose-built lists that significantly improve discovery quality.

**Wordlists used when SecLists is present:**

| Purpose | SecLists file |
|---|---|
| Subdomain + vhost fuzzing (ffuf) | `Discovery/DNS/subdomains-top1million-20000.txt` |
| Dirbusting base (feroxbuster) | `Discovery/Web-Content/combined_directories.txt` |
| API endpoint discovery | `Discovery/Web-Content/common-api-endpoints-mazen160.txt` |
| GraphQL endpoint discovery | `Discovery/Web-Content/graphql.txt` |
| Swagger / OpenAPI paths | `Discovery/Web-Content/swagger.txt` |
| Reverse proxy path confusion | `Discovery/Web-Content/reverse-proxy-inconsistencies.txt` |
| WordPress (auto-added when detected) | `Discovery/Web-Content/CMS/CMS-Wordpress.txt` |
| Joomla (auto-added when detected) | `Discovery/Web-Content/CMS/CMS-Joomla.txt` |
| Drupal (auto-added when detected) | `Discovery/Web-Content/CMS/CMS-Drupal.txt` |

If SecLists is not found, `scry` falls back to its bundled `wordlists/common.txt` and prints a notice at startup:

```
[!] SecLists not found at /usr/share/wordlists/seclists/ — falling back to bundled common.txt
    Install with: sudo apt install seclists
```

**Install SecLists:**

```bash
# Debian / Ubuntu / Kali
sudo apt install seclists

# Arch Linux (AUR)
yay -S seclists

# Manual
git clone https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/seclists
```

---

## Compilation

### Standard build (debug)

```bash
git clone <repo-url>
cd scry
cargo build
```

Binary at `target/debug/scry`.

### Release build (optimised, recommended)

```bash
cargo build --release
```

Binary at `target/release/scry`. Optionally copy it to a directory in your PATH:

```bash
sudo cp target/release/scry /usr/local/bin/
```

### Portable static binary (musl — runs on any x86_64 Linux)

A musl build produces a fully self-contained binary with no dynamic library dependencies. This is the best option for dropping onto CTF boxes or systems where glibc version mismatches are a concern.

```bash
# Add the musl target (one-time)
rustup target add x86_64-unknown-linux-musl

# Install musl-gcc if not present
sudo apt install musl-tools          # Debian/Ubuntu/Kali
sudo pacman -S musl                  # Arch

# Build
cargo build --release --target x86_64-unknown-linux-musl
```

Binary at `target/x86_64-unknown-linux-musl/release/scry`.

### ARM64 / aarch64 (e.g. Raspberry Pi, Apple Silicon VM, AWS Graviton)

```bash
rustup target add aarch64-unknown-linux-gnu

# Cross-compiler (Debian/Ubuntu)
sudo apt install gcc-aarch64-linux-gnu

# Tell Cargo to use the cross-linker
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc

cargo build --release --target aarch64-unknown-linux-gnu
```

### Cross-compilation from any platform (using `cross`)

[cross](https://github.com/cross-rs/cross) wraps Docker to handle toolchain setup automatically and supports a wide range of targets:

```bash
cargo install cross
cross build --release --target x86_64-unknown-linux-musl
cross build --release --target aarch64-unknown-linux-gnu
```

### Reducing binary size

Add the following to `Cargo.toml` to strip debug symbols and enable size optimisations in release builds:

```toml
[profile.release]
strip = true
opt-level = 3
lto = true
codegen-units = 1
```

Or strip manually after building:

```bash
strip target/release/scry
```

---

## Quick start

```bash
# Basic scan
scry --target example.com --port 443

# Skip slow modules
scry --target example.com --skip eyewitness,whatweb

# Use a custom wordlist (overrides SecLists)
scry --target example.com --wordlist /path/to/wordlist.txt

# Terminal output only, no report
scry --target example.com --no-report
```

Run `scry --help` for the full list of options.
