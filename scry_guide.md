# ctf-recon — Project Description & Implementation Guide

## What this is

`ctf-recon` is a single-binary Rust CLI tool for CTF competitions and penetration testing. It performs automated, multi-phase reconnaissance against a target domain+port combination. The operator gives it a domain and port and it runs completely autonomously — discovering subdomains, virtual hosts, endpoints, secrets, technologies, and taking screenshots — then produces a self-contained HTML report. The operator sees all discoveries in real time as colored terminal output. The tool never hangs: every external process is wrapped in a timeout watchdog, and if something stalls the tool emits a timeout event and moves on.

The tool is a **coordinator of external tools**, not a reimplementation of them. Heavy lifting (dirbusting, crawling, subdomain/vhost scanning, HTTP probing, header analysis, screenshots, tech fingerprinting) is delegated to best-in-class external binaries. Rust owns the orchestration, event bus, real-time terminal output, JS secret scanning, and report generation.

---

## External tool dependencies

These must be present in PATH at startup. The tool checks for all of them at launch and exits with a clear error listing which are missing.

| Tool | Purpose | Key flags |
|---|---|---|
| `httpx` | HTTP probing, header analysis, basic tech detection | `-json -silent -title -tech-detect -headers -follow-redirects` |
| `feroxbuster` | Endpoint/directory bruteforce | `--json --silent --no-state` |
| `katana` | Web crawler | `-json -silent -js-crawl -known-files all` |
| `ffuf` | Subdomain + vHost fuzzing | `-s` (silent, plaintext output) |
| `whatweb` | Deep tech stack fingerprinting | `--log-json=- --no-errors --quiet` |
| `eyewitness` | Screenshots | `--web --no-prompt` |

Dependency check uses the `which` crate. Chromium/Chrome is NOT a direct dependency — EyeWitness handles its own browser.

---

## Architecture

### Execution phases

The orchestrator runs three sequential phases. Within each phase, modules run concurrently via `tokio::task::JoinSet`. Every module call is wrapped in `tokio::time::timeout`.

**Phase 1 — Passive recon** (runs first, feeds data into later phases)
- DNS + subdomain scan (ffuf)
- vHost scan (ffuf)
- HTTP probe + header analysis — filters discovered hosts down to live ones, captures titles, headers, and basic tech (httpx)

**Phase 2 — Active discovery** (operates on live hosts from phase 1)
- Web crawl (katana) — also handles robots.txt and sitemap.xml automatically via `-known-files all`
- Endpoint bruteforce (feroxbuster) — wordlist is the bundled default; robots/sitemap seeds come from katana discoveries

**Phase 3 — Deep analysis** (operates on URLs discovered in phase 2)
- JS secret scanning (pure Rust, regex against fetched .js files)
- Tech fingerprinting — deep pass (whatweb)
- Screenshots (eyewitness)

**Report generation** — after all phases complete (or Ctrl+C), the findings store is passed to the Tera template renderer and a self-contained HTML file is written.

### Event bus

A `tokio::sync::broadcast` channel carries `FindingEvent` variants throughout the entire run. Every module sends events to this channel. Two subscribers consume it:

1. **Printer task** — formats and prints each event to the terminal in real time with colors (`colored` crate)
2. **Store task** — appends each event's payload to the `FindingStore` for later report generation

`FindingEvent` variants:
```rust
pub enum FindingEvent {
    ModuleStart { name: String },
    ModuleEnd   { name: String },
    Timeout     { module: String },
    NewSubdomain { host: String, status: u16 },
    NewVhost     { host: String, status: u16, size: u64 },
    NewEndpoint  { url: String, status: u16, size: u64, words: u64 },
    NewUrl       { url: String, source: String },
    SecretFound  { url: String, pattern: String, snippet: String },
    TechDetected { host: String, tech: String, version: Option<String> },
    HeaderAlert  { host: String, severity: Severity, message: String },
    Screenshot   { host: String, path: PathBuf },
}
```

Terminal color scheme:
- Green → new assets (subdomains, vhosts, endpoints, URLs)
- Red → secrets found
- Yellow → header alerts / interesting findings
- Cyan → tech detections
- Gray → module start/end/timeout info messages

---

## Module implementation details

### Subprocess pattern (used by httpx, feroxbuster, katana, ffuf)

All streaming external tools use the same async pattern:

```rust
use tokio::process::Command;
use tokio::io::{BufReader, AsyncBufReadExt};
use std::process::Stdio;

let mut child = Command::new("toolname")
    .args([...])
    .stdout(Stdio::piped())
    .stderr(Stdio::null())
    .spawn()?;

let stdout = child.stdout.take().unwrap();
let mut lines = BufReader::new(stdout).lines();

while let Some(line) = lines.next_line().await? {
    // parse line, fire event immediately — does NOT wait for process to exit
    if let Some(event) = parse_line(&line) {
        tx.send(event).ok();
    }
}
child.wait().await?;
```

This is a live stream — events fire the instant the child process writes a newline. There is no buffering or waiting for the process to finish.

### httpx

httpx handles two jobs in one pass: HTTP probing (determining which hosts are live) and header analysis (inspecting security headers, leakage headers, CORS misconfigs). It outputs NDJSON and streams line by line, so it follows the standard subprocess pattern.

Invocation (takes a file of hosts — base domain + all ffuf subdomain discoveries):
```bash
httpx \
  -list <hosts_file> \
  -json \
  -silent \
  -title \
  -status-code \
  -content-length \
  -tech-detect \
  -headers \
  -follow-redirects \
  -threads 50 \
  -timeout 10
```

Output: NDJSON, one object per line:
```rust
#[derive(Deserialize)]
pub struct HttpxResult {
    pub url:            String,
    #[serde(rename = "status-code")]
    pub status:         u16,
    pub title:          Option<String>,
    #[serde(rename = "content-length")]
    pub content_length: Option<u64>,
    pub tech:           Option<Vec<String>>,
    pub headers:        Option<HashMap<String, String>>,
    #[serde(rename = "final-url")]
    pub final_url:      Option<String>,
}
```

Each result does two things:

1. **Populates the live hosts list** — emit `FindingEvent::LiveHost` and add to `FindingStore.live_hosts`. The live host list is shared via `Arc` with all phase 2 and phase 3 modules.

2. **Drives header analysis inline** — the `analyse_headers()` function is called on each result as it streams in, emitting `FindingEvent::HeaderAlert` without any additional HTTP requests.

```rust
fn analyse_headers(result: &HttpxResult, tx: &Sender<FindingEvent>) {
    let headers = match &result.headers { Some(h) => h, None => return };

    // Missing security headers
    let required = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
    ];
    for header in required {
        if !headers.contains_key(header) {
            tx.send(FindingEvent::HeaderAlert {
                host:     result.url.clone(),
                severity: Severity::Medium,
                message:  format!("Missing: {}", header),
            }).ok();
        }
    }

    // Tech leakage headers
    for header in ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"] {
        if let Some(val) = headers.get(header) {
            tx.send(FindingEvent::HeaderAlert {
                host:     result.url.clone(),
                severity: Severity::Info,
                message:  format!("{}: {}", header, val),
            }).ok();
        }
    }

    // Misconfigurations
    if headers.get("access-control-allow-origin").map(|v| v == "*").unwrap_or(false) {
        tx.send(FindingEvent::HeaderAlert {
            host:     result.url.clone(),
            severity: Severity::High,
            message:  "Open CORS: Access-Control-Allow-Origin: *".into(),
        }).ok();
    }
}
```

The `-tech-detect` flag gives a fast first-pass tech list per host. These are emitted as `FindingEvent::TechDetected`. WhatWeb runs afterward in phase 3 for a deeper pass on the same hosts.

The `LiveHost` struct is populated from `HttpxResult`:
```rust
pub struct LiveHost {
    pub original_host:  String,
    pub final_url:      String,
    pub status:         u16,
    pub title:          Option<String>,
    pub server:         Option<String>,
    pub content_length: Option<u64>,
}
```

### feroxbuster

Invocation:
```bash
feroxbuster \
  --url <target> \
  --wordlist <augmented_wordlist_path> \
  --json \
  --silent \
  --no-state \
  --timeout 10 \
  --threads 50 \
  --filter-status 404 \
  --extensions php,bak,json,xml,js,zip,env,txt,conf,config,yaml,yml,log,old,backup
```

Output: NDJSON, one object per line. Parse with:
```rust
#[derive(Deserialize)]
pub struct FeroxResult {
    #[serde(rename = "type")]
    pub kind:           String,   // "response" or "statistics" — only handle "response"
    pub url:            String,
    pub status:         u16,
    pub content_length: u64,
    pub words:          u64,
    pub lines:          u64,
}
```

Filter `kind == "response"` only. Emit `FindingEvent::NewEndpoint` per result.

### Katana

Invocation:
```bash
katana \
  -u <target> \
  -json \
  -silent \
  -depth 3 \
  -js-crawl \
  -known-files all \
  -timeout 10
```

`-known-files all` makes katana auto-fetch and parse robots.txt and sitemap.xml, adding those paths to its crawl queue. This replaces the need for a separate robots/sitemap module.

Output: NDJSON, one object per line:
```rust
#[derive(Deserialize)]
pub struct KatanaResult {
    pub request:  KatanaRequest,
    pub response: Option<KatanaResponse>,
}

#[derive(Deserialize)]
pub struct KatanaRequest {
    pub url:    String,
    pub method: String,
}

#[derive(Deserialize)]
pub struct KatanaResponse {
    pub status_code:  u16,
    pub content_type: Option<String>,
}
```

Emit `FindingEvent::NewUrl` per result. Collect `.js` URLs into a separate list and pass to the JS scanner in phase 3.

### ffuf (subdomain + vhost)

ffuf does NOT use JSON for real-time output. Use `-s` (silent) for clean plaintext and parse with regex.

**Subdomain invocation:**
```bash
ffuf \
  -w <wordlist> \
  -u https://FUZZ.<domain> \
  -mc 200,204,301,302,307,401,403 \
  -t 100 \
  -s
```

**vHost invocation:**
```bash
ffuf \
  -w <wordlist> \
  -u https://<domain> \
  -H "Host: FUZZ.<domain>" \
  -mc 200,204,301,302,307,401,403 \
  -fs <baseline_size> \
  -t 100 \
  -s
```

The baseline size for `-fs` is obtained by probing the target with a random nonexistent hostname before spawning ffuf. This eliminates wildcard false positives.

Output line format:
```
admin                   [Status: 200, Size: 4321, Words: 87, Lines: 112]
```

Parse regex:
```rust
let re = Regex::new(
    r"^(\S+)\s+\[Status: (\d+), Size: (\d+), Words: (\d+), Lines: (\d+)\]"
).unwrap();
```

Emit `FindingEvent::NewSubdomain` or `FindingEvent::NewVhost` per match.

### WhatWeb

Invocation (one per live host, or batch via `--input-file`):
```bash
whatweb --log-json=- --no-errors --quiet <url>
```

Output: a JSON array written all at once when the process exits (not streaming). Wait for process completion, then parse the full output.

```rust
#[derive(Deserialize)]
pub struct WhatWebResult {
    pub target:      String,
    pub http_status: u16,
    pub plugins:     HashMap<String, WhatWebPlugin>,
}

#[derive(Deserialize)]
pub struct WhatWebPlugin {
    pub version: Option<Vec<String>>,
    pub string:  Option<Vec<String>>,
}
```

Emit one `FindingEvent::TechDetected` per plugin per host.

### EyeWitness

EyeWitness is file-based, not stream-based. Write all live host URLs to a temp file, run EyeWitness, then collect the PNG files it created.

Invocation:
```bash
eyewitness \
  --web \
  --input-file <url_list_path> \
  --destination <output_dir> \
  --no-prompt \
  --timeout 10 \
  --threads 5
```

EyeWitness saves screenshots as `<output_dir>/screenshots/<sanitized_hostname>.png`. After the process exits, glob for `*.png` files in the destination directory and emit `FindingEvent::Screenshot` for each.

For the HTML report, screenshots are embedded as base64 data URIs so the report is fully self-contained:
```rust
let data = std::fs::read(&path)?;
let b64  = base64::encode(&data);
format!("data:image/png;base64,{}", b64)
```

---

## JS secret scanner

This module is pure Rust — no external tool. It operates on all `.js` URLs discovered by katana during phase 2.

For each URL:
1. Fetch the JS file content with reqwest (10s timeout)
2. Run all compiled regex patterns against the content
3. For each match, emit `FindingEvent::SecretFound` with a redacted snippet

**Regex patterns sourced from SecretFinder** (https://github.com/m4ll0k/SecretFinder). The full pattern set from that project should be used. Key categories:

```rust
// These are representative examples — use the complete SecretFinder pattern list
pub const PATTERNS: &[(&str, &str)] = &[
    ("google_api",        r"AIza[0-9A-Za-z\-_]{35}"),
    ("firebase",          r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"),
    ("google_oauth",      r"ya29\.[0-9A-Za-z\-_]+"),
    ("amazon_aws_key",    r"AKIA[0-9A-Z]{16}"),
    ("amazon_aws_url",    r"s3\.amazonaws\.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws\.com"),
    ("facebook_token",    r"EAACEdEose0cBA[0-9A-Za-z]+"),
    ("mailgun",           r"key-[0-9a-zA-Z]{32}"),
    ("twilio_api",        r"SK[0-9a-fA-F]{32}"),
    ("twilio_account",    r"AC[a-zA-Z0-9_\-]{32}"),
    ("paypal_braintree",  r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),
    ("square_oauth",      r"sq0atp-[0-9A-Za-z\-_]{22}"),
    ("square_secret",     r"sq0csp-[0-9A-Za-z\-_]{43}"),
    ("stripe_secret",     r#"(?:r|s)k_live_[0-9a-zA-Z]{24}"#),
    ("stripe_restricted", r"rk_live_[0-9a-zA-Z]{24}"),
    ("github_token",      r"[gG][iI][tT][hH][uU][bB].*['\"][0-9a-zA-Z]{35,40}['\"]"),
    ("rsa_private",       r"-----BEGIN RSA PRIVATE KEY-----"),
    ("ssh_private",       r"-----BEGIN OPENSSH PRIVATE KEY-----"),
    ("generic_private",   r"-----BEGIN PRIVATE KEY-----"),
    ("slack_token",       r"xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}"),
    ("slack_webhook",     r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}"),
    ("heroku_api",        r"[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"),
    ("jwt",               r"eyJ[A-Za-z0-9_/+\-]{10,}={0,2}\.[A-Za-z0-9_/+\-]{10,}={0,2}\.[A-Za-z0-9_/+\-]{10,}={0,2}"),
    ("bearer_token",      r"[Bb]earer\s+[A-Za-z0-9\-._~+/]{20,}"),
    ("generic_api_key",   r#"[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]\s*[:=]\s*['"][A-Za-z0-9]{16,}['""]"#),
    ("generic_secret",    r#"[Ss][Ee][Cc][Rr][Ee][Tt]\s*[:=]\s*['"][A-Za-z0-9]{16,}['""]"#),
    ("generic_password",  r#"[Pp]assword\s*[:=]\s*['"][^'"]{8,}['""]"#),
    ("mailto",            r"mailto:[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    ("ip_address",        r#"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"#),
    ("todo_comment",      r"(?i)(TODO|FIXME|HACK|BUG|XXX|CREDENTIALS?|CREDS?)\s*:?\s*.{5,80}"),
];
```

Compile all patterns once at startup into a `Vec<(String, Regex)>` — not per-file. Use `regex::RegexSet` for fast multi-pattern matching, then get the specific match details from individual `Regex` instances.

Snippet redaction — show context but don't expose full secrets in the terminal:
```rust
fn redact(matched: &str) -> String {
    if matched.len() <= 12 {
        return "*".repeat(matched.len());
    }
    let visible = &matched[..6];
    let tail    = &matched[matched.len()-4..];
    format!("{}...{}", visible, tail)
}
```

---

## HTTP header analysis

Pure Rust module using reqwest. For each live host, sends a HEAD (falling back to GET) request and inspects response headers.

Checks performed:

**Missing security headers (severity: Medium)**
- `Strict-Transport-Security` (HSTS)
- `Content-Security-Policy`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`

**Tech leakage headers (severity: Info/Low)**
- `Server` — emit value (e.g. `Apache/2.4.51`)
- `X-Powered-By` — emit value (e.g. `PHP/7.4.3`)
- `X-AspNet-Version`
- `X-AspNetMvc-Version`

**Misconfiguration headers (severity: High)**
- `Access-Control-Allow-Origin: *` — open CORS
- `Access-Control-Allow-Credentials: true` combined with wildcard origin
- `Set-Cookie` without `HttpOnly` flag
- `Set-Cookie` without `Secure` flag (on HTTPS targets)

Emit `FindingEvent::HeaderAlert` for each finding with appropriate severity.

---

## Augmented wordlist for feroxbuster

Katana's `-known-files all` fetches robots.txt and sitemap.xml and adds their paths to the crawl queue. The paths discovered by katana during phase 2 are collected in the findings store. Before feroxbuster runs, a temporary augmented wordlist is built:

```rust
pub async fn build_wordlist(
    base_path: &Path,
    discovered_paths: &[String],
) -> tempfile::NamedTempFile {
    let base = tokio::fs::read_to_string(base_path).await.unwrap_or_default();
    let mut words: HashSet<String> = base.lines().map(String::from).collect();

    for url in discovered_paths {
        if let Ok(parsed) = url::Url::parse(url) {
            let path = parsed.path().trim_start_matches('/');
            // add each path segment
            for segment in path.split('/') {
                if !segment.is_empty() {
                    words.insert(segment.to_string());
                }
            }
            // add the full path too
            if !path.is_empty() {
                words.insert(path.to_string());
            }
        }
    }

    let mut file = tempfile::NamedTempFile::new().unwrap();
    for word in &words {
        writeln!(file, "{}", word).ok();
    }
    file
}
```

The `NamedTempFile` is kept alive for the duration of the feroxbuster run and deleted automatically on drop.

---

## Timeout watchdog

Every module is wrapped the same way:

```rust
let module_name = "feroxbuster";
tx.send(FindingEvent::ModuleStart { name: module_name.into() }).ok();

match tokio::time::timeout(
    Duration::from_secs(config.module_timeout),
    run_feroxbuster(&config, tx.clone())
).await {
    Ok(Ok(_))  => {},
    Ok(Err(e)) => eprintln!("[{}] error: {}", module_name, e),
    Err(_)     => tx.send(FindingEvent::Timeout { module: module_name.into() }).ok(),
}

tx.send(FindingEvent::ModuleEnd { name: module_name.into() }).ok();
```

Default timeout values (configurable via CLI):
- ffuf (subdomains): 180s
- ffuf (vhosts): 120s
- httpx: 60s total (10s per host internally)
- feroxbuster: 300s
- katana: 120s
- whatweb: 30s per host
- eyewitness: 120s total
- JS scanner: 10s per file, 120s total

---

## HTTP probe and header analysis

Both are handled by httpx in a single pass during phase 1. See the httpx module section above. There is no separate pure-Rust probe or headers module — reqwest is not used for probing or header inspection.

---

## Findings store

Thread-safe, append-only store shared across all tasks:

```rust
pub struct FindingStore {
    pub subdomains:  Vec<SubdomainFinding>,
    pub vhosts:      Vec<VhostFinding>,
    pub endpoints:   Vec<EndpointFinding>,
    pub urls:        Vec<UrlFinding>,
    pub secrets:     Vec<SecretFinding>,
    pub technologies: Vec<TechFinding>,
    pub header_alerts: Vec<HeaderFinding>,
    pub screenshots: Vec<ScreenshotFinding>,
    pub live_hosts:  Vec<LiveHost>,
    pub timeouts:    Vec<String>,
}

pub type SharedStore = Arc<Mutex<FindingStore>>;
```

The store subscriber on the event bus appends to the appropriate vec for each `FindingEvent` variant received.

---

## HTML report

Generated using the `tera` crate. The template is embedded at compile time via `include_str!`. The report is a single fully self-contained `.html` file — no external CSS, JS, or image dependencies.

Report sections:
1. **Header** — target, scan date/time, duration, tool versions
2. **Executive summary** — counts table (subdomains found, endpoints found, secrets found, techs detected, header alerts)
3. **Timeouts** — which modules timed out during the run
4. **Live hosts** — table with status, title, server header
5. **Subdomains** — discovered subdomains with status codes
6. **Virtual hosts** — discovered vhosts
7. **Endpoints** — full dirbusting results table, sortable by status code
8. **Secrets** — grouped by pattern type, with file URL and redacted snippet
9. **Header analysis** — grouped by severity, with host and description
10. **Technology stack** — grouped by host
11. **Screenshots** — gallery grid, one card per host, screenshot embedded as base64 PNG data URI
12. **Raw crawled URLs** — collapsible full URL list

Severity badge colors in the report: Red = High, Orange = Medium, Blue = Info/Low.

---

## Cargo.toml dependencies

```toml
[dependencies]
tokio          = { version = "1", features = ["full"] }
reqwest        = { version = "0.11", features = ["json", "rustls-tls"] }  # only for JS file fetching in js_scanner
clap           = { version = "4", features = ["derive"] }
colored        = "2"
serde          = { version = "1", features = ["derive"] }
serde_json     = "1"
tera           = "1"
regex          = "1"
url            = "2"
base64         = "0.21"
tempfile       = "3"
which          = "4"
glob           = "0.3"
tokio-stream   = "0.1"
indicatif      = "0.17"
```

Note: `scraper` is no longer needed — httpx handles title extraction. `reqwest` is kept but only for fetching raw `.js` file content in the JS scanner; it is not used for probing or header inspection.

---

## CLI interface

```
ctf-recon --target example.com --port 443 [OPTIONS]

Options:
  -t, --target <DOMAIN>          Target domain (required)
  -p, --port <PORT>              Target port (default: 443)
  -w, --wordlist <FILE>          Custom wordlist (default: bundled)
  -o, --output <FILE>            Report output path (default: recon_<target>_<timestamp>.html)
      --timeout <SECS>           Per-module timeout in seconds (default: varies per module)
      --threads <N>              Concurrency hint passed to external tools (default: 50)
      --screenshot-dir <DIR>     Where EyeWitness saves screenshots (default: /tmp/ctf-recon-shots/)
      --skip <MODULES>           Comma-separated list of modules to skip
      --no-report                Skip report generation (terminal output only)
  -v, --verbose                  Show raw tool output alongside parsed events
```

---

## Project file structure

```
ctf-recon/
├── Cargo.toml
├── Cargo.lock
├── README.md
├── src/
│   ├── main.rs                  # CLI parsing, dep check, runtime bootstrap, Ctrl+C handler
│   ├── config.rs                # Config struct built from CLI args
│   ├── orchestrator.rs          # Phase scheduler, JoinSet management
│   ├── events.rs                # FindingEvent enum, broadcast channel setup
│   ├── printer.rs               # Colored terminal output subscriber
│   ├── store.rs                 # FindingStore, SharedStore, store subscriber task
│   ├── modules/
│   │   ├── mod.rs
│   │   ├── httpx.rs             # httpx probe + header analysis (streaming NDJSON)
│   │   ├── ffuf_subdomains.rs   # ffuf subdomain scan
│   │   ├── ffuf_vhosts.rs       # ffuf vhost scan
│   │   ├── feroxbuster.rs       # feroxbuster dirbusting
│   │   ├── katana.rs            # katana crawler
│   │   ├── js_scanner.rs        # JS secret scanner (pure Rust, reqwest for fetching)
│   │   ├── whatweb.rs           # WhatWeb tech fingerprinting
│   │   └── eyewitness.rs        # EyeWitness screenshot capture
│   ├── wordlist.rs              # Augmented wordlist builder (merge + dedup)
│   └── report/
│       ├── mod.rs               # Tera render logic, base64 screenshot embedding
│       └── template.html        # Tera HTML template (include_str! at compile time)
├── wordlists/
│   └── common.txt               # Bundled default wordlist
└── assets/
    └── report.css               # Inlined into template at compile time (optional)
```

---

## Build order (suggested implementation sequence)

1. `Cargo.toml` + `config.rs` + `main.rs` skeleton — CLI parsing and dependency check only
2. `events.rs` + `printer.rs` — get the event bus and colored terminal output working with mock events
3. `store.rs` — add the store subscriber
4. `ffuf_subdomains.rs` + `ffuf_vhosts.rs` — first external subprocess integration
5. `httpx.rs` — streaming NDJSON probe + inline header analysis; validates the live hosts pipeline
6. `katana.rs` — crawler, NDJSON parsing
7. `wordlist.rs` + `feroxbuster.rs` — augmented wordlist flow + dirbust
8. `js_scanner.rs` — load SecretFinder patterns, test against known JS samples
9. `whatweb.rs` — batch mode subprocess
10. `eyewitness.rs` — file-based integration
11. `report/` — Tera template, wire all findings, test self-contained output
12. `orchestrator.rs` — connect all modules into phased execution with timeouts
13. End-to-end testing against a local target (e.g. HackTheBox machine or DVWA)

---

## Key implementation notes for future context

- **No module reimplements what an external tool already does.** If a tool exists and is best-in-class for a task, use it. Rust owns coordination, parsing, and output.
- **httpx replaces both the pure-Rust HTTP probe and the pure-Rust header analysis module.** It handles live host filtering, title extraction, header inspection, and a first-pass tech detection in a single streaming NDJSON pass. Header analysis logic runs inline inside the httpx output parser — no second HTTP request is made.
- **Katana replaces the robots.rs/sitemap module** that was in the original plan. Its `-known-files all` flag handles this automatically.
- **ffuf uses plaintext output + regex**, not JSON, for real-time streaming. JSON mode in ffuf writes a summary file at exit, not a stream.
- **WhatWeb and EyeWitness are batch** — wait for process exit, then ingest. They are fast enough that streaming is not needed.
- **httpx, feroxbuster, and katana are NDJSON streaming** — parse line by line as the process runs.
- **reqwest is kept only for the JS scanner** — to fetch raw `.js` file content. It is not used for probing or header inspection.
- **JS scanner patterns come from the SecretFinder project** (https://github.com/m4ll0k/SecretFinder). Pull the full `regex.py` pattern list from that repo and port to Rust regex syntax (Python and Rust regex are mostly compatible; watch for named groups `(?P<name>...)` which are `(?<name>...)` in Rust).
- **Screenshots are base64-embedded** in the HTML report so the report is one file with no external dependencies.
- **The wordlist augmentation pipeline**: katana discoveries from phase 2 are path-segmented and merged with the bundled wordlist, written to a tempfile, passed to feroxbuster. The tempfile auto-deletes on drop.
- **Ctrl+C handling**: register a `tokio::signal::ctrl_c()` listener in main. On signal, set a shared `AtomicBool` cancellation flag. Modules check this flag periodically (or the timeout watchdog handles it). After the signal, drain the store and generate a partial report.
- **The `--skip` flag** lets the operator skip modules by name (e.g. `--skip eyewitness,whatweb`) for faster runs when certain info isn't needed.
