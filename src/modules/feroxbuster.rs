use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Deserialize;
use tokio::io::AsyncReadExt;
use crate::config::Config;
use crate::events::{FindingEvent, Sender};
use crate::tool_paths::make_command;
use crate::wordlist;

#[derive(Debug, Deserialize)]
struct FeroxResult {
    #[serde(rename = "type")]
    kind: String,
    url: String,
    status: u16,
    #[serde(rename = "content_length", default)]
    content_length: u64,
    #[serde(default)]
    words: u64,
    #[serde(default)]
    headers: HashMap<String, String>,
}

/// Build a comma-separated extension list based on detected technologies and
/// whether a large (SecLists) or small (bundled) wordlist is in use.
///
/// With a large wordlist the wordlist itself contains explicit filenames, so
/// we only add extensions that are directly implied by detected tech.
/// With the bundled small wordlist we add a modest set of generic extras too.
fn build_extensions(techs: &[String], using_seclists: bool) -> Vec<&'static str> {
    let lower: Vec<String> = techs.iter().map(|s| s.to_lowercase()).collect();
    let has = |s: &str| lower.iter().any(|t| t.contains(s));

    let mut exts: Vec<&'static str> = Vec::new();

    // PHP-based stacks
    if has("php") || has("wordpress") || has("joomla") || has("drupal")
        || has("laravel") || has("magento") || has("prestashop")
    {
        exts.push("php");
    }
    // ASP.NET / IIS
    if has("asp.net") || has("iis") {
        exts.push("aspx");
    }
    // Java application servers
    if has("tomcat") || has("jboss") || has("glassfish") || has("wildfly") || has("weblogic") {
        exts.push("jsp");
    }
    // ColdFusion
    if has("coldfusion") {
        exts.push("cfm");
        exts.push("cfc");
    }
    // Perl / CGI
    if has("perl") || has("cgi") {
        exts.push("pl");
        exts.push("cgi");
    }

    if !using_seclists {
        // With the small bundled wordlist, broaden to generic high-value files
        for e in &["bak", "env", "log", "json", "conf", "zip", "old"] {
            if !exts.contains(e) {
                exts.push(e);
            }
        }
        // If still no server-side language detected, try the two most common ones
        if !exts.iter().any(|e| ["php", "aspx", "asp", "jsp", "cfm", "pl"].contains(e)) {
            exts.push("php");
            exts.push("aspx");
        }
    }

    exts
}

pub async fn run(
    config: &Config,
    target_url: &str,
    wordlist_path: &Path,
    detected_techs: &[String],
    skip_ferox: &Arc<AtomicBool>,
    tx: &Sender,
) -> anyhow::Result<()> {
    let wordlist = wordlist_path.to_string_lossy();
    let using_seclists = config.wordlist.is_none() && wordlist::seclists_available(&config.seclists_base);
    let exts = build_extensions(detected_techs, using_seclists);

    if exts.is_empty() {
        eprintln!("[feroxbuster] {} — no extensions (relying on wordlist)", target_url);
    } else {
        eprintln!("[feroxbuster] {} — extensions: {}", target_url, exts.join(","));
    }
    eprintln!("[feroxbuster] press Ctrl+C once to skip feroxbuster and continue the scan");

    let mut cmd = make_command("feroxbuster", &config.tool_paths);
    cmd.args([
        "--url",
        target_url,
        "--wordlist",
        &wordlist,
        "--json",
        "--silent",
        "--no-state",
        "--timeout",
        "10",
        "--threads",
        &config.threads.to_string(),
        "--filter-status",
        "404",
    ]);
    if !exts.is_empty() {
        cmd.args(["--extensions", &exts.join(",")]);
    }

    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::null()).spawn()?;

    let mut stdout = child.stdout.take().unwrap();

    // feroxbuster --json --silent writes JSON objects concatenated without
    // newlines, so line-based reading doesn't work. Track brace depth to
    // split complete objects from the raw byte stream.
    //
    // No activity timeout here: feroxbuster with --filter-status 404 only
    // writes to stdout on non-404 hits, so silent gaps between hits can easily
    // exceed any reasonable per-read timeout on large wordlists. The outer
    // 7200s timeout in the orchestrator is the safety net; use Ctrl+C to skip.
    let mut json_buf: Vec<u8> = Vec::new();
    let mut depth: i32 = 0;
    let mut in_string = false;
    let mut escape_next = false;
    let mut chunk = [0u8; 8192];

    loop {
        let n = match stdout.read(&mut chunk).await {
            Ok(0) => break, // EOF — subprocess exited naturally
            Ok(n) => n,
            Err(e) => return Err(e.into()),
        };

        for &b in &chunk[..n] {
            if escape_next {
                escape_next = false;
                json_buf.push(b);
                continue;
            }
            if in_string {
                json_buf.push(b);
                match b {
                    b'\\' => escape_next = true,
                    b'"' => in_string = false,
                    _ => {}
                }
                continue;
            }
            match b {
                b'{' => {
                    depth += 1;
                    json_buf.push(b);
                }
                b'}' if depth > 0 => {
                    depth -= 1;
                    json_buf.push(b);
                    if depth == 0 {
                        if let Ok(r) = serde_json::from_slice::<FeroxResult>(&json_buf) {
                            if r.kind == "response" {
                                let redirect_to = if (300..400).contains(&r.status) {
                                    r.headers.get("location").cloned()
                                } else {
                                    None
                                };
                                tx.send(FindingEvent::NewEndpoint {
                                    url: r.url,
                                    status: r.status,
                                    size: r.content_length,
                                    words: r.words,
                                    redirect_to,
                                })
                                .ok();
                            }
                        }
                        json_buf.clear();
                    }
                }
                b'"' if depth > 0 => {
                    in_string = true;
                    json_buf.push(b);
                }
                _ if depth > 0 => {
                    json_buf.push(b);
                }
                _ => {} // whitespace/garbage between objects at depth 0
            }
        }

        if skip_ferox.load(Ordering::Relaxed) {
            eprintln!("[feroxbuster] skipped — {}", target_url);
            child.kill().await.ok();
            break;
        }
    }

    child.wait().await.ok();
    Ok(())
}
