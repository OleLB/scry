use std::collections::HashMap;
use std::io::Write;
use std::process::Stdio;

use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use crate::config::Config;
use crate::events::{FindingEvent, Sender, Severity};
use crate::store::{LiveHost, SharedStore};
use crate::tool_paths::make_command;

#[derive(Debug, Deserialize)]
struct HttpxResult {
    url: String,
    #[serde(rename = "status-code", default)]
    status: u16,
    title: Option<String>,
    #[serde(rename = "content-length")]
    content_length: Option<u64>,
    tech: Option<Vec<String>>,
    #[serde(default)]
    headers: Option<HashMap<String, String>>,
    #[serde(rename = "final-url")]
    final_url: Option<String>,
}

pub async fn run(
    config: &Config,
    store: &SharedStore,
    tx: &Sender,
) -> anyhow::Result<()> {
    // Build hosts list: base domain + all discovered subdomains + vhosts.
    // Use full URLs (scheme + port) so httpx probes the right port.
    // Vhosts work here when the caller has added them to /etc/hosts; httpx
    // fails gracefully (no output) for any entry it cannot resolve.
    let hosts: Vec<String> = {
        let s = store.lock().await;
        let mut list: Vec<String> = s
            .subdomains
            .iter()
            .map(|f| config.url_for(&f.host))
            .collect();
        for vhost in &s.vhosts {
            list.push(config.url_for(&vhost.host));
        }
        list.push(config.target_url());
        list
    };

    let mut tmp = tempfile::NamedTempFile::new()?;
    for host in &hosts {
        writeln!(tmp, "{}", host)?;
    }
    tmp.flush()?;
    let tmp_path = tmp.path().to_string_lossy().into_owned();

    let threads_str = config.threads.to_string();
    let args = [
        "-list", &tmp_path, "-json", "-silent", "-title",
        "-status-code", "-content-length", "-tech-detect",
        "-include-response-header", "-follow-redirects",
        "-threads", &threads_str, "-timeout", "10",
    ];
    if config.debug {
        eprintln!("[debug] httpx {}", args.join(" "));
    }
    let mut child = make_command("httpx", &config.tool_paths)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(if config.debug { Stdio::inherit() } else { Stdio::null() })
        .spawn()?;

    let stdout = child.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();

    while let Some(line) = lines.next_line().await? {
        if config.debug { eprintln!("[debug|httpx] {}", line); }
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(result) = serde_json::from_str::<HttpxResult>(&line) {
            let server = result
                .headers
                .as_ref()
                .and_then(|h| h.get("server").cloned());

            let final_url = result.final_url.clone().unwrap_or_else(|| result.url.clone());

            let host = LiveHost {
                final_url: final_url.clone(),
                status: result.status,
                title: result.title.clone(),
                server: server.clone(),
                content_length: result.content_length,
            };

            tx.send(FindingEvent::LiveHost { host }).ok();

            // Inline header analysis
            analyse_headers(&result, tx);

            // Tech detection (first-pass from httpx)
            if let Some(techs) = &result.tech {
                for tech_str in techs {
                    // Format: "Name:version" or just "Name"
                    let (tech, version) = if let Some(idx) = tech_str.find(':') {
                        let (t, v) = tech_str.split_at(idx);
                        (t.to_string(), Some(v[1..].to_string()))
                    } else {
                        (tech_str.clone(), None)
                    };
                    tx.send(FindingEvent::TechDetected {
                        host: final_url.clone(),
                        tech,
                        version,
                    })
                    .ok();
                }
            }
        }
    }

    child.wait().await?;
    Ok(())
}

fn analyse_headers(result: &HttpxResult, tx: &Sender) {
    let headers = match &result.headers {
        Some(h) => h,
        None => return,
    };

    let host = result.final_url.clone().unwrap_or_else(|| result.url.clone());

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
                host: host.clone(),
                severity: Severity::Medium,
                message: format!("Missing: {}", header),
            })
            .ok();
        }
    }

    // Tech leakage headers
    for header in ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"] {
        if let Some(val) = headers.get(header) {
            tx.send(FindingEvent::HeaderAlert {
                host: host.clone(),
                severity: Severity::Info,
                message: format!("{}: {}", header, val),
            })
            .ok();
        }
    }

    // CORS wildcard
    if headers
        .get("access-control-allow-origin")
        .map(|v| v == "*")
        .unwrap_or(false)
    {
        tx.send(FindingEvent::HeaderAlert {
            host: host.clone(),
            severity: Severity::High,
            message: "Open CORS: Access-Control-Allow-Origin: *".into(),
        })
        .ok();
    }

    // Credentials with wildcard CORS
    if headers
        .get("access-control-allow-credentials")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
        && headers
            .get("access-control-allow-origin")
            .map(|v| v == "*")
            .unwrap_or(false)
    {
        tx.send(FindingEvent::HeaderAlert {
            host: host.clone(),
            severity: Severity::High,
            message: "CORS misconfiguration: credentials allowed with wildcard origin".into(),
        })
        .ok();
    }

    // Set-Cookie flag checks
    if let Some(cookie) = headers.get("set-cookie") {
        let lower = cookie.to_lowercase();
        if !lower.contains("httponly") {
            tx.send(FindingEvent::HeaderAlert {
                host: host.clone(),
                severity: Severity::Medium,
                message: "Set-Cookie missing HttpOnly flag".into(),
            })
            .ok();
        }
        if host.starts_with("https") && !lower.contains("secure") {
            tx.send(FindingEvent::HeaderAlert {
                host: host.clone(),
                severity: Severity::Medium,
                message: "Set-Cookie missing Secure flag on HTTPS".into(),
            })
            .ok();
        }
    }
}
