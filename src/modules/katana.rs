use std::process::Stdio;

use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use crate::config::Config;
use crate::events::{FindingEvent, Sender};
use crate::tool_paths::make_command;

#[derive(Debug, Deserialize)]
struct KatanaResult {
    request: KatanaRequest,
    response: Option<KatanaResponse>,
}

#[derive(Debug, Deserialize)]
struct KatanaRequest {
    endpoint: String,
    #[allow(dead_code)]
    method: Option<String>,
}

#[derive(Debug, Deserialize)]
struct KatanaResponse {
    #[serde(rename = "status_code")]
    status_code: Option<u16>,
    #[allow(dead_code)]
    content_type: Option<String>,
}

pub async fn run(config: &Config, target_url: &str, tx: &Sender) -> anyhow::Result<()> {
    let mut child = make_command("katana", &config.tool_paths)
        .args([
            "-u",
            target_url,
            "-jsonl",
            "-silent",
            "-depth",
            "3",
            "-js-crawl",
            "-known-files",
            "all",
            "-timeout",
            "10",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    let stdout = child.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(result) = serde_json::from_str::<KatanaResult>(&line) {
            let url = result.request.endpoint.clone();
            let source = if result.response.as_ref().and_then(|r| r.status_code).is_some() {
                "katana"
            } else {
                "katana"
            };
            tx.send(FindingEvent::NewUrl {
                url: url.clone(),
                source: source.to_string(),
            })
            .ok();
        }
    }

    child.wait().await?;
    Ok(())
}
