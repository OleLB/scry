use std::collections::HashMap;
use std::process::Stdio;

use serde::Deserialize;

use crate::config::Config;
use crate::events::{FindingEvent, Sender};
use crate::tool_paths::make_command;

#[derive(Debug, Deserialize)]
struct WhatWebResult {
    target: String,
    #[serde(default)]
    plugins: HashMap<String, WhatWebPlugin>,
}

#[derive(Debug, Deserialize)]
struct WhatWebPlugin {
    version: Option<Vec<String>>,
    #[allow(dead_code)]
    string: Option<Vec<String>>,
}

pub async fn run(config: &Config, target_url: &str, tx: &Sender) -> anyhow::Result<()> {
    let output = make_command("whatweb", &config.tool_paths)
        .args([
            "--log-json=-",
            "--no-errors",
            "--quiet",
            target_url,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let text = stdout.trim();
    if text.is_empty() {
        return Ok(());
    }

    // WhatWeb outputs a JSON array
    let results: Vec<WhatWebResult> = match serde_json::from_str(text) {
        Ok(r) => r,
        Err(_) => {
            // Sometimes it outputs one object per line instead of an array
            text.lines()
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect()
        }
    };

    for result in &results {
        for (plugin_name, plugin) in &result.plugins {
            let version = plugin
                .version
                .as_ref()
                .and_then(|v| v.first())
                .cloned();
            tx.send(FindingEvent::TechDetected {
                host: result.target.clone(),
                tech: plugin_name.clone(),
                version,
            })
            .ok();
        }
    }

    Ok(())
}
