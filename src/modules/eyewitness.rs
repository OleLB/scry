use std::io::Write;
use std::path::Path;
use std::process::Stdio;

use crate::config::Config;
use crate::events::{FindingEvent, Sender};
use crate::tool_paths::make_command;

pub async fn run(config: &Config, live_urls: &[String], tx: &Sender) -> anyhow::Result<()> {
    if live_urls.is_empty() {
        return Ok(());
    }

    // Write URL list to a tempfile
    let mut tmp = tempfile::NamedTempFile::new()?;
    for url in live_urls {
        writeln!(tmp, "{}", url)?;
    }
    tmp.flush()?;

    let dest = &config.screenshot_dir;
    std::fs::create_dir_all(dest)?;

    let mut child = make_command("EyeWitness.py", &config.tool_paths)
        .args([
            "--web",
            "-f",
            &tmp.path().to_string_lossy(),
            "-d",
            &dest.to_string_lossy(),
            "--no-prompt",
            "--timeout",
            "10",
            "--threads",
            "5",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    child.wait().await?;

    // Collect screenshots — pass urls so each PNG can be linked back to its source
    collect_screenshots(dest, live_urls, tx).await;

    Ok(())
}

async fn collect_screenshots(dest: &Path, urls: &[String], tx: &Sender) {
    let pattern = dest.join("**/*.png").to_string_lossy().into_owned();
    if let Ok(paths) = glob::glob(&pattern) {
        for entry in paths.flatten() {
            let stem = entry
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();

            // Find the URL from the input list whose host best matches the filename stem.
            // EyeWitness names files after the host (e.g. facts.htb.png for http://facts.htb).
            // For endpoint URLs the stem may contain path components too, so we prefer
            // the longest host match found within the stem.
            let url = urls
                .iter()
                .filter_map(|u| {
                    let parsed = url::Url::parse(u).ok()?;
                    let host = parsed.host_str()?.to_string();
                    if !stem.contains(&host) { return None; }
                    // Also score path segments that appear in the stem so that
                    // http://facts.htb/admin beats http://facts.htb for stem "facts.htb_admin".
                    let path_score: usize = parsed
                        .path_segments()
                        .map(|segs| {
                            segs.filter(|seg| !seg.is_empty() && stem.contains(*seg))
                                .map(|seg| seg.len())
                                .sum()
                        })
                        .unwrap_or(0);
                    Some((host.len() + path_score, u.clone()))
                })
                .max_by_key(|(score, _)| *score)
                .map(|(_, u)| u)
                .unwrap_or_else(|| format!("http://{}", stem));

            tx.send(FindingEvent::Screenshot {
                host: stem,
                url,
                path: entry,
            })
            .ok();
        }
    }
}
