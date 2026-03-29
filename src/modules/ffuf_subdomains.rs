use std::io::Write;
use std::process::Stdio;

use regex::Regex;
use tokio::io::{AsyncBufReadExt, BufReader};
use crate::config::Config;
use crate::events::{FindingEvent, Sender};
use crate::tool_paths::make_command;
use crate::wordlist;

pub async fn run(config: &Config, tx: &Sender) -> anyhow::Result<()> {
    let (wordlist_path, _tmp) = get_wordlist_path(config);
    let url_pattern = format!("https://FUZZ.{}", config.target);

    let mut child = make_command("ffuf", &config.tool_paths)
        .args([
            "-w",
            &wordlist_path,
            "-u",
            &url_pattern,
            "-mc",
            "200,204,301,302,307,401,403",
            "-t",
            "100",
            "-s",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    let stdout = child.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();

    let re = Regex::new(
        r"^(\S+)\s+\[Status: (\d+), Size: (\d+), Words: (\d+), Lines: (\d+)\]",
    )
    .unwrap();

    while let Some(line) = lines.next_line().await? {
        if let Some(caps) = re.captures(&line) {
            let host = format!("{}.{}", &caps[1], config.target);
            let status: u16 = caps[2].parse().unwrap_or(0);
            tx.send(FindingEvent::NewSubdomain { host, status }).ok();
        }
    }

    child.wait().await?;
    // _tmp drops here, cleaning up the bundled-wordlist tempfile if one was created
    Ok(())
}

/// Returns (path_string, optional_tempfile_handle).
/// The tempfile handle must be kept alive for the duration of the ffuf run.
fn get_wordlist_path(config: &Config) -> (String, Option<tempfile::NamedTempFile>) {
    // 1. User override
    if let Some(p) = &config.wordlist {
        return (p.to_string_lossy().into_owned(), None);
    }
    // 2. SecLists DNS wordlist
    if let Some(p) = wordlist::seclists_dns_wordlist(&config.seclists_base) {
        return (p.to_string_lossy().into_owned(), None);
    }
    // 3. Bundled fallback — write to tempfile and hold the handle
    let content = include_str!("../../wordlists/common.txt");
    let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
    write!(tmp, "{}", content).ok();
    let path = tmp.path().to_string_lossy().into_owned();
    (path, Some(tmp))
}
