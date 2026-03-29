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
    let target_url = config.target_url();

    // Probe with a random hostname to get baseline response size for -fs
    let baseline_size = get_baseline_size(config).await.unwrap_or(0);

    let host_header = format!("Host: FUZZ.{}", config.target);

    let mut args = vec![
        "-w".to_string(),
        wordlist_path,
        "-u".to_string(),
        target_url,
        "-H".to_string(),
        host_header,
        "-mc".to_string(),
        "200,204,301,302,307,401,403".to_string(),
        "-t".to_string(),
        "100".to_string(),
        "-s".to_string(),
    ];

    if baseline_size > 0 {
        args.push("-fs".to_string());
        args.push(baseline_size.to_string());
    }

    let mut child = make_command("ffuf", &config.tool_paths)
        .args(&args)
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
            let size: u64 = caps[3].parse().unwrap_or(0);
            tx.send(FindingEvent::NewVhost { host, status, size }).ok();
        }
    }

    child.wait().await?;
    // _tmp drops here, cleaning up the bundled-wordlist tempfile if one was created
    Ok(())
}

async fn get_baseline_size(config: &Config) -> Option<u64> {
    let random_host = format!(
        "ctfrecon-baseline-{}.{}",
        uuid_like(),
        config.target
    );
    let url = config.target_url();

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok()?;

    let resp = client
        .get(&url)
        .header("Host", &random_host)
        .send()
        .await
        .ok()?;

    let bytes = resp.bytes().await.ok()?;
    Some(bytes.len() as u64)
}

fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    format!("{:08x}", t)
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
