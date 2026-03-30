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
    let url_pattern = format!("{}://FUZZ.{}:{}", config.scheme(), config.target, config.port);
    let wordlist_arg = format!("{}:FUZZ", wordlist_path);

    if config.debug {
        eprintln!("[debug] ffuf (subdomains) -w {} -u {}", wordlist_arg, url_pattern);
    }
    let mut child = make_command("ffuf", &config.tool_paths)
        .args(["-w", &wordlist_arg, "-u", &url_pattern])
        .stdout(Stdio::piped())
        .stderr(if config.debug { Stdio::inherit() } else { Stdio::piped() })
        .spawn()?;

    let stdout = child.stdout.take().unwrap();
    // Drain piped stderr (non-debug) so ffuf doesn't block on a full pipe buffer
    if !config.debug {
        let stderr = child.stderr.take().unwrap();
        tokio::spawn(async move {
            let mut buf = tokio::io::BufReader::new(stderr);
            let mut sink = Vec::new();
            let _ = tokio::io::AsyncReadExt::read_to_end(&mut buf, &mut sink).await;
        });
    }

    let mut lines = BufReader::new(stdout).lines();

    // ffuf v2.x appends ", Duration: Xms" before the closing bracket
    let re = Regex::new(
        r"^(\S+)\s+\[Status: (\d+), Size: (\d+), Words: (\d+), Lines: (\d+)",
    )
    .unwrap();

    while let Some(line) = lines.next_line().await? {
        if config.debug { eprintln!("[debug|ffuf_subdomains] {}", line); }
        let line = line.trim_matches('\r');
        let line = strip_ansi(line);
        if let Some(caps) = re.captures(line.as_ref()) {
            let host = format!("{}.{}", &caps[1], config.target);
            let status: u16 = caps[2].parse().unwrap_or(0);
            tx.send(FindingEvent::NewSubdomain { host, status }).ok();
        }
    }

    child.wait().await?;
    // _tmp drops here, cleaning up the bundled-wordlist tempfile if one was created
    Ok(())
}

fn strip_ansi(s: &str) -> std::borrow::Cow<'_, str> {
    if !s.contains('\x1b') {
        return std::borrow::Cow::Borrowed(s);
    }
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r"\x1b\[[0-9;]*[A-Za-z]").unwrap());
    std::borrow::Cow::Owned(re.replace_all(s, "").into_owned())
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
