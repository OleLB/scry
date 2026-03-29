use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};

use tempfile::NamedTempFile;

static BUNDLED_WORDLIST: &str = include_str!("../wordlists/common.txt");

pub fn seclists_available(seclists_base: &Path) -> bool {
    seclists_base.is_dir()
}

pub fn seclists_dns_wordlist(seclists_base: &Path) -> Option<PathBuf> {
    let p = seclists_base.join("Discovery/DNS/subdomains-top1million-20000.txt");
    p.exists().then_some(p)
}

/// Returns the base web-content wordlist path (combined_directories.txt) if it exists.
pub fn seclists_web_wordlists(seclists_base: &Path) -> Vec<PathBuf> {
    let p = seclists_base.join("Discovery/Web-Content/combined_directories.txt");
    if p.exists() { vec![p] } else { vec![] }
}

/// Returns tech-specific wordlist paths for any techs detected in Phase 1.
/// CMS wordlists come first; IIS/ActiveDirectory is added when IIS is detected.
pub fn seclists_cms_wordlists(seclists_base: &Path, detected_techs: &[String]) -> Vec<PathBuf> {
    let tech_map = [
        ("wordpress", "Discovery/Web-Content/CMS/CMS-Wordpress.txt"),
        ("joomla",    "Discovery/Web-Content/CMS/CMS-Joomla.txt"),
        ("drupal",    "Discovery/Web-Content/CMS/CMS-Drupal.txt"),
        ("iis",       "Discovery/Web-Content/ActiveDirectory-small.txt"),
    ];
    let mut paths = Vec::new();
    for (name, file) in &tech_map {
        if detected_techs.iter().any(|t| t.to_lowercase().contains(name)) {
            let p = seclists_base.join(file);
            if p.exists() {
                paths.push(p);
            }
        }
    }
    paths
}

/// Returns true for lines that should be kept — non-empty, non-comment.
fn is_valid_word(line: &str) -> bool {
    let t = line.trim();
    !t.is_empty() && !t.starts_with('#')
}

/// Build the augmented wordlist for feroxbuster.
///
/// Priority:
/// 1. `user_wordlist` — used alone when set (user override wins)
/// 2. `extra_wordlists` — SecLists web-content + CMS paths merged together
/// 3. Bundled `common.txt` — fallback when neither above is available
///
/// Katana-discovered URL path segments are always appended regardless of source.
pub async fn build_wordlist(
    user_wordlist: Option<&Path>,
    extra_wordlists: &[PathBuf],
    discovered_urls: &[String],
) -> anyhow::Result<NamedTempFile> {
    let mut words: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let mut push = |w: String| {
        if seen.insert(w.clone()) {
            words.push(w);
        }
    };

    if let Some(p) = user_wordlist {
        // User override: read only this file, preserving order
        let content = tokio::fs::read_to_string(p).await.unwrap_or_default();
        for line in content.lines().filter(|l| is_valid_word(l)) {
            push(line.to_string());
        }
    } else if !extra_wordlists.is_empty() {
        // SecLists: merge files in the order they were provided (CMS first, then combined)
        for path in extra_wordlists {
            if let Ok(content) = tokio::fs::read_to_string(path).await {
                for line in content.lines().filter(|l| is_valid_word(l)) {
                    push(line.to_string());
                }
            }
        }
    } else {
        // Bundled fallback
        for line in BUNDLED_WORDLIST.lines().filter(|l| is_valid_word(l)) {
            push(line.to_string());
        }
    }

    // Always augment with katana-discovered path segments (appended at the end)
    for url_str in discovered_urls {
        if let Ok(parsed) = url::Url::parse(url_str) {
            let path = parsed.path().trim_start_matches('/');
            for segment in path.split('/') {
                let seg = segment.trim();
                if !seg.is_empty() {
                    push(seg.to_string());
                }
            }
            if !path.is_empty() {
                push(path.to_string());
            }
        }
    }

    let mut file = NamedTempFile::new()?;
    for word in &words {
        writeln!(file, "{}", word)?;
    }
    file.flush()?;
    Ok(file)
}
