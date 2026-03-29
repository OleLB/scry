use std::{path::PathBuf, sync::Arc};

use tokio::sync::{Mutex, broadcast::error::RecvError};

use crate::events::{FindingEvent, Receiver, Severity};

// ── Finding types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LiveHost {
    pub final_url: String,
    pub status: u16,
    pub title: Option<String>,
    pub server: Option<String>,
    pub content_length: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct SubdomainFinding {
    pub host: String,
    pub status: u16,
}

#[derive(Debug, Clone)]
pub struct VhostFinding {
    pub host: String,
    pub status: u16,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct EndpointFinding {
    pub url: String,
    pub status: u16,
    pub size: u64,
    pub words: u64,
    pub redirect_to: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UrlFinding {
    pub url: String,
    pub source: String,
}

#[derive(Debug, Clone)]
pub struct SecretFinding {
    pub url: String,
    pub pattern: String,
    pub snippet: String,
}

#[derive(Debug, Clone)]
pub struct TechFinding {
    pub host: String,
    pub tech: String,
    pub version: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HeaderFinding {
    pub host: String,
    pub severity: Severity,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct ScreenshotFinding {
    pub host: String,
    pub url: String,
    pub path: PathBuf,
}

// ── FindingStore ──────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct FindingStore {
    pub subdomains: Vec<SubdomainFinding>,
    pub vhosts: Vec<VhostFinding>,
    pub live_hosts: Vec<LiveHost>,
    pub endpoints: Vec<EndpointFinding>,
    pub urls: Vec<UrlFinding>,
    pub js_urls: Vec<String>,
    pub secrets: Vec<SecretFinding>,
    pub technologies: Vec<TechFinding>,
    pub header_alerts: Vec<HeaderFinding>,
    pub screenshots: Vec<ScreenshotFinding>,
    pub timeouts: Vec<String>,
}

pub type SharedStore = Arc<Mutex<FindingStore>>;

// ── Store subscriber task ─────────────────────────────────────────────────────

pub async fn run_store(mut rx: Receiver, store: SharedStore) {
    loop {
        match rx.recv().await {
            Ok(event) => {
                let mut s = store.lock().await;
                match event {
                    FindingEvent::ModuleStart { .. } | FindingEvent::ModuleEnd { .. } => {}
                    FindingEvent::Timeout { module } => {
                        s.timeouts.push(module);
                    }
                    FindingEvent::NewSubdomain { host, status } => {
                        s.subdomains.push(SubdomainFinding { host, status });
                    }
                    FindingEvent::NewVhost { host, status, size } => {
                        s.vhosts.push(VhostFinding { host, status, size });
                    }
                    FindingEvent::LiveHost { host } => {
                        s.live_hosts.push(host);
                    }
                    FindingEvent::NewEndpoint { url, status, size, words, redirect_to } => {
                        s.endpoints.push(EndpointFinding { url, status, size, words, redirect_to });
                    }
                    FindingEvent::NewUrl { url, source } => {
                        if url.ends_with(".js") {
                            s.js_urls.push(url.clone());
                        }
                        s.urls.push(UrlFinding { url, source });
                    }
                    FindingEvent::SecretFound { url, pattern, snippet } => {
                        s.secrets.push(SecretFinding { url, pattern, snippet });
                    }
                    FindingEvent::TechDetected { host, tech, version } => {
                        s.technologies.push(TechFinding { host, tech, version });
                    }
                    FindingEvent::HeaderAlert { host, severity, message } => {
                        s.header_alerts.push(HeaderFinding { host, severity, message });
                    }
                    FindingEvent::Screenshot { host, url, path } => {
                        s.screenshots.push(ScreenshotFinding { host, url, path });
                    }
                }
            }
            Err(RecvError::Lagged(_)) => {}
            Err(RecvError::Closed) => break,
        }
    }
}
