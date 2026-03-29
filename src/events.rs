use std::path::PathBuf;

use tokio::sync::broadcast;

use crate::store::LiveHost;

#[derive(Debug, Clone)]
pub enum Severity {
    High,
    Medium,
    Info,
}

#[derive(Debug, Clone)]
pub enum FindingEvent {
    ModuleStart { name: String },
    ModuleEnd { name: String },
    Timeout { module: String },
    NewSubdomain { host: String, status: u16 },
    NewVhost { host: String, status: u16, size: u64 },
    LiveHost { host: LiveHost },
    NewEndpoint { url: String, status: u16, size: u64, words: u64, redirect_to: Option<String> },
    NewUrl { url: String, source: String },
    SecretFound { url: String, pattern: String, snippet: String },
    TechDetected { host: String, tech: String, version: Option<String> },
    HeaderAlert { host: String, severity: Severity, message: String },
    Screenshot { host: String, url: String, path: PathBuf },
}

pub type Sender = broadcast::Sender<FindingEvent>;
pub type Receiver = broadcast::Receiver<FindingEvent>;

pub fn make_channel() -> (Sender, Receiver) {
    broadcast::channel(1024)
}
