use std::path::PathBuf;

use clap::Parser;

use crate::tool_paths::ToolPaths;

#[derive(Parser, Debug, Clone)]
#[command(name = "scry", about = "Multi-phase recon tool for CTF and penetration testing\nDefaults to port 443 over HTTPS when only --target is supplied.\nPorts 80 and 8080 default to HTTP; all others default to HTTPS.")]
pub struct Config {
    /// Target domain (e.g. example.com)
    #[arg(short, long)]
    pub target: String,

    /// Target port (default: 443). Ports 80 and 8080 auto-select HTTP; all others auto-select HTTPS.
    #[arg(short, long, default_value = "443")]
    pub port: u16,

    /// Protocol override: http or https (default: auto-detected from port)
    #[arg(long, value_parser = ["http", "https"])]
    pub protocol: Option<String>,

    /// Custom wordlist path (default: bundled common.txt)
    #[arg(short, long)]
    pub wordlist: Option<PathBuf>,

    /// Report output path (default: recon_<target>_<timestamp>.html)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Per-module timeout in seconds
    #[arg(long, default_value = "300")]
    pub module_timeout: u64,

    /// Concurrency hint passed to external tools
    #[arg(long, default_value = "50")]
    pub threads: u64,

    /// Directory where EyeWitness saves screenshots
    #[arg(long, default_value = "/tmp/scry-shots")]
    pub screenshot_dir: PathBuf,

    /// Comma-separated list of modules to skip (e.g. eyewitness,whatweb)
    #[arg(long, value_delimiter = ',', default_value = "")]
    pub skip: Vec<String>,

    /// Skip report generation (terminal output only)
    #[arg(long)]
    pub no_report: bool,

    /// Show raw tool output alongside parsed events
    #[arg(short, long)]
    pub verbose: bool,

    /// Print all external tool commands and their raw output
    #[arg(short = 'd', long)]
    pub debug: bool,

    /// Custom tool paths loaded from ~/.config/scry/scry.conf
    #[arg(skip)]
    pub tool_paths: ToolPaths,

    /// SecLists base directory (from scry.conf `seclists=` or default)
    #[arg(skip)]
    pub seclists_base: PathBuf,
}

impl Config {
    pub fn scheme(&self) -> &'static str {
        if let Some(p) = &self.protocol {
            return if p == "https" { "https" } else { "http" };
        }
        match self.port {
            80 | 8080 => "http",
            _ => "https",
        }
    }

    pub fn target_url(&self) -> String {
        self.url_for(&self.target.clone())
    }

    pub fn url_for(&self, host: &str) -> String {
        let scheme = self.scheme();
        if (self.port == 443 && scheme == "https") || (self.port == 80 && scheme == "http") {
            format!("{}://{}", scheme, host)
        } else {
            format!("{}://{}:{}", scheme, host, self.port)
        }
    }

    pub fn should_skip(&self, module: &str) -> bool {
        self.skip.iter().any(|s| s.eq_ignore_ascii_case(module))
    }
}
