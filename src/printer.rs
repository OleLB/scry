use colored::Colorize;
use tokio::sync::broadcast::error::RecvError;

use crate::events::{FindingEvent, Receiver, Severity};

pub async fn run_printer(mut rx: Receiver) {
    let mut seen_hosts: std::collections::HashSet<String> = std::collections::HashSet::new();
    loop {
        match rx.recv().await {
            Ok(event) => print_event(&event, &mut seen_hosts),
            Err(RecvError::Lagged(n)) => {
                eprintln!("{}", format!("[printer] lagged, dropped {} events", n).dimmed());
            }
            Err(RecvError::Closed) => break,
        }
    }
}

fn print_event(event: &FindingEvent, seen_hosts: &mut std::collections::HashSet<String>) {
    match event {
        FindingEvent::ModuleStart { name } => {
            println!("{}", format!("[*] Starting: {}", name).dimmed());
        }
        FindingEvent::ModuleEnd { name } => {
            println!("{}", format!("[*] Finished: {}", name).dimmed());
        }
        FindingEvent::Timeout { module } => {
            println!("{}", format!("[!] Timeout: {}", module).dimmed());
        }
        FindingEvent::NewSubdomain { host, status } => {
            if !seen_hosts.insert(host.clone()) { return; }
            println!("[+] subdomain: {} [{}]", host.green(), status);
        }
        FindingEvent::NewVhost { host, status, size } => {
            if !seen_hosts.insert(host.clone()) { return; }
            println!("[+] vhost: {} [{}] size={}", host.green(), status, size);
        }
        FindingEvent::LiveHost { host } => {
            let title = host.title.as_deref().unwrap_or("-");
            println!("[+] live: {} [{}] {}", host.final_url.green(), host.status, title);
        }
        FindingEvent::NewEndpoint { url, status, size, words, redirect_to } => {
            let colored_url = match status {
                200..=299 => url.green(),
                300..=399 => url.blue(),
                400..=499 => url.yellow(),
                _ => url.red(),
            };
            if let Some(loc) = redirect_to {
                println!("[+] endpoint: {} [{}] sz={} w={} -> {}", colored_url, status, size, words, loc);
            } else {
                println!("[+] endpoint: {} [{}] sz={} w={}", colored_url, status, size, words);
            }
        }
        FindingEvent::NewUrl { url, source } => {
            println!("[+] url: {} ({})", url.green(), source);
        }
        FindingEvent::SecretFound { url, pattern, snippet } => {
            println!("[!] secret: {} | {} | {}", pattern.red().bold(), url, snippet);
        }
        FindingEvent::TechDetected { host, tech, version } => {
            let ver = version.as_deref().unwrap_or("");
            if ver.is_empty() {
                println!("[~] tech: {} -> {}", host, tech.cyan());
            } else {
                println!("[~] tech: {} -> {} {}", host, tech.cyan(), ver);
            }
        }
        FindingEvent::HeaderAlert { host, severity, message } => {
            let colored_msg = match severity {
                Severity::High => message.red(),
                Severity::Medium => message.yellow(),
                Severity::Info => message.dimmed(),
            };
            println!("[!] header: {} | {}", host, colored_msg);
        }
        FindingEvent::Screenshot { host, url, path } => {
            let _ = host;
            println!("[+] screenshot: {} -> {}", url.green(), path.display());
        }
    }
}
