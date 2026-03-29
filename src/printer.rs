use colored::Colorize;
use tokio::sync::broadcast::error::RecvError;

use crate::events::{FindingEvent, Receiver, Severity};

pub async fn run_printer(mut rx: Receiver) {
    loop {
        match rx.recv().await {
            Ok(event) => print_event(&event),
            Err(RecvError::Lagged(n)) => {
                eprintln!("{}", format!("[printer] lagged, dropped {} events", n).dimmed());
            }
            Err(RecvError::Closed) => break,
        }
    }
}

fn print_event(event: &FindingEvent) {
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
            println!("{}", format!("[+] Subdomain  {} [{}]", host, status).green());
        }
        FindingEvent::NewVhost { host, status, size } => {
            println!("{}", format!("[+] VHost      {} [{}] size={}", host, status, size).green());
        }
        FindingEvent::LiveHost { host } => {
            let title = host.title.as_deref().unwrap_or("-");
            println!(
                "{}",
                format!("[+] Live       {} [{}] {}", host.final_url, host.status, title).green()
            );
        }
        FindingEvent::NewEndpoint { url, status, size, words, redirect_to } => {
            let mut line = format!("[+] Endpoint   {} [{}] sz={} w={}", url, status, size, words);
            if let Some(loc) = redirect_to {
                line.push_str(&format!(" -> {}", loc));
            }
            let colored = match status {
                200..=299 => line.green(),
                300..=399 => line.blue(),
                400..=499 => line.yellow(),
                _ => line.red(),
            };
            println!("{}", colored);
        }
        FindingEvent::NewUrl { url, source } => {
            println!("{}", format!("[+] URL        {} ({})", url, source).green());
        }
        FindingEvent::SecretFound { url, pattern, snippet } => {
            println!(
                "{}",
                format!("[!] SECRET     {} | {} | {}", pattern, url, snippet).red().bold()
            );
        }
        FindingEvent::TechDetected { host, tech, version } => {
            let ver = version.as_deref().unwrap_or("");
            if ver.is_empty() {
                println!("{}", format!("[~] Tech       {} -> {}", host, tech).cyan());
            } else {
                println!("{}", format!("[~] Tech       {} -> {} {}", host, tech, ver).cyan());
            }
        }
        FindingEvent::HeaderAlert { host, severity, message } => {
            let line = format!("[!] Header     {} | {}", host, message);
            let colored = match severity {
                Severity::High => line.red(),
                Severity::Medium => line.yellow(),
                Severity::Info => line.dimmed(),
            };
            println!("{}", colored);
        }
        FindingEvent::Screenshot { host, url, path } => {
            let _ = host;
            println!(
                "{}",
                format!("[+] Screenshot {} -> {}", url, path.display()).green()
            );
        }
    }
}
