use std::path::PathBuf;
use std::time::SystemTime;

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::Serialize;
use tera::{Context, Tera};

use crate::config::Config;
use crate::events::Severity;
use crate::store::FindingStore;

const TEMPLATE: &str = include_str!("template.html");

// Serialisable mirror types for Tera

#[derive(Serialize)]
struct LiveHostView {
    final_url: String,
    status: u16,
    title: Option<String>,
    server: Option<String>,
    content_length: Option<u64>,
}

#[derive(Serialize)]
struct SubdomainView {
    host: String,
    status: u16,
}

#[derive(Serialize)]
struct VhostView {
    host: String,
    status: u16,
    size: u64,
}

#[derive(Serialize)]
struct EndpointView {
    url: String,
    status: u16,
    size: u64,
    words: u64,
    redirect_to: Option<String>,
}

#[derive(Serialize)]
struct SecretView {
    url: String,
    pattern: String,
    snippet: String,
}

#[derive(Serialize)]
struct TechView {
    host: String,
    tech: String,
    version: Option<String>,
}

#[derive(Serialize)]
struct HeaderAlertView {
    host: String,
    severity: String,
    message: String,
}

#[derive(Serialize)]
struct ScreenshotView {
    host: String,
    url: String,
    data_uri: String,
}

#[derive(Serialize)]
struct UrlView {
    url: String,
    source: String,
}

pub fn generate(store: &FindingStore, config: &Config) -> anyhow::Result<PathBuf> {
    let output_path = config.output.clone().unwrap_or_else(|| {
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        PathBuf::from(format!("recon_{}_{}.html", config.target, ts))
    });

    let scan_date = {
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        format_unix_ts(ts)
    };

    // Build views
    let live_hosts: Vec<LiveHostView> = store
        .live_hosts
        .iter()
        .map(|h| LiveHostView {
            final_url: h.final_url.clone(),
            status: h.status,
            title: h.title.clone(),
            server: h.server.clone(),
            content_length: h.content_length,
        })
        .collect();

    let subdomains: Vec<SubdomainView> = store
        .subdomains
        .iter()
        .map(|s| SubdomainView { host: s.host.clone(), status: s.status })
        .collect();

    let vhosts: Vec<VhostView> = store
        .vhosts
        .iter()
        .map(|v| VhostView { host: v.host.clone(), status: v.status, size: v.size })
        .collect();

    let mk_endpoint = |e: &crate::store::EndpointFinding| EndpointView {
        url: e.url.clone(),
        status: e.status,
        size: e.size,
        words: e.words,
        redirect_to: e.redirect_to.clone(),
    };
    let ok_endpoints: Vec<EndpointView> = store.endpoints.iter()
        .filter(|e| e.status < 400)
        .map(mk_endpoint)
        .collect();
    let forbidden_endpoints: Vec<EndpointView> = store.endpoints.iter()
        .filter(|e| (400..500).contains(&e.status))
        .map(mk_endpoint)
        .collect();
    let broken_endpoints: Vec<EndpointView> = store.endpoints.iter()
        .filter(|e| e.status >= 500)
        .map(mk_endpoint)
        .collect();

    let secrets: Vec<SecretView> = store
        .secrets
        .iter()
        .map(|s| SecretView {
            url: s.url.clone(),
            pattern: s.pattern.clone(),
            snippet: s.snippet.clone(),
        })
        .collect();

    let technologies: Vec<TechView> = store
        .technologies
        .iter()
        .map(|t| TechView {
            host: t.host.clone(),
            tech: t.tech.clone(),
            version: t.version.clone(),
        })
        .collect();

    let header_alerts: Vec<HeaderAlertView> = store
        .header_alerts
        .iter()
        .map(|a| HeaderAlertView {
            host: a.host.clone(),
            severity: severity_str(&a.severity).to_string(),
            message: a.message.clone(),
        })
        .collect();

    let screenshots: Vec<ScreenshotView> = store
        .screenshots
        .iter()
        .filter_map(|s| {
            let bytes = std::fs::read(&s.path).ok()?;
            let data_uri = format!("data:image/png;base64,{}", B64.encode(&bytes));
            Some(ScreenshotView { host: s.host.clone(), url: s.url.clone(), data_uri })
        })
        .collect();

    let urls: Vec<UrlView> = store
        .urls
        .iter()
        .map(|u| UrlView { url: u.url.clone(), source: u.source.clone() })
        .collect();

    // Build context
    let mut ctx = Context::new();
    ctx.insert("target", &config.target);
    ctx.insert("port", &config.port);
    ctx.insert("scan_date", &scan_date);
    ctx.insert("live_hosts", &live_hosts);
    ctx.insert("subdomains", &subdomains);
    ctx.insert("vhosts", &vhosts);
    ctx.insert("ok_endpoints", &ok_endpoints);
    ctx.insert("forbidden_endpoints", &forbidden_endpoints);
    ctx.insert("broken_endpoints", &broken_endpoints);
    ctx.insert("secrets", &secrets);
    ctx.insert("technologies", &technologies);
    ctx.insert("header_alerts", &header_alerts);
    ctx.insert("screenshots", &screenshots);
    ctx.insert("urls", &urls);
    ctx.insert("timeouts", &store.timeouts);

    let html = Tera::one_off(TEMPLATE, &ctx, false)?;
    std::fs::write(&output_path, html)?;
    Ok(output_path)
}

fn severity_str(s: &Severity) -> &'static str {
    match s {
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Info => "Info",
    }
}

fn format_unix_ts(ts: u64) -> String {
    // Simple ISO-like formatting without external deps
    let secs = ts;
    let mins = secs / 60;
    let hours = mins / 60;
    let days = hours / 24;
    // Approximate date from epoch — just show unix timestamp for simplicity
    // A proper impl would use chrono, but we're keeping deps minimal
    format!("Unix epoch +{}d {}h {}m", days, hours % 24, mins % 60)
}
