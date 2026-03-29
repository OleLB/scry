use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use tokio::task::JoinSet;

use crate::config::Config;
use crate::events::{FindingEvent, Sender};
use crate::modules::{eyewitness, feroxbuster, ffuf_subdomains, ffuf_vhosts, httpx, js_scanner, katana, whatweb};
use crate::store::SharedStore;
use crate::wordlist;

macro_rules! with_timeout {
    ($name:expr, $timeout:expr, $tx:expr, $fut:expr) => {{
        $tx.send(FindingEvent::ModuleStart { name: $name.into() }).ok();
        match tokio::time::timeout(Duration::from_secs($timeout), $fut).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => eprintln!("[{}] error: {}", $name, e),
            Err(_) => {
                $tx.send(FindingEvent::Timeout { module: $name.into() }).ok();
            }
        }
        $tx.send(FindingEvent::ModuleEnd { name: $name.into() }).ok();
    }};
}

pub async fn run(
    config: Arc<Config>,
    store: SharedStore,
    tx: Sender,
    cancel: Arc<AtomicBool>,
    skip_ferox: Arc<AtomicBool>,
) {
    let timeout = config.module_timeout;

    // ── Phase 1: Passive recon ────────────────────────────────────────────────
    {
        let mut set: JoinSet<()> = JoinSet::new();

        if !config.should_skip("ffuf_subdomains") {
            let cfg = config.clone();
            let tx2 = tx.clone();
            set.spawn(async move {
                with_timeout!("ffuf_subdomains", 180, tx2, ffuf_subdomains::run(&cfg, &tx2));
            });
        }

        if !config.should_skip("ffuf_vhosts") {
            let cfg = config.clone();
            let tx2 = tx.clone();
            set.spawn(async move {
                with_timeout!("ffuf_vhosts", 120, tx2, ffuf_vhosts::run(&cfg, &tx2));
            });
        }

        while set.join_next().await.is_some() {}
    }

    if cancel.load(Ordering::Relaxed) {
        return;
    }

    // httpx runs after ffuf (needs subdomain list)
    if !config.should_skip("httpx") {
        let cfg = config.clone();
        let store2 = store.clone();
        let tx2 = tx.clone();
        with_timeout!("httpx", timeout, tx2, httpx::run(&cfg, &store2, &tx2));
    }

    if cancel.load(Ordering::Relaxed) {
        return;
    }

    // ── Phase 2: Active discovery ─────────────────────────────────────────────
    let live_urls: Vec<String> = {
        let s = store.lock().await;
        s.live_hosts.iter().map(|h| h.final_url.clone()).collect()
    };

    {
        let mut set: JoinSet<()> = JoinSet::new();

        for target_url in &live_urls {
            if !config.should_skip("katana") {
                let cfg = config.clone();
                let tx2 = tx.clone();
                let url = target_url.clone();
                set.spawn(async move {
                    with_timeout!("katana", 120, tx2, katana::run(&cfg, &url, &tx2));
                });
            }
        }

        while set.join_next().await.is_some() {}
    }

    if cancel.load(Ordering::Relaxed) {
        return;
    }

    // Build augmented wordlist from katana discoveries, then run feroxbuster
    if !config.should_skip("feroxbuster") && !live_urls.is_empty() {
        let discovered_urls: Vec<String> = {
            let s = store.lock().await;
            s.urls.iter().map(|u| u.url.clone()).collect()
        };

        // Collect detected tech names so CMS-specific wordlists can be added
        let detected_techs: Vec<String> = {
            let s = store.lock().await;
            s.technologies.iter().map(|t| t.tech.clone()).collect()
        };

        let extra_wordlists = if config.wordlist.is_none() {
            // CMS/tech-specific wordlists first, then the broad combined list
            let mut lists = wordlist::seclists_cms_wordlists(&config.seclists_base, &detected_techs);
            lists.extend(wordlist::seclists_web_wordlists(&config.seclists_base));
            lists
        } else {
            vec![]
        };

        match wordlist::build_wordlist(config.wordlist.as_deref(), &extra_wordlists, &discovered_urls).await {
            Ok(wordlist_file) => {
                let mut set: JoinSet<()> = JoinSet::new();
                for target_url in &live_urls {
                    let cfg = config.clone();
                    let tx2 = tx.clone();
                    let url = target_url.clone();
                    let wl_path = wordlist_file.path().to_path_buf();
                    let techs = detected_techs.clone();
                    let sf = skip_ferox.clone();
                    set.spawn(async move {
                        with_timeout!(
                            "feroxbuster",
                            7200,
                            tx2,
                            feroxbuster::run(&cfg, &url, &wl_path, &techs, &sf, &tx2)
                        );
                    });
                }
                while set.join_next().await.is_some() {}
                // wordlist_file drops here, auto-deleting the tempfile
            }
            Err(e) => eprintln!("[wordlist] error building augmented wordlist: {}", e),
        }
    }

    if cancel.load(Ordering::Relaxed) {
        return;
    }

    // ── Phase 3: Deep analysis ────────────────────────────────────────────────
    let js_urls: Vec<String> = {
        let s = store.lock().await;
        s.js_urls.clone()
    };

    {
        let mut set: JoinSet<()> = JoinSet::new();

        // JS scanner
        if !config.should_skip("js_scanner") && !js_urls.is_empty() {
            let tx2 = tx.clone();
            let urls = js_urls.clone();
            set.spawn(async move {
                with_timeout!("js_scanner", 120, tx2, js_scanner::run(urls, &tx2));
            });
        }

        // WhatWeb — one task per live host
        if !config.should_skip("whatweb") {
            for target_url in &live_urls {
                let cfg = config.clone();
                let tx2 = tx.clone();
                let url = target_url.clone();
                set.spawn(async move {
                    with_timeout!("whatweb", 30, tx2, whatweb::run(&cfg, &url, &tx2));
                });
            }
        }

        // EyeWitness — screenshot live hosts + all 2xx/3xx endpoints
        if !config.should_skip("eyewitness") {
            let endpoint_urls: Vec<String> = {
                let s = store.lock().await;
                s.endpoints.iter()
                    .filter(|e| e.status < 400)
                    .map(|e| e.url.clone())
                    .collect()
            };
            // Merge live_urls first, then endpoint URLs; deduplicate preserving order
            let mut seen = std::collections::HashSet::new();
            let mut all_urls: Vec<String> = Vec::new();
            for url in live_urls.iter().chain(endpoint_urls.iter()) {
                if seen.insert(url.clone()) {
                    all_urls.push(url.clone());
                }
            }
            let cfg = config.clone();
            let tx2 = tx.clone();
            set.spawn(async move {
                with_timeout!("eyewitness", 3600, tx2, eyewitness::run(&cfg, &all_urls, &tx2));
            });
        }

        while set.join_next().await.is_some() {}
    }
}
