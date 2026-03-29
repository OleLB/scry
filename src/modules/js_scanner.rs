use regex::{Regex, RegexSet};

use crate::events::{FindingEvent, Sender};

pub const PATTERNS: &[(&str, &str)] = &[
    // Patterns ported from js_regex.py (SecretFinder project)
    ("google_api",                    r"AIza[0-9A-Za-z-_]{35}"),
    ("firebase",                      r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"),
    ("google_captcha",                r"6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$"),
    ("google_oauth",                  r"ya29\.[0-9A-Za-z\-_]+"),
    ("amazon_aws_access_key_id",      r"A[SK]IA[0-9A-Z]{16}"),
    ("amazon_mws_auth_token",         r"amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    ("amazon_aws_url",                r"s3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com"),
    ("amazon_aws_url2",               r"([a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9-\.\_]+|s3-[a-zA-Z0-9-\.\_\/]+|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)"),
    ("facebook_access_token",         r"EAACEdEose0cBA[0-9A-Za-z]+"),
    ("authorization_basic",           r"basic [a-zA-Z0-9=:_\+\/-]{5,100}"),
    ("authorization_bearer",          r"bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}"),
    ("authorization_api",             r"api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}"),
    ("mailgun_api_key",               r"key-[0-9a-zA-Z]{32}"),
    ("twilio_api_key",                r"SK[0-9a-fA-F]{32}"),
    ("twilio_account_sid",            r"AC[a-zA-Z0-9_\-]{32}"),
    ("twilio_app_sid",                r"AP[a-zA-Z0-9_\-]{32}"),
    ("paypal_braintree_access_token", r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),
    ("square_oauth_secret",           r"sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}"),
    ("square_access_token",           r"sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}"),
    ("stripe_standard_api",           r"sk_live_[0-9a-zA-Z]{24}"),
    ("stripe_restricted_api",         r"rk_live_[0-9a-zA-Z]{24}"),
    ("github_access_token",           r"[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*"),
    ("rsa_private_key",               r"-----BEGIN RSA PRIVATE KEY-----"),
    ("ssh_dsa_private_key",           r"-----BEGIN DSA PRIVATE KEY-----"),
    ("ssh_ec_private_key",            r"-----BEGIN EC PRIVATE KEY-----"),
    ("pgp_private_block",             r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
    // $-anchor removed so it matches anywhere in multi-line JS content
    ("json_web_token",                r"ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"),
    // Rust raw string r#"..."# used because the pattern contains double-quote characters
    ("slack_token",                   r#""api_token":"(xox[a-zA-Z]-[a-zA-Z0-9-]+)""#),
    ("SSH_privKey",                   r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)"),
    ("heroku_api_key",                r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
    // Rust raw string r#"..."# used because the pattern contains double-quote and backtick characters
    ("possible_creds",                r#"(?i)(password\s*[`=:"]+\s*[^\s]+|password is\s*[`=:"]*\s*[^\s]+|pwd\s*[`=:"]*\s*[^\s]+|passwd\s*[`=:"]+\s*[^\s]+)"#),
];

pub struct JsScanner {
    set: RegexSet,
    patterns: Vec<(String, Regex)>,
}

impl JsScanner {
    pub fn new() -> Self {
        let pattern_strings: Vec<&str> = PATTERNS.iter().map(|(_, p)| *p).collect();
        let set = RegexSet::new(&pattern_strings).expect("JS scanner RegexSet compile");
        let patterns = PATTERNS
            .iter()
            .map(|(name, pat)| {
                (
                    name.to_string(),
                    Regex::new(pat).expect("JS scanner Regex compile"),
                )
            })
            .collect();
        JsScanner { set, patterns }
    }

    pub async fn scan_url(&self, url: &str, tx: &Sender) {
        let client = match reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(10))
            .build()
        {
            Ok(c) => c,
            Err(_) => return,
        };

        let content = match client.get(url).send().await {
            Ok(resp) => match resp.text().await {
                Ok(t) => t,
                Err(_) => return,
            },
            Err(_) => return,
        };

        let matches = self.set.matches(&content);
        for idx in matches.iter() {
            let (name, re) = &self.patterns[idx];
            if let Some(m) = re.find(&content) {
                let snippet = redact(m.as_str());
                tx.send(FindingEvent::SecretFound {
                    url: url.to_string(),
                    pattern: name.clone(),
                    snippet,
                })
                .ok();
            }
        }
    }
}

fn redact(matched: &str) -> String {
    if matched.len() <= 12 {
        return "*".repeat(matched.len());
    }
    let visible = &matched[..6];
    let tail = &matched[matched.len() - 4..];
    format!("{}...{}", visible, tail)
}

pub async fn run(js_urls: Vec<String>, tx: &Sender) -> anyhow::Result<()> {
    let scanner = JsScanner::new();
    for url in &js_urls {
        scanner.scan_url(url, tx).await;
    }
    Ok(())
}
