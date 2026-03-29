use std::collections::HashMap;
use std::path::PathBuf;

/// Maps a tool name (e.g. "whatweb") to its custom command string
/// (e.g. "ruby /opt/tools/WhatWeb/whatweb").
pub type ToolPaths = HashMap<String, String>;

fn config_file_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("scry").join("scry.conf"))
}

/// Load `~/.config/scry/scry.conf`. Returns an empty map if the file is absent.
///
/// Supported line formats:
/// ```
/// # comment
/// whatweb='/usr/local/rvm/gems/ruby-3.2.2@whatweb/wrappers/ruby /opt/tools/WhatWeb/whatweb'
/// EyeWitness.py="/path/to/EyeWitness.py"
/// httpx=/usr/local/bin/httpx
/// ```
pub fn load() -> ToolPaths {
    let path = match config_file_path() {
        Some(p) => p,
        None => return ToolPaths::new(),
    };
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return ToolPaths::new(),
    };
    let mut map = ToolPaths::new();
    for (i, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(eq) = line.find('=') else {
            eprintln!("[scry.conf:{}] skipping malformed line (no '='): {}", i + 1, line);
            continue;
        };
        let key = line[..eq].trim().to_string();
        let raw = line[eq + 1..].trim();
        // Strip one layer of surrounding single or double quotes
        let value = if (raw.starts_with('\'') && raw.ends_with('\''))
            || (raw.starts_with('"') && raw.ends_with('"'))
        {
            raw[1..raw.len() - 1].to_string()
        } else {
            raw.to_string()
        };
        if !key.is_empty() && !value.is_empty() {
            map.insert(key, value);
        }
    }
    map
}

/// Build a `tokio::process::Command` for `tool_name`.
///
/// If `tool_paths` has an entry for `tool_name`, the stored string is split on
/// the first space: the first token becomes the program, the remainder is
/// prepended as a single argument (the interpreter-script pattern).
///
/// The caller then chains `.args([...])` for tool-specific flags as usual.
///
/// Example — stored value: `"ruby /opt/tools/WhatWeb/whatweb"`
/// → `Command::new("ruby").arg("/opt/tools/WhatWeb/whatweb").args([...])`
pub fn make_command(tool_name: &str, tool_paths: &ToolPaths) -> tokio::process::Command {
    match tool_paths.get(tool_name) {
        Some(cmd_str) => {
            let parts: Vec<&str> = cmd_str.splitn(2, ' ').collect();
            match parts.as_slice() {
                [program, rest] => {
                    let mut cmd = tokio::process::Command::new(program);
                    cmd.arg(rest);
                    cmd
                }
                [program] => tokio::process::Command::new(program),
                _ => tokio::process::Command::new(tool_name),
            }
        }
        None => tokio::process::Command::new(tool_name),
    }
}

/// Returns the effective binary name/path to check with `which` for a given tool.
///
/// If a custom path is configured, returns the first whitespace-delimited token
/// (the interpreter or direct binary). Otherwise returns `tool_name` unchanged.
pub fn effective_program<'a>(tool_name: &'a str, tool_paths: &'a ToolPaths) -> &'a str {
    match tool_paths.get(tool_name) {
        Some(cmd_str) => cmd_str.split_ascii_whitespace().next().unwrap_or(tool_name),
        None => tool_name,
    }
}
