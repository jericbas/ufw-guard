//! Declarative system configuration (`/etc/ufw/ufw-guard.conf`) for ufw-guard.
//!
//! Zero-dependency `key = value` parser. Lines starting with `#` or `;` are comments,
//! values may be wrapped in double or single quotes. Precedence for tunables that also
//! have environment variables is: environment > config file > built-in default.

use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/ufw/ufw-guard.conf";
pub const CONFIG_PATH_ENV: &str = "UFW_GUARD_CONFIG";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Permit `--force-no-comment` / `UFW_GUARD_BYPASS`.
    pub allow_bypass: bool,
    pub min_comment_length: Option<usize>,
    pub comment_pattern: Option<String>,
    /// Require an audit comment on `ufw delete` (recorded in the audit log, not forwarded).
    pub require_comment_on_delete: bool,
    /// Append `[by: user @ date]` attribution to comments.
    pub auto_append_user: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            allow_bypass: true,
            min_comment_length: None,
            comment_pattern: None,
            require_comment_on_delete: false,
            auto_append_user: true,
        }
    }
}

pub fn resolve_config_path() -> PathBuf {
    env::var(CONFIG_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_CONFIG_PATH))
}

fn unquote(value: &str) -> &str {
    let v = value.trim();
    for q in ['"', '\''] {
        if v.len() >= 2 && v.starts_with(q) && v.ends_with(q) {
            return &v[1..v.len() - 1];
        }
    }
    v
}

fn parse_bool(key: &str, value: &str, line_no: usize) -> Result<bool, String> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Ok(true),
        "false" | "no" | "off" | "0" => Ok(false),
        _ => Err(format!(
            "line {}: invalid boolean '{}' for '{}' (expected true or false)",
            line_no, value, key
        )),
    }
}

/// Parse configuration text. Unknown keys and malformed values are errors (fail closed).
pub fn parse_config(text: &str) -> Result<Config, String> {
    let mut cfg = Config::default();
    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("line {}: expected 'key = value'", line_no))?;
        let key = key.trim();
        let value = unquote(value);
        match key {
            "allow_bypass" => cfg.allow_bypass = parse_bool(key, value, line_no)?,
            "require_comment_on_delete" => {
                cfg.require_comment_on_delete = parse_bool(key, value, line_no)?
            }
            "auto_append_user" => cfg.auto_append_user = parse_bool(key, value, line_no)?,
            "min_comment_length" => {
                cfg.min_comment_length = Some(value.parse::<usize>().map_err(|_| {
                    format!(
                        "line {}: invalid integer '{}' for 'min_comment_length'",
                        line_no, value
                    )
                })?)
            }
            "comment_pattern" => {
                cfg.comment_pattern = if value.is_empty() {
                    None
                } else {
                    Some(value.to_string())
                }
            }
            _ => return Err(format!("line {}: unknown setting '{}'", line_no, key)),
        }
    }
    Ok(cfg)
}

/// Load configuration; an absent file yields defaults, any other failure is an error.
pub fn load() -> Result<Config, String> {
    let path = resolve_config_path();
    match fs::read_to_string(&path) {
        Ok(text) => parse_config(&text).map_err(|e| format!("{}: {}", path.display(), e)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(Config::default()),
        Err(e) => Err(format!("cannot read {}: {}", path.display(), e)),
    }
}

/// Lenient loader for deep call sites; `enforce_policy` validates the file up front.
pub fn current() -> Config {
    load().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults_on_empty() {
        assert_eq!(parse_config("").unwrap(), Config::default());
        assert_eq!(
            parse_config("# only a comment\n\n").unwrap(),
            Config::default()
        );
    }

    #[test]
    fn test_full_config() {
        let cfg = parse_config(
            "allow_bypass = false\nmin_comment_length = 10\ncomment_pattern = \"^JIRA-[0-9]+\"\n\
             require_comment_on_delete = true  \nauto_append_user = false\n",
        )
        .unwrap();
        assert!(!cfg.allow_bypass);
        assert_eq!(cfg.min_comment_length, Some(10));
        assert_eq!(cfg.comment_pattern.as_deref(), Some("^JIRA-[0-9]+"));
        assert!(cfg.require_comment_on_delete);
        assert!(!cfg.auto_append_user);
    }

    #[test]
    fn test_pattern_with_equals_and_single_quotes() {
        let cfg = parse_config("comment_pattern = 'a=b'").unwrap();
        assert_eq!(cfg.comment_pattern.as_deref(), Some("a=b"));
    }

    #[test]
    fn test_errors() {
        assert!(parse_config("allow_bypass = maybe").is_err());
        assert!(parse_config("min_comment_length = -1").is_err());
        assert!(parse_config("bogus = 1").is_err());
        assert!(parse_config("no equals here").is_err());
    }
}
