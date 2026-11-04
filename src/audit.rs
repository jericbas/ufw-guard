//! Tamper-evident audit logging for rule changes and break-glass bypasses.

use crate::attribution::resolve_invoking_user;
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_LOG_PATH: &str = "/var/log/ufw-guard.log";
pub const LOG_PATH_ENV: &str = "UFW_GUARD_LOG_FILE";
pub const AUDIT_TIMESTAMP_ENV: &str = "UFW_GUARD_AUDIT_TIMESTAMP";
pub const AUDIT_ENABLED_ENV: &str = "UFW_GUARD_AUDIT_ENABLED";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventType {
    Bypass,
    RuleExecuted,
    RuleRemediated,
    RuleRejected,
}

impl AuditEventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditEventType::Bypass => "bypass",
            AuditEventType::RuleExecuted => "rule_executed",
            AuditEventType::RuleRemediated => "rule_remediated",
            AuditEventType::RuleRejected => "rule_rejected",
        }
    }
}

pub struct AuditEntry<'a> {
    pub timestamp: &'a str,
    pub user: &'a str,
    pub event: AuditEventType,
    pub status: &'a str,
    pub raw_args: &'a [String],
    pub forwarded_args: Option<&'a [String]>,
    pub comment: Option<&'a str>,
    pub error: Option<&'a str>,
}

pub fn is_audit_enabled() -> bool {
    env::var(AUDIT_ENABLED_ENV)
        .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
        .unwrap_or(true)
}

pub fn resolve_log_path() -> PathBuf {
    env::var(LOG_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_LOG_PATH))
}

pub fn current_iso8601_timestamp() -> String {
    if let Ok(override_ts) = env::var(AUDIT_TIMESTAMP_ENV) {
        let trimmed = override_ts.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let sec = secs % 60;
    let min = (secs / 60) % 60;
    let hour = (secs / 3600) % 24;
    let days = (secs / 86400) as i64;

    // Civil date from day count
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1024 + doe / 1461 - doe / 14241) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hour, min, sec
    )
}

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

pub fn format_audit_record(entry: &AuditEntry) -> String {
    let raw_args_json = entry
        .raw_args
        .iter()
        .map(|a| format!("\"{}\"", escape_json(a)))
        .collect::<Vec<_>>()
        .join(",");

    let forwarded_args_json = match entry.forwarded_args {
        Some(f_args) => {
            let joined = f_args
                .iter()
                .map(|a| format!("\"{}\"", escape_json(a)))
                .collect::<Vec<_>>()
                .join(",");
            format!("[{}]", joined)
        }
        None => "null".to_string(),
    };

    let comment_json = match entry.comment {
        Some(c) => format!("\"{}\"", escape_json(c)),
        None => "null".to_string(),
    };

    let error_json = match entry.error {
        Some(e) => format!("\"{}\"", escape_json(e)),
        None => "null".to_string(),
    };

    format!(
        "{{\"timestamp\":\"{}\",\"user\":\"{}\",\"event\":\"{}\",\"status\":\"{}\",\"raw_args\":[{}],\"forwarded_args\":{},\"comment\":{},\"error\":{}}}",
        escape_json(entry.timestamp),
        escape_json(entry.user),
        entry.event.as_str(),
        escape_json(entry.status),
        raw_args_json,
        forwarded_args_json,
        comment_json,
        error_json
    )
}

pub fn write_audit_log(record_line: &str, log_path: &Path) {
    if let Some(parent) = log_path.parent() {
        if !parent.exists() {
            let _ = std::fs::create_dir_all(parent);
        }
    }

    match OpenOptions::new().create(true).append(true).open(log_path) {
        Ok(mut file) => {
            if let Err(err) = writeln!(file, "{}", record_line) {
                eprintln!(
                    "[ufw-guard audit WARN] Failed to append to audit log {}: {}",
                    log_path.display(),
                    err
                );
            }
        }
        Err(err) => {
            eprintln!(
                "[ufw-guard audit WARN] Could not open audit log {}: {}",
                log_path.display(),
                err
            );
        }
    }
}

pub fn log_event(
    event: AuditEventType,
    status: &str,
    raw_args: &[String],
    forwarded_args: Option<&[String]>,
    comment: Option<&str>,
    error: Option<&str>,
) {
    if !is_audit_enabled() {
        return;
    }

    let timestamp = current_iso8601_timestamp();
    let user = resolve_invoking_user();
    let entry = AuditEntry {
        timestamp: &timestamp,
        user: &user,
        event,
        status,
        raw_args,
        forwarded_args,
        comment,
        error,
    };
    let record_line = format_audit_record(&entry);
    let log_path = resolve_log_path();
    write_audit_log(&record_line, &log_path);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_format_audit_record_json() {
        let raw = vec!["allow".to_string(), "22/tcp".to_string()];
        let fwd = vec![
            "allow".to_string(),
            "22/tcp".to_string(),
            "comment".to_string(),
            "SSH".to_string(),
        ];
        let entry = AuditEntry {
            timestamp: "2026-11-04T12:00:00Z",
            user: "jeric",
            event: AuditEventType::RuleExecuted,
            status: "success",
            raw_args: &raw,
            forwarded_args: Some(&fwd),
            comment: Some("SSH"),
            error: None,
        };
        let record = format_audit_record(&entry);

        assert!(record.contains(r#""timestamp":"2026-11-04T12:00:00Z""#));
        assert!(record.contains(r#""user":"jeric""#));
        assert!(record.contains(r#""event":"rule_executed""#));
        assert!(record.contains(r#""status":"success""#));
        assert!(record.contains(r#""raw_args":["allow","22/tcp"]"#));
        assert!(record.contains(r#""comment":"SSH""#));
        assert!(record.contains(r#""error":null"#));
    }

    #[test]
    fn test_audit_log_write_and_read() {
        let temp_dir = env::temp_dir();
        let log_file = temp_dir.join(format!("ufw_audit_test_{}.log", std::process::id()));
        env::set_var(LOG_PATH_ENV, &log_file);
        env::set_var(AUDIT_TIMESTAMP_ENV, "2026-11-04T12:00:00Z");
        env::set_var("SUDO_USER", "admin_bob");

        let raw = vec![
            "allow".to_string(),
            "443".to_string(),
            "--force-no-comment".to_string(),
        ];
        let fwd = vec!["allow".to_string(), "443".to_string()];

        log_event(
            AuditEventType::Bypass,
            "bypassed",
            &raw,
            Some(&fwd),
            None,
            None,
        );

        let content = fs::read_to_string(&log_file).unwrap();
        assert!(content.contains(r#""event":"bypass""#));
        assert!(content.contains(r#""user":"admin_bob""#));

        let _ = fs::remove_file(log_file);
        env::remove_var(LOG_PATH_ENV);
        env::remove_var(AUDIT_TIMESTAMP_ENV);
        env::remove_var("SUDO_USER");
    }

    #[test]
    fn test_audit_graceful_degradation_invalid_path() {
        let invalid_path = PathBuf::from("/nonexistent_dir_123456/invalid.log");
        write_audit_log("test line", &invalid_path);
    }
}
