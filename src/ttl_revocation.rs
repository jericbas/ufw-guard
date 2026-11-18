//! Safe command construction and stale-rule checks for TTL expiration.

use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub const EXPIRATION_FLAG: &str = "--expire-rule";

pub fn marker() -> String {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{}-{}", std::process::id(), nonce)
}

pub fn revocation_args(args: &[String]) -> Result<Vec<String>, String> {
    let mut rule = Vec::with_capacity(args.len());
    let mut index = 0;
    while index < args.len() {
        if args[index].eq_ignore_ascii_case("comment") {
            index += 2;
        } else if args[index] == "--force-no-comment" {
            index += 1;
        } else {
            rule.push(args[index].clone());
            index += 1;
        }
    }
    let route = rule.first().is_some_and(|word| word == "route");
    if route {
        rule.remove(0);
    }
    if rule.first().is_some_and(|word| word == "insert") {
        rule.remove(0);
        if rule.first().is_some_and(|word| word.parse::<u32>().is_ok()) {
            rule.remove(0);
        }
    } else if rule.first().is_some_and(|word| word == "prepend") {
        rule.remove(0);
    }
    if rule.is_empty() {
        return Err("cannot generate a TTL revocation command for this rule".to_string());
    }
    let mut revoke = Vec::with_capacity(rule.len() + 2);
    if route {
        revoke.push("route".to_string());
    }
    revoke.push("delete".to_string());
    revoke.extend(rule);
    Ok(revoke)
}

pub fn systemd_run_arguments(
    ttl: &str,
    wrapper: &Path,
    marker: &str,
    upstream: &Path,
    revoke: &[String],
) -> Vec<String> {
    let mut args = vec![format!("--on-active={ttl}"), "--".to_string()];
    args.push(wrapper.to_string_lossy().into_owned());
    args.push(EXPIRATION_FLAG.to_string());
    args.push(marker.to_string());
    args.push(upstream.to_string_lossy().into_owned());
    args.extend(revoke.iter().cloned());
    args
}

pub fn marker_is_active(upstream: &Path, marker: &str) -> Result<bool, String> {
    let output = Command::new(upstream)
        .args(["show", "added"])
        .output()
        .map_err(|e| format!("cannot check expiring UFW rule: {}", e))?;
    if !output.status.success() {
        return Err(format!(
            "cannot check expiring UFW rule: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).contains(marker))
}
