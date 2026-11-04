//! Automatic metadata attribution in rule comments for ufw-guard.

use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

pub const AUTO_ATTRIBUTION_ENV: &str = "UFW_GUARD_AUTO_ATTRIBUTION";
pub const ATTRIBUTION_DATE_ENV: &str = "UFW_GUARD_ATTRIBUTION_DATE";

pub fn is_attribution_enabled() -> bool {
    env::var(AUTO_ATTRIBUTION_ENV)
        .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
        .unwrap_or(true)
}

pub fn resolve_invoking_user() -> String {
    if let Ok(sudo_user) = env::var("SUDO_USER") {
        let trimmed = sudo_user.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    if let Ok(user) = env::var("USER") {
        let trimmed = user.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    if let Ok(logname) = env::var("LOGNAME") {
        let trimmed = logname.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    "root".to_string()
}

pub fn current_utc_date() -> String {
    if let Ok(override_date) = env::var(ATTRIBUTION_DATE_ENV) {
        let trimmed = override_date.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let days = (secs / 86400) as i64;
    // Civil date from day count (Howard Hinnant algorithm)
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

    format!("{:04}-{:02}-{:02}", y, m, d)
}

pub fn has_attribution(comment: &str) -> bool {
    comment.contains("[by: ")
}

pub fn enrich_comment(base_comment: &str) -> String {
    let trimmed = base_comment.trim();
    if !is_attribution_enabled() || has_attribution(trimmed) {
        return trimmed.to_string();
    }

    let user = resolve_invoking_user();
    let date = current_utc_date();
    format!("{} [by: {} @ {}]", trimmed, user, date)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_invoking_user_sudo() {
        env::set_var("SUDO_USER", "admin_jeric");
        env::set_var("USER", "root");
        assert_eq!(resolve_invoking_user(), "admin_jeric");
        env::remove_var("SUDO_USER");
        env::remove_var("USER");
    }

    #[test]
    fn test_resolve_invoking_user_fallback() {
        env::remove_var("SUDO_USER");
        env::set_var("USER", "deploy_agent");
        assert_eq!(resolve_invoking_user(), "deploy_agent");
        env::remove_var("USER");
    }

    #[test]
    fn test_enrich_comment_standard() {
        env::set_var("SUDO_USER", "jeric");
        env::set_var(ATTRIBUTION_DATE_ENV, "2026-11-04");
        env::remove_var(AUTO_ATTRIBUTION_ENV);

        let enriched = enrich_comment("Allow SSH ingress");
        assert_eq!(enriched, "Allow SSH ingress [by: jeric @ 2026-11-04]");

        env::remove_var("SUDO_USER");
        env::remove_var(ATTRIBUTION_DATE_ENV);
    }

    #[test]
    fn test_enrich_comment_idempotent() {
        env::set_var("SUDO_USER", "jeric");
        env::set_var(ATTRIBUTION_DATE_ENV, "2026-11-04");

        let already_enriched = "Allow SSH ingress [by: alice @ 2026-10-01]";
        assert_eq!(enrich_comment(already_enriched), already_enriched);

        env::remove_var("SUDO_USER");
        env::remove_var(ATTRIBUTION_DATE_ENV);
    }

    #[test]
    fn test_enrich_comment_disabled() {
        env::set_var(AUTO_ATTRIBUTION_ENV, "0");
        let base = "Allow Prometheus metrics";
        assert_eq!(enrich_comment(base), base);
        env::remove_var(AUTO_ATTRIBUTION_ENV);
    }
}
