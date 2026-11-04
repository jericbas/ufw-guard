//! Policy engine combining argument classification, quality enforcement, and interactive remediation.

use crate::args::{
    classify_arguments_with, extract_comment, is_delete_command, replace_or_inject_comment,
    strip_bypass_flag, strip_comment, CommandClassification,
};
use crate::attribution::enrich_comment;
use crate::audit::{log_event, AuditEventType};
use crate::config::{self, Config};
use crate::prompt::{is_interactive, resolve_missing_comment};
use crate::quality::validate_comment;

/// Enforce `require_comment_on_delete`: the comment is recorded in the audit log and
/// stripped, because upstream `ufw delete` matches rules by specification only.
fn enforce_delete_comment(raw_args: &[String]) -> Result<Vec<String>, String> {
    let comment = match extract_comment(raw_args) {
        Some(c) => match validate_comment(&c) {
            Ok(()) => Ok(c),
            Err(v) if is_interactive() => {
                eprintln!("ufw-guard: {}", v);
                resolve_missing_comment()
            }
            Err(v) => Err(format!("Delete comment violates governance policy: {}", v)),
        },
        None if is_interactive() => resolve_missing_comment(),
        None => Err(
            "Deleting a firewall rule requires `comment \"<reason>\"` (require_comment_on_delete = true)."
                .to_string(),
        ),
    };
    match comment {
        Ok(c) => {
            let enriched = enrich_comment(&c);
            let forwarded = strip_comment(&strip_bypass_flag(raw_args).0);
            log_event(
                AuditEventType::RuleExecuted,
                "success",
                raw_args,
                Some(&forwarded),
                Some(&enriched),
                None,
            );
            Ok(forwarded)
        }
        Err(e) => {
            log_event(
                AuditEventType::RuleRejected,
                "rejected",
                raw_args,
                None,
                None,
                Some(&e),
            );
            Err(e)
        }
    }
}

pub fn enforce_policy(raw_args: &[String]) -> Result<Vec<String>, String> {
    let cfg: Config = config::load()?;
    enforce_policy_with(raw_args, &cfg)
}

pub fn enforce_policy_with(raw_args: &[String], cfg: &Config) -> Result<Vec<String>, String> {
    let classification = classify_arguments_with(raw_args, cfg.allow_bypass);

    match classification {
        CommandClassification::BypassDenied => {
            let err_msg =
                "Bypass is disabled by system policy (allow_bypass = false in ufw-guard.conf)."
                    .to_string();
            log_event(
                AuditEventType::RuleRejected,
                "rejected",
                raw_args,
                None,
                None,
                Some(&err_msg),
            );
            Err(err_msg)
        }
        CommandClassification::PassThrough
            if cfg.require_comment_on_delete && is_delete_command(raw_args) =>
        {
            enforce_delete_comment(raw_args)
        }
        CommandClassification::Bypass => {
            let (stripped, _) = strip_bypass_flag(raw_args);
            log_event(
                AuditEventType::Bypass,
                "bypassed",
                raw_args,
                Some(&stripped),
                None,
                None,
            );
            Ok(stripped)
        }
        CommandClassification::PassThrough => {
            let (stripped, _) = strip_bypass_flag(raw_args);
            Ok(stripped)
        }
        CommandClassification::RuleWithValidComment(comment) => {
            let (stripped, _) = strip_bypass_flag(raw_args);
            let enriched = enrich_comment(&comment);
            let final_args = replace_or_inject_comment(&stripped, &enriched);
            log_event(
                AuditEventType::RuleExecuted,
                "success",
                raw_args,
                Some(&final_args),
                Some(&enriched),
                None,
            );
            Ok(final_args)
        }
        CommandClassification::RuleWithInvalidComment(violation) => {
            if !is_interactive() {
                let err_msg = format!(
                    "Firewall rule comment violates governance policy: {}",
                    violation
                );
                log_event(
                    AuditEventType::RuleRejected,
                    "rejected",
                    raw_args,
                    None,
                    None,
                    Some(&err_msg),
                );
                return Err(err_msg);
            }

            eprintln!("ufw-guard: {}", violation);
            let new_comment = resolve_missing_comment()?;
            let (stripped, _) = strip_bypass_flag(raw_args);
            let enriched = enrich_comment(&new_comment);
            let final_args = replace_or_inject_comment(&stripped, &enriched);
            log_event(
                AuditEventType::RuleRemediated,
                "success",
                raw_args,
                Some(&final_args),
                Some(&enriched),
                None,
            );
            Ok(final_args)
        }
        CommandClassification::RuleMissingComment => {
            let comment = match resolve_missing_comment() {
                Ok(c) => c,
                Err(e) => {
                    log_event(
                        AuditEventType::RuleRejected,
                        "rejected",
                        raw_args,
                        None,
                        None,
                        Some(&e),
                    );
                    return Err(e);
                }
            };
            let (stripped, _) = strip_bypass_flag(raw_args);
            let enriched = enrich_comment(&comment);
            let final_args = replace_or_inject_comment(&stripped, &enriched);
            log_event(
                AuditEventType::RuleRemediated,
                "success",
                raw_args,
                Some(&final_args),
                Some(&enriched),
                None,
            );
            Ok(final_args)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_args(s: &[&str]) -> Vec<String> {
        s.iter().map(|&x| x.to_string()).collect()
    }

    #[test]
    fn test_bypass_denied_by_config() {
        let cfg = Config {
            allow_bypass: false,
            ..Config::default()
        };
        let args = to_args(&["allow", "22", "--force-no-comment"]);
        let err = enforce_policy_with(&args, &cfg).unwrap_err();
        assert!(err.contains("Bypass is disabled"));
    }

    #[test]
    fn test_delete_requires_comment_and_strips_it() {
        let cfg = Config {
            require_comment_on_delete: true,
            ..Config::default()
        };
        let args = to_args(&["delete", "allow", "22", "comment", "Closing legacy SSH"]);
        assert_eq!(
            enforce_policy_with(&args, &cfg).unwrap(),
            to_args(&["delete", "allow", "22"])
        );
    }

    #[test]
    fn test_enforce_policy_bypass() {
        let args = to_args(&["allow", "22", "--force-no-comment"]);
        let result = enforce_policy(&args);
        assert_eq!(result.unwrap(), to_args(&["allow", "22"]));
    }

    #[test]
    fn test_enforce_policy_with_comment_and_attribution() {
        let args = to_args(&["allow", "80", "comment", "Web Ingress"]);
        let result = enforce_policy(&args).unwrap();
        assert!(result.contains(&"comment".to_string()));
        let comment_val = result.last().unwrap();
        assert!(comment_val.starts_with("Web Ingress [by: "));
    }

    #[test]
    fn test_enforce_policy_invalid_comment_non_interactive() {
        std::env::set_var(crate::prompt::NON_INTERACTIVE_ENV, "1");
        let args = to_args(&["allow", "80", "comment", "test"]);
        let result = enforce_policy(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("violates governance policy"));
        std::env::remove_var(crate::prompt::NON_INTERACTIVE_ENV);
    }
}
