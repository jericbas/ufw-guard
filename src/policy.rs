//! Policy engine combining argument classification, quality enforcement, and interactive remediation.

use crate::args::{
    classify_arguments, replace_or_inject_comment, strip_bypass_flag, CommandClassification,
};
use crate::attribution::enrich_comment;
use crate::audit::{log_event, AuditEventType};
use crate::prompt::{is_interactive, resolve_missing_comment};

pub fn enforce_policy(raw_args: &[String]) -> Result<Vec<String>, String> {
    let classification = classify_arguments(raw_args);

    match classification {
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
    fn test_enforce_policy_bypass() {
        let args = to_args(&["allow", "22", "--force-no-comment"]);
        let result = enforce_policy(&args);
        assert_eq!(result.unwrap(), to_args(&["allow", "22"]));
    }

    #[test]
    fn test_enforce_policy_with_comment_and_attribution() {
        std::env::set_var(crate::attribution::AUTO_ATTRIBUTION_ENV, "1");
        std::env::set_var("SUDO_USER", "admin_jeric");
        std::env::set_var(crate::attribution::ATTRIBUTION_DATE_ENV, "2026-11-04");

        let args = to_args(&["allow", "80", "comment", "Web Ingress"]);
        let result = enforce_policy(&args).unwrap();
        assert_eq!(
            result,
            to_args(&[
                "allow",
                "80",
                "comment",
                "Web Ingress [by: admin_jeric @ 2026-11-04]"
            ])
        );

        std::env::remove_var("SUDO_USER");
        std::env::remove_var(crate::attribution::ATTRIBUTION_DATE_ENV);
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
