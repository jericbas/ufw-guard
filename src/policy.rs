//! Policy engine combining argument classification and interactive remediation.

use crate::args::{classify_arguments, inject_comment, strip_bypass_flag, CommandClassification};
use crate::prompt::resolve_missing_comment;

pub fn enforce_policy(raw_args: &[String]) -> Result<Vec<String>, String> {
    let classification = classify_arguments(raw_args);

    match classification {
        CommandClassification::Bypass => {
            let (stripped, _) = strip_bypass_flag(raw_args);
            Ok(stripped)
        }
        CommandClassification::PassThrough | CommandClassification::RuleWithValidComment => {
            let (stripped, _) = strip_bypass_flag(raw_args);
            Ok(stripped)
        }
        CommandClassification::RuleMissingComment => {
            let comment = resolve_missing_comment()?;
            let (stripped, _) = strip_bypass_flag(raw_args);
            Ok(inject_comment(stripped, &comment))
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
    fn test_enforce_policy_with_comment() {
        let args = to_args(&["allow", "80", "comment", "Web"]);
        let result = enforce_policy(&args);
        assert_eq!(result.unwrap(), to_args(&["allow", "80", "comment", "Web"]));
    }
}
