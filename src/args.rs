//! Argument parsing and rule classification for UFW commands.

pub const RULE_SUBCOMMANDS: &[&str] = &[
    "allow", "deny", "reject", "limit", "route", "insert", "prepend",
];

pub const PASSTHROUGH_SUBCOMMANDS: &[&str] = &[
    "status",
    "enable",
    "disable",
    "reload",
    "reset",
    "delete",
    "--version",
    "-v",
    "--help",
    "-h",
    "default",
    "logging",
    "app",
];

pub const BYPASS_FLAG: &str = "--force-no-comment";
pub const BYPASS_ENV: &str = "UFW_GUARD_BYPASS";

#[derive(Debug, PartialEq, Eq)]
pub enum CommandClassification {
    Bypass,
    PassThrough,
    RuleWithValidComment,
    RuleMissingComment,
}

pub fn strip_bypass_flag(args: &[String]) -> (Vec<String>, bool) {
    let mut stripped = Vec::with_capacity(args.len());
    let mut had_flag = false;
    for arg in args {
        if arg == BYPASS_FLAG {
            had_flag = true;
        } else {
            stripped.push(arg.clone());
        }
    }
    (stripped, had_flag)
}

pub fn is_env_bypass_set() -> bool {
    std::env::var(BYPASS_ENV)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub fn classify_arguments(args: &[String]) -> CommandClassification {
    let (_, had_bypass_flag) = strip_bypass_flag(args);
    if had_bypass_flag || is_env_bypass_set() {
        return CommandClassification::Bypass;
    }

    let is_delete = args.iter().any(|a| a == "delete");
    if is_delete {
        return CommandClassification::PassThrough;
    }

    let is_passthrough = args
        .iter()
        .any(|a| PASSTHROUGH_SUBCOMMANDS.iter().any(|&cmd| a == cmd));
    if is_passthrough {
        return CommandClassification::PassThrough;
    }

    let is_rule = args
        .iter()
        .any(|a| RULE_SUBCOMMANDS.iter().any(|&cmd| a == cmd));
    if !is_rule {
        return CommandClassification::PassThrough;
    }

    if has_valid_comment(args) {
        CommandClassification::RuleWithValidComment
    } else {
        CommandClassification::RuleMissingComment
    }
}

pub fn has_valid_comment(args: &[String]) -> bool {
    for (idx, arg) in args.iter().enumerate() {
        if arg.eq_ignore_ascii_case("comment") {
            if let Some(next_arg) = args.get(idx + 1) {
                if !next_arg.trim().is_empty() && !next_arg.starts_with("--") {
                    return true;
                }
            }
        }
    }
    false
}

pub fn inject_comment(mut args: Vec<String>, comment: &str) -> Vec<String> {
    args.push("comment".to_string());
    args.push(comment.to_string());
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_args(s: &[&str]) -> Vec<String> {
        s.iter().map(|&x| x.to_string()).collect()
    }

    #[test]
    fn test_passthrough_commands() {
        assert_eq!(
            classify_arguments(&to_args(&["status"])),
            CommandClassification::PassThrough
        );
        assert_eq!(
            classify_arguments(&to_args(&["enable"])),
            CommandClassification::PassThrough
        );
        assert_eq!(
            classify_arguments(&to_args(&["delete", "allow", "22"])),
            CommandClassification::PassThrough
        );
        assert_eq!(
            classify_arguments(&to_args(&["--version"])),
            CommandClassification::PassThrough
        );
    }

    #[test]
    fn test_rule_requiring_comment() {
        assert_eq!(
            classify_arguments(&to_args(&["allow", "22/tcp"])),
            CommandClassification::RuleMissingComment
        );
        assert_eq!(
            classify_arguments(&to_args(&["deny", "from", "1.2.3.4"])),
            CommandClassification::RuleMissingComment
        );
        assert_eq!(
            classify_arguments(&to_args(&["limit", "ssh"])),
            CommandClassification::RuleMissingComment
        );
    }

    #[test]
    fn test_rule_with_comment() {
        assert_eq!(
            classify_arguments(&to_args(&["allow", "22", "comment", "SSH ingress"])),
            CommandClassification::RuleWithValidComment
        );
        assert_eq!(
            classify_arguments(&to_args(&["insert", "1", "allow", "80", "comment", "HTTP"])),
            CommandClassification::RuleWithValidComment
        );
    }

    #[test]
    fn test_bypass_flag() {
        let (stripped, had) = strip_bypass_flag(&to_args(&["allow", "22", "--force-no-comment"]));
        assert!(had);
        assert_eq!(stripped, to_args(&["allow", "22"]));
        assert_eq!(
            classify_arguments(&to_args(&["allow", "22", "--force-no-comment"])),
            CommandClassification::Bypass
        );
    }

    #[test]
    fn test_inject_comment() {
        let injected = inject_comment(to_args(&["allow", "22"]), "Admin SSH");
        assert_eq!(injected, to_args(&["allow", "22", "comment", "Admin SSH"]));
    }
}
