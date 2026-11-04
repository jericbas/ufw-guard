//! Comment quality validation and pattern enforcement for ufw-guard.

use regex_lite::Regex;
use std::env;

pub const DEFAULT_MIN_COMMENT_LEN: usize = 4;
pub const MIN_COMMENT_LEN_ENV: &str = "UFW_GUARD_MIN_COMMENT_LEN";
pub const COMMENT_PATTERN_ENV: &str = "UFW_GUARD_COMMENT_PATTERN";
pub const COMMENT_REGEX_ENV: &str = "UFW_GUARD_COMMENT_REGEX";

pub const TRIVIAL_PLACEHOLDERS: &[&str] = &[
    "test",
    "temp",
    "temporary",
    "none",
    "n/a",
    "na",
    "asdf",
    "todo",
    "comment",
    "rule",
    "placeholder",
    "default",
    "xxx",
    "abc",
    "admin",
    "null",
    "blank",
];

#[derive(Debug, PartialEq, Eq)]
pub enum QualityViolation {
    Empty,
    TooShort { actual: usize, min: usize },
    Placeholder(String),
    NoAlphanumeric,
    PatternMismatch { pattern: String },
    InvalidPatternConfig { pattern: String, error: String },
}

impl std::fmt::Display for QualityViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QualityViolation::Empty => write!(f, "Comment cannot be empty."),
            QualityViolation::TooShort { actual, min } => write!(
                f,
                "Comment is too short (length: {}, minimum required: {}).",
                actual, min
            ),
            QualityViolation::Placeholder(p) => {
                write!(
                    f,
                    "Comment '{}' is a generic placeholder and not allowed.",
                    p
                )
            }
            QualityViolation::NoAlphanumeric => write!(
                f,
                "Comment must contain alphanumeric characters, not solely punctuation or symbols."
            ),
            QualityViolation::PatternMismatch { pattern } => {
                write!(
                    f,
                    "Comment does not match required policy pattern '{}'.",
                    pattern
                )
            }
            QualityViolation::InvalidPatternConfig { pattern, error } => {
                write!(f, "Invalid pattern configuration '{}': {}.", pattern, error)
            }
        }
    }
}

pub fn get_min_comment_length() -> usize {
    env::var(MIN_COMMENT_LEN_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .or_else(|| crate::config::current().min_comment_length)
        .unwrap_or(DEFAULT_MIN_COMMENT_LEN)
}

pub fn get_comment_pattern() -> Option<String> {
    env::var(COMMENT_PATTERN_ENV)
        .or_else(|_| env::var(COMMENT_REGEX_ENV))
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .or_else(|| crate::config::current().comment_pattern)
}

pub fn validate_comment_with_config(
    comment: &str,
    min_len: usize,
    pattern: Option<&str>,
) -> Result<(), QualityViolation> {
    let trimmed = comment.trim();
    if trimmed.is_empty() {
        return Err(QualityViolation::Empty);
    }

    if trimmed.chars().count() < min_len {
        return Err(QualityViolation::TooShort {
            actual: trimmed.chars().count(),
            min: min_len,
        });
    }

    if !trimmed.chars().any(|c| c.is_alphanumeric()) {
        return Err(QualityViolation::NoAlphanumeric);
    }

    let lower = trimmed.to_ascii_lowercase();
    for &placeholder in TRIVIAL_PLACEHOLDERS {
        if lower == placeholder {
            return Err(QualityViolation::Placeholder(trimmed.to_string()));
        }
    }

    if let Some(pat) = pattern {
        match Regex::new(pat) {
            Ok(re) => {
                if !re.is_match(trimmed) {
                    return Err(QualityViolation::PatternMismatch {
                        pattern: pat.to_string(),
                    });
                }
            }
            Err(err) => {
                return Err(QualityViolation::InvalidPatternConfig {
                    pattern: pat.to_string(),
                    error: err.to_string(),
                });
            }
        }
    }

    Ok(())
}

pub fn validate_comment(comment: &str) -> Result<(), QualityViolation> {
    let min_len = get_min_comment_length();
    let pattern = get_comment_pattern();
    validate_comment_with_config(comment, min_len, pattern.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_comments() {
        assert!(validate_comment_with_config("Allow HTTP ingress", 4, None).is_ok());
        assert!(validate_comment_with_config("JIRA-1234: open port", 4, None).is_ok());
        assert!(validate_comment_with_config("Internal VPN access", 4, None).is_ok());
    }

    #[test]
    fn test_empty_or_whitespace() {
        assert_eq!(
            validate_comment_with_config("", 4, None),
            Err(QualityViolation::Empty)
        );
        assert_eq!(
            validate_comment_with_config("   ", 4, None),
            Err(QualityViolation::Empty)
        );
    }

    #[test]
    fn test_too_short() {
        assert_eq!(
            validate_comment_with_config("SSH", 4, None),
            Err(QualityViolation::TooShort { actual: 3, min: 4 })
        );
        assert_eq!(
            validate_comment_with_config("a", 4, None),
            Err(QualityViolation::TooShort { actual: 1, min: 4 })
        );
    }

    #[test]
    fn test_trivial_placeholders() {
        assert_eq!(
            validate_comment_with_config("test", 4, None),
            Err(QualityViolation::Placeholder("test".to_string()))
        );
        assert_eq!(
            validate_comment_with_config("TEST", 4, None),
            Err(QualityViolation::Placeholder("TEST".to_string()))
        );
        assert_eq!(
            validate_comment_with_config("todo", 4, None),
            Err(QualityViolation::Placeholder("todo".to_string()))
        );
        assert_eq!(
            validate_comment_with_config("temp", 4, None),
            Err(QualityViolation::Placeholder("temp".to_string()))
        );
        assert_eq!(
            validate_comment_with_config("none", 4, None),
            Err(QualityViolation::Placeholder("none".to_string()))
        );
    }

    #[test]
    fn test_pure_punctuation() {
        assert_eq!(
            validate_comment_with_config("....", 4, None),
            Err(QualityViolation::NoAlphanumeric)
        );
        assert_eq!(
            validate_comment_with_config("----", 4, None),
            Err(QualityViolation::NoAlphanumeric)
        );
        assert_eq!(
            validate_comment_with_config("????", 4, None),
            Err(QualityViolation::NoAlphanumeric)
        );
    }

    #[test]
    fn test_pattern_matching() {
        let pattern = Some(r"^\[(ops|sec)\]");
        assert!(validate_comment_with_config("[ops] Ingress for web cluster", 4, pattern).is_ok());
        assert!(validate_comment_with_config("[sec] Lockdown port 22", 4, pattern).is_ok());
        assert_eq!(
            validate_comment_with_config("Ingress for web cluster", 4, pattern),
            Err(QualityViolation::PatternMismatch {
                pattern: r"^\[(ops|sec)\]".to_string()
            })
        );
    }
}
