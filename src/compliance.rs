//! Compliance scanner (`ufw --audit`) and interactive remediation (`ufw --remediate`)
//! for rules that pre-date ufw-guard or were created via bypass.

use crate::args::{extract_comment, RULE_SUBCOMMANDS};
use crate::attribution::enrich_comment;
use crate::audit::{log_event, AuditEventType};
use crate::quality::validate_comment;
use std::io::{BufRead, Write};
use std::path::Path;
use std::process::Command;

pub const AUDIT_FLAG: &str = "--audit";
pub const REMEDIATE_FLAG: &str = "--remediate";

/// Exit code when uncommented / non-compliant rules are found.
pub const EXIT_NONCOMPLIANT: i32 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingRule {
    /// Tokens after the leading `ufw`, comment included (e.g. `allow 22/tcp comment x`).
    pub tokens: Vec<String>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    Compliant,
    MissingComment,
    InvalidComment(String),
}

impl ExistingRule {
    pub fn spec(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.tokens.len() {
            if self.tokens[i].eq_ignore_ascii_case("comment") {
                i += 2;
            } else {
                out.push(self.tokens[i].clone());
                i += 1;
            }
        }
        out
    }

    pub fn display(&self) -> String {
        format!("ufw {}", self.spec().join(" "))
    }

    pub fn finding(&self) -> Finding {
        match &self.comment {
            None => Finding::MissingComment,
            Some(c) => match validate_comment(c) {
                Ok(()) => Finding::Compliant,
                Err(v) => Finding::InvalidComment(v.to_string()),
            },
        }
    }
}

/// Shell-style split honoring single and double quotes (as emitted by `ufw show added`).
pub fn split_shell_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    for ch in line.chars() {
        match quote {
            Some(q) if ch == q => quote = None,
            Some(_) => cur.push(ch),
            None if ch == '\'' || ch == '"' => {
                quote = Some(ch);
                in_word = true;
            }
            None if ch.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            None => {
                cur.push(ch);
                in_word = true;
            }
        }
    }
    if in_word {
        words.push(cur);
    }
    words
}

/// Parse the output of `ufw show added` into rules.
pub fn parse_added_rules(output: &str) -> Vec<ExistingRule> {
    let mut rules = Vec::new();
    for line in output.lines() {
        let words = split_shell_words(line.trim());
        if words.first().map(String::as_str) != Some("ufw") {
            continue;
        }
        let tokens: Vec<String> = words[1..].to_vec();
        let is_rule = tokens
            .iter()
            .take(2)
            .any(|t| RULE_SUBCOMMANDS.contains(&t.as_str()));
        if !is_rule {
            continue;
        }
        let comment = extract_comment(&tokens);
        rules.push(ExistingRule { tokens, comment });
    }
    rules
}

pub fn fetch_existing_rules(upstream: &Path) -> Result<Vec<ExistingRule>, String> {
    let output = Command::new(upstream)
        .args(["show", "added"])
        .output()
        .map_err(|e| format!("Failed to run {} show added: {}", upstream.display(), e))?;
    if !output.status.success() {
        return Err(format!(
            "`ufw show added` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(parse_added_rules(&String::from_utf8_lossy(&output.stdout)))
}

/// Write a deterministic report; returns the number of non-compliant rules.
pub fn render_audit_report<W: Write>(
    rules: &[ExistingRule],
    out: &mut W,
) -> std::io::Result<usize> {
    let mut bad = 0;
    for (i, rule) in rules.iter().enumerate() {
        match rule.finding() {
            Finding::Compliant => {}
            Finding::MissingComment => {
                bad += 1;
                writeln!(
                    out,
                    "[NONCOMPLIANT] #{}: {}  (missing comment)",
                    i + 1,
                    rule.display()
                )?;
            }
            Finding::InvalidComment(reason) => {
                bad += 1;
                writeln!(
                    out,
                    "[NONCOMPLIANT] #{}: {}  (invalid comment: {})",
                    i + 1,
                    rule.display(),
                    reason
                )?;
            }
        }
    }
    writeln!(
        out,
        "ufw-guard audit: {} of {} rule(s) non-compliant.",
        bad,
        rules.len()
    )?;
    Ok(bad)
}

/// Run `ufw --audit`; returns the process exit code (0 clean, 2 non-compliant, 1 error).
pub fn run_audit(upstream: &Path) -> i32 {
    let rules = match fetch_existing_rules(upstream) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ufw-guard error: {}", e);
            return 1;
        }
    };
    let stdout = std::io::stdout();
    match render_audit_report(&rules, &mut stdout.lock()) {
        Ok(0) => 0,
        Ok(_) => EXIT_NONCOMPLIANT,
        Err(_) => 1,
    }
}

/// Abstraction over running upstream commands so remediation is testable.
pub trait UfwRunner {
    fn run(&mut self, args: &[String]) -> Result<(), String>;
}

pub struct ProcessRunner<'a>(pub &'a Path);

impl UfwRunner for ProcessRunner<'_> {
    fn run(&mut self, args: &[String]) -> Result<(), String> {
        let out = Command::new(self.0)
            .args(args)
            .output()
            .map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }
}

/// `ufw delete <spec>` argument vector (route rules use `route delete`).
fn delete_args(spec: &[String]) -> Vec<String> {
    let mut v = Vec::new();
    if spec.first().map(String::as_str) == Some("route") {
        v.push("route".to_string());
        v.push("delete".to_string());
        v.extend(spec[1..].iter().cloned());
    } else {
        v.push("delete".to_string());
        v.extend(spec.iter().cloned());
    }
    v
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct RemediationSummary {
    pub fixed: usize,
    pub skipped: usize,
    pub failed: usize,
}

/// Walk through non-compliant rules, prompting for a comment. Blank input skips a rule.
/// UFW cannot edit comments in place, so a rule is deleted and re-added with its comment;
/// if the re-add fails the original rule is restored.
pub fn remediate_rules<R: BufRead, W: Write, U: UfwRunner>(
    rules: &[ExistingRule],
    reader: &mut R,
    writer: &mut W,
    runner: &mut U,
) -> Result<RemediationSummary, String> {
    let mut summary = RemediationSummary::default();
    let e = |x: std::io::Error| x.to_string();
    for (i, rule) in rules.iter().enumerate() {
        let reason = match rule.finding() {
            Finding::Compliant => continue,
            Finding::MissingComment => "missing comment".to_string(),
            Finding::InvalidComment(r) => format!("invalid comment: {}", r),
        };
        writeln!(writer, "\n#{}: {}  ({})", i + 1, rule.display(), reason).map_err(e)?;

        let comment = loop {
            write!(writer, "Comment (blank to skip): ").map_err(e)?;
            writer.flush().map_err(e)?;
            let mut line = String::new();
            if reader.read_line(&mut line).map_err(e)? == 0 {
                return Err("Unexpected EOF during remediation.".to_string());
            }
            let t = line.trim();
            if t.is_empty() {
                break None;
            }
            match validate_comment(t) {
                Ok(()) => break Some(t.to_string()),
                Err(v) => writeln!(writer, "Invalid comment: {}", v).map_err(e)?,
            }
        };
        let Some(comment) = comment else {
            summary.skipped += 1;
            continue;
        };

        let spec = rule.spec();
        let enriched = enrich_comment(&comment);
        let mut add_args = spec.clone();
        add_args.push("comment".to_string());
        add_args.push(enriched.clone());

        if let Err(err) = runner.run(&delete_args(&spec)) {
            writeln!(writer, "Failed to remove existing rule: {}", err).map_err(e)?;
            log_event(
                AuditEventType::RuleRejected,
                "failed",
                &spec,
                None,
                None,
                Some(&err),
            );
            summary.failed += 1;
            continue;
        }
        match runner.run(&add_args) {
            Ok(()) => {
                writeln!(writer, "Applied comment.").map_err(e)?;
                log_event(
                    AuditEventType::RuleRemediated,
                    "success",
                    &spec,
                    Some(&add_args),
                    Some(&enriched),
                    None,
                );
                summary.fixed += 1;
            }
            Err(err) => {
                let restored = runner.run(&spec).is_ok();
                writeln!(
                    writer,
                    "Failed to re-add rule with comment: {} (original rule {})",
                    err,
                    if restored {
                        "restored"
                    } else {
                        "NOT restored - check manually!"
                    }
                )
                .map_err(e)?;
                log_event(
                    AuditEventType::RuleRejected,
                    "failed",
                    &spec,
                    None,
                    None,
                    Some(&err),
                );
                summary.failed += 1;
            }
        }
    }
    writeln!(
        writer,
        "\nufw-guard remediate: {} fixed, {} skipped, {} failed.",
        summary.fixed, summary.skipped, summary.failed
    )
    .map_err(e)?;
    Ok(summary)
}

/// Run `ufw --remediate` (interactive terminal required); returns the exit code.
pub fn run_remediate(upstream: &Path) -> i32 {
    if !crate::prompt::is_interactive() {
        eprintln!("ufw-guard error: --remediate requires an interactive terminal.");
        return 1;
    }
    let rules = match fetch_existing_rules(upstream) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ufw-guard error: {}", e);
            return 1;
        }
    };
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let mut stderr = std::io::stderr().lock();
    let mut runner = ProcessRunner(upstream);
    match remediate_rules(&rules, &mut reader, &mut stderr, &mut runner) {
        Ok(s) if s.failed == 0 && s.skipped == 0 => 0,
        Ok(_) => EXIT_NONCOMPLIANT,
        Err(e) => {
            eprintln!("ufw-guard error: {}", e);
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const SAMPLE: &str = "Added user rules (see 'ufw status' for running firewall):\n\
ufw allow 22/tcp\n\
ufw allow 80/tcp comment 'Web ingress'\n\
ufw deny from 10.0.0.0/8 comment 'tmp'\n\
ufw route allow in on eth0 out on eth1\n\
\n";

    #[test]
    fn test_parse_and_findings() {
        let rules = parse_added_rules(SAMPLE);
        assert_eq!(rules.len(), 4);
        assert_eq!(rules[0].finding(), Finding::MissingComment);
        assert_eq!(rules[1].finding(), Finding::Compliant);
        assert!(matches!(rules[2].finding(), Finding::InvalidComment(_)));
        assert_eq!(rules[1].spec(), vec!["allow", "80/tcp"]);
    }

    #[test]
    fn test_report_counts() {
        let rules = parse_added_rules(SAMPLE);
        let mut out = Vec::new();
        assert_eq!(render_audit_report(&rules, &mut out).unwrap(), 3);
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("[NONCOMPLIANT] #1: ufw allow 22/tcp  (missing comment)"));
        assert!(s.contains("3 of 4 rule(s) non-compliant."));
    }

    struct Mock {
        calls: Vec<Vec<String>>,
        fail_add: bool,
    }
    impl UfwRunner for Mock {
        fn run(&mut self, args: &[String]) -> Result<(), String> {
            self.calls.push(args.to_vec());
            if self.fail_add && args.contains(&"comment".to_string()) {
                return Err("boom".into());
            }
            Ok(())
        }
    }

    #[test]
    fn test_remediate_fix_skip_and_route() {
        let rules = parse_added_rules(SAMPLE);
        let mut input =
            Cursor::new(b"Allow SSH admin access\ntest\n\nRouting eth0 to eth1\n".to_vec());
        let mut out = Vec::new();
        let mut m = Mock {
            calls: vec![],
            fail_add: false,
        };
        let s = remediate_rules(&rules, &mut input, &mut out, &mut m).unwrap();
        assert_eq!(
            s,
            RemediationSummary {
                fixed: 2,
                skipped: 1,
                failed: 0
            }
        );
        assert_eq!(m.calls[0], vec!["delete", "allow", "22/tcp"]);
        assert_eq!(m.calls[1][0..3], ["allow", "22/tcp", "comment"]);
        assert_eq!(m.calls[2][0..2], ["route", "delete"]);
    }

    #[test]
    fn test_remediate_restores_on_failure() {
        let rules = parse_added_rules("ufw allow 22/tcp\n");
        let mut input = Cursor::new(b"Allow SSH admin access\n".to_vec());
        let mut out = Vec::new();
        let mut m = Mock {
            calls: vec![],
            fail_add: true,
        };
        let s = remediate_rules(&rules, &mut input, &mut out, &mut m).unwrap();
        assert_eq!(s.failed, 1);
        assert_eq!(m.calls.last().unwrap(), &vec!["allow", "22/tcp"]);
        assert!(String::from_utf8(out).unwrap().contains("restored"));
    }
}
