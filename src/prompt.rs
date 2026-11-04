//! Interactive terminal prompt handling for ufw-guard.

use crate::quality;
use std::io::{self, BufRead, IsTerminal, Write};

pub const NON_INTERACTIVE_ENV: &str = "UFW_GUARD_NON_INTERACTIVE";

pub fn is_interactive() -> bool {
    if let Ok(val) = std::env::var(NON_INTERACTIVE_ENV) {
        if val == "1" || val.eq_ignore_ascii_case("true") {
            return false;
        }
    }
    io::stdin().is_terminal()
}

pub fn prompt_for_comment_interactive<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
) -> Result<String, String> {
    writeln!(
        writer,
        "ufw-guard: Firewall rules require an audit comment."
    )
    .map_err(|e| e.to_string())?;

    let max_attempts = 3;
    for attempt in 1..=max_attempts {
        write!(writer, "Enter mandatory comment: ").map_err(|e| e.to_string())?;
        writer.flush().map_err(|e| e.to_string())?;

        let mut line = String::new();
        let bytes_read = reader.read_line(&mut line).map_err(|e| e.to_string())?;
        if bytes_read == 0 {
            return Err("Unexpected EOF while reading comment.".to_string());
        }

        let trimmed = line.trim();
        match quality::validate_comment(trimmed) {
            Ok(()) => return Ok(trimmed.to_string()),
            Err(violation) => {
                if attempt < max_attempts {
                    writeln!(writer, "Invalid comment: {}", violation)
                        .map_err(|e| e.to_string())?;
                } else {
                    return Err(format!("Comment validation failed: {}", violation));
                }
            }
        }
    }

    Err("Maximum comment entry attempts exceeded.".to_string())
}

pub fn resolve_missing_comment() -> Result<String, String> {
    if !is_interactive() {
        return Err(
            "Missing required comment on firewall rule in non-interactive mode. \
             Provide `comment \"<text>\"` or use `--force-no-comment` to bypass."
                .to_string(),
        );
    }

    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut stderr = io::stderr().lock();
    prompt_for_comment_interactive(&mut reader, &mut stderr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_prompt_success() {
        let mut input = Cursor::new(b"Allow HTTP ingress\n");
        let mut output = Vec::new();
        let res = prompt_for_comment_interactive(&mut input, &mut output);
        assert_eq!(res.unwrap(), "Allow HTTP ingress");
    }

    #[test]
    fn test_prompt_retry_then_success() {
        // First entry "test" (placeholder), second "Allow SSH ingress" (valid)
        let mut input = Cursor::new(b"test\nAllow SSH ingress\n");
        let mut output = Vec::new();
        let res = prompt_for_comment_interactive(&mut input, &mut output);
        assert_eq!(res.unwrap(), "Allow SSH ingress");
        let out_str = String::from_utf8(output).unwrap();
        assert!(out_str.contains("Invalid comment"));
    }

    #[test]
    fn test_prompt_empty_fails() {
        let mut input = Cursor::new(b"   \n\n\n");
        let mut output = Vec::new();
        let res = prompt_for_comment_interactive(&mut input, &mut output);
        assert!(res.is_err());
    }
}
