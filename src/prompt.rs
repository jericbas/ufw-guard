//! Interactive terminal prompt handling for ufw-guard.

use std::io::{self, BufRead, IsTerminal, Write};

pub fn is_interactive() -> bool {
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
    write!(writer, "Enter mandatory comment: ").map_err(|e| e.to_string())?;
    writer.flush().map_err(|e| e.to_string())?;

    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        Err("Comment cannot be empty.".to_string())
    } else {
        Ok(trimmed.to_string())
    }
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
    fn test_prompt_empty_fails() {
        let mut input = Cursor::new(b"   \n");
        let mut output = Vec::new();
        let res = prompt_for_comment_interactive(&mut input, &mut output);
        assert!(res.is_err());
    }
}
