//! TTL option parsing and construction of automatic UFW rule revocations.

use std::io::{BufRead, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::args::{
    extract_comment, replace_or_inject_comment, PASSTHROUGH_SUBCOMMANDS, RULE_SUBCOMMANDS,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TtlSpec {
    pub seconds: u64,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTtl {
    pub args: Vec<String>,
    pub ttl: Option<TtlSpec>,
    pub explicit_no_ttl: bool,
}

pub fn is_rule_command(args: &[String]) -> bool {
    !args.iter().any(|arg| arg == "--dry-run")
        && !args
            .iter()
            .any(|arg| PASSTHROUGH_SUBCOMMANDS.contains(&arg.as_str()) || arg == "delete")
        && args
            .iter()
            .any(|arg| RULE_SUBCOMMANDS.contains(&arg.as_str()))
}

pub fn parse_duration(value: &str) -> Result<TtlSpec, String> {
    let split = value
        .find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(value.len());
    let amount = value[..split].parse::<u64>().map_err(|_| {
        format!("invalid TTL '{value}'; use a positive duration such as 30m, 2h, or 1d")
    })?;
    let unit = &value[split..];
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        _ => return Err(format!("invalid TTL unit in '{value}'; use s, m, h, or d")),
    };
    let seconds = amount
        .checked_mul(multiplier)
        .filter(|seconds| *seconds >= 60)
        .ok_or_else(|| format!("TTL '{value}' must be at least one minute"))?;
    Ok(TtlSpec {
        seconds,
        label: value.to_string(),
    })
}

pub fn parse_arguments(args: &[String]) -> Result<ParsedTtl, String> {
    let mut clean = Vec::with_capacity(args.len());
    let mut ttl = None;
    let mut explicit_no_ttl = false;
    let mut saw_ttl = false;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(value) = arg.strip_prefix("--ttl=") {
            if saw_ttl {
                return Err("specify --ttl only once".to_string());
            }
            ttl = Some(parse_duration(value)?);
            saw_ttl = true;
        } else if arg == "--ttl" {
            if saw_ttl {
                return Err("specify --ttl only once".to_string());
            }
            let value = args
                .get(index + 1)
                .ok_or_else(|| "--ttl requires a duration such as 30m, 2h, or 1d".to_string())?;
            ttl = Some(parse_duration(value)?);
            saw_ttl = true;
            index += 1;
        } else if arg == "--no-ttl" || arg == "--permanent" {
            explicit_no_ttl = true;
        } else {
            clean.push(arg.clone());
        }
        index += 1;
    }

    if !saw_ttl && !explicit_no_ttl {
        return Ok(ParsedTtl {
            args: clean,
            ttl,
            explicit_no_ttl,
        });
    }
    if !is_rule_command(&clean) {
        return Err("TTL options are only valid on rule-creation commands".to_string());
    }
    if saw_ttl && explicit_no_ttl {
        return Err("--ttl cannot be combined with --no-ttl or --permanent".to_string());
    }
    Ok(ParsedTtl {
        args: clean,
        ttl,
        explicit_no_ttl,
    })
}

pub fn prompt_ttl<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
) -> Result<Option<TtlSpec>, String> {
    write!(
        writer,
        "Set rule expiration TTL (e.g., 30m, 2h, 1d) [press Enter for none]: "
    )
    .map_err(|e| e.to_string())?;
    writer.flush().map_err(|e| e.to_string())?;
    let mut value = String::new();
    if reader.read_line(&mut value).map_err(|e| e.to_string())? == 0 {
        return Err("unexpected EOF while reading rule TTL".to_string());
    }
    let value = value.trim();
    if value.is_empty() {
        Ok(None)
    } else {
        parse_duration(value).map(Some)
    }
}

pub fn expiration_unix(seconds: u64) -> Result<u64, String> {
    SystemTime::now()
        .checked_add(Duration::from_secs(seconds))
        .and_then(|expiry| expiry.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs())
        .ok_or_else(|| "TTL expiration time is out of range".to_string())
}

pub fn append_expiration_metadata(
    args: &[String],
    ttl: &str,
    expires_unix: u64,
    marker: &str,
) -> Vec<String> {
    let comment = extract_comment(args).unwrap_or_default();
    let metadata = format!(
        "[ttl: {}, expires-unix: {}, ttl-id: {}]",
        ttl, expires_unix, marker
    );
    let annotated = if comment.is_empty() {
        metadata
    } else {
        format!("{} {}", comment, metadata)
    };
    replace_or_inject_comment(args, &annotated)
}
