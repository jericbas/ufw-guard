//! ufw-guard: Enforces comment governance before delegating to upstream UFW.

use std::env;
use std::process;

use ufw_guard::compliance;
use ufw_guard::executor;
use ufw_guard::policy;
use ufw_guard::prompt;
use ufw_guard::ttl::{self, ParsedTtl};
use ufw_guard::ttl_revocation;

fn main() {
    let raw_args: Vec<String> = env::args().skip(1).collect();

    if raw_args.first().map(String::as_str) == Some(ttl_revocation::EXPIRATION_FLAG) {
        if let Err(err) = run_expiration_command(&raw_args[1..]) {
            eprintln!("ufw-guard error: {}", err);
            process::exit(1);
        }
        return;
    }

    match raw_args.first().map(String::as_str) {
        Some(compliance::AUDIT_FLAG) => {
            process::exit(compliance::run_audit(&executor::resolve_upstream_path()))
        }
        Some(compliance::REMEDIATE_FLAG) => {
            process::exit(compliance::run_remediate(&executor::resolve_upstream_path()))
        }
        _ => {}
    }

    if let Err(err) = run_rule_command(&raw_args) {
        eprintln!("ufw-guard error: {}", err);
        process::exit(1);
    }
}

fn run_rule_command(raw_args: &[String]) -> Result<(), String> {
    let ParsedTtl {
        args,
        ttl: parsed_ttl,
        explicit_no_ttl,
    } = ttl::parse_arguments(raw_args)?;
    let is_rule = ttl::is_rule_command(&args);
    let ttl = match parsed_ttl {
        Some(value) => Some(value),
        None if is_rule && !explicit_no_ttl && prompt::is_interactive() => {
            ttl::prompt_ttl(&mut std::io::stdin().lock(), &mut std::io::stderr().lock())?
        }
        None => None,
    };

    let mut forwarded_args = policy::enforce_policy(&args)?;
    if is_rule && ttl.is_none() {
        eprintln!("[ufw-guard WARN] No TTL set: this firewall rule is permanent and will remain open until manually deleted.");
    }
    let upstream = executor::resolve_upstream_path();
    if let Some(spec) = ttl {
        let expires_unix = ttl::expiration_unix(spec.seconds)?;
        let marker = ttl_revocation::marker();
        forwarded_args =
            ttl::append_expiration_metadata(&forwarded_args, &spec.label, expires_unix, &marker);
        let revoke_args = ttl_revocation::revocation_args(&forwarded_args)?;
        executor::validate_upstream_binary(&upstream)?;
        let wrapper = env::current_exe().map_err(|e| format!("cannot locate ufw-guard: {}", e))?;
        executor::schedule_rule_revocation(
            &spec.label,
            &wrapper,
            &marker,
            &upstream,
            &revoke_args,
        )?;
        eprintln!("ufw-guard: scheduled rule removal in {}.", spec.label);
    }

    executor::execute_upstream(&upstream, &forwarded_args)
}

fn run_expiration_command(args: &[String]) -> Result<(), String> {
    let marker = args
        .first()
        .ok_or_else(|| "missing TTL expiration marker".to_string())?;
    let upstream = args
        .get(1)
        .ok_or_else(|| "missing upstream UFW path for TTL expiration".to_string())?;
    let revoke_args = &args[2..];
    if !ttl_revocation::marker_is_active(std::path::Path::new(upstream), marker)? {
        eprintln!("ufw-guard: expiring rule is absent or has changed; skipping removal.");
        return Ok(());
    }
    executor::execute_upstream(std::path::Path::new(upstream), revoke_args)
}
