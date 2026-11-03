//! ufw-guard: Enforces comment governance before delegating to upstream UFW.

pub mod args;
pub mod policy;
pub mod prompt;

use std::env;
use std::process;

fn main() {
    let raw_args: Vec<String> = env::args().skip(1).collect();

    match policy::enforce_policy(&raw_args) {
        Ok(args_to_forward) => {
            // Forwarding placeholder for Phase 2; Phase 3 implements execvp passthrough.
            println!("Forwarding validated arguments: {:?}", args_to_forward);
        }
        Err(err) => {
            eprintln!("ufw-guard error: {}", err);
            process::exit(1);
        }
    }
}
