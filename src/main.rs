//! ufw-guard: Enforces comment governance before delegating to upstream UFW.

use std::env;
use std::process;

use ufw_guard::executor;
use ufw_guard::policy;

fn main() {
    let raw_args: Vec<String> = env::args().skip(1).collect();

    match policy::enforce_policy(&raw_args) {
        Ok(args_to_forward) => {
            let upstream_path = executor::resolve_upstream_path();
            if let Err(err) = executor::execute_upstream(&upstream_path, &args_to_forward) {
                eprintln!("ufw-guard delegation error: {}", err);
                process::exit(1);
            }
        }
        Err(err) => {
            eprintln!("ufw-guard error: {}", err);
            process::exit(1);
        }
    }
}
