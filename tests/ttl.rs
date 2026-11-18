use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use ufw_guard::ttl::{append_expiration_metadata, parse_arguments, parse_duration, prompt_ttl};
use ufw_guard::ttl_revocation::revocation_args;

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

#[test]
fn parses_supported_durations_and_rejects_invalid_values() {
    assert_eq!(parse_duration("30m").unwrap().seconds, 1_800);
    assert_eq!(parse_duration("2h").unwrap().seconds, 7_200);
    assert_eq!(parse_duration("1d").unwrap().seconds, 86_400);
    assert!(parse_duration("0m").is_err());
    assert!(parse_duration("30s").is_err());
    assert!(parse_duration("5x").is_err());
    assert!(parse_duration("999999999999999999999d").is_err());
}

#[test]
fn removes_ttl_options_before_forwarding() {
    let parsed = parse_arguments(&args(&[
        "allow",
        "22/tcp",
        "--ttl",
        "2h",
        "comment",
        "Allow SSH ingress",
    ]))
    .unwrap();
    assert_eq!(parsed.ttl.unwrap().label, "2h");
    assert_eq!(
        parsed.args,
        args(&["allow", "22/tcp", "comment", "Allow SSH ingress"])
    );

    let permanent = parse_arguments(&args(&["allow", "22/tcp", "--permanent"])).unwrap();
    assert!(permanent.explicit_no_ttl);
    assert!(permanent.ttl.is_none());
    assert!(parse_arguments(&args(&["status", "--ttl=30m"])).is_err());
    assert!(parse_arguments(&args(&["delete", "allow", "22", "--ttl=30m"])).is_err());
    assert!(parse_arguments(&args(&["--dry-run", "allow", "22", "--ttl=30m"])).is_err());
    assert!(parse_arguments(&args(&["allow", "22", "--ttl", "30m", "--no-ttl"])).is_err());
}

#[test]
fn prompts_for_optional_ttl_and_accepts_enter_as_permanent() {
    let mut input = "2h\n".as_bytes();
    let mut output = Vec::new();
    assert_eq!(
        prompt_ttl(&mut input, &mut output)
            .unwrap()
            .unwrap()
            .seconds,
        7_200
    );
    assert!(String::from_utf8(output)
        .unwrap()
        .contains("press Enter for none"));

    let mut input = "\n".as_bytes();
    assert!(prompt_ttl(&mut input, &mut Vec::new()).unwrap().is_none());
}

#[test]
fn adds_expiry_metadata_to_the_governed_comment() {
    assert_eq!(
        append_expiration_metadata(
            &args(&["allow", "80", "comment", "Web ingress"]),
            "2h",
            123,
            "42-123",
        ),
        args(&[
            "allow",
            "80",
            "comment",
            "Web ingress [ttl: 2h, expires-unix: 123, ttl-id: 42-123]"
        ]),
    );
    assert_eq!(
        append_expiration_metadata(&args(&["allow", "80"]), "30m", 123, "42-123"),
        args(&[
            "allow",
            "80",
            "comment",
            "[ttl: 30m, expires-unix: 123, ttl-id: 42-123]"
        ]),
    );
}

#[test]
fn builds_delete_commands_for_direct_inserted_and_routed_rules() {
    assert_eq!(
        revocation_args(&args(&["allow", "22/tcp", "comment", "SSH [ttl: 2h]"])).unwrap(),
        args(&["delete", "allow", "22/tcp"]),
    );
    assert_eq!(
        revocation_args(&args(&["insert", "3", "deny", "from", "1.2.3.4"])).unwrap(),
        args(&["delete", "deny", "from", "1.2.3.4"]),
    );
    assert_eq!(
        revocation_args(&args(&["route", "allow", "in", "on", "eth0"])).unwrap(),
        args(&["route", "delete", "allow", "in", "on", "eth0"]),
    );
}

#[test]
fn ttl_rule_schedules_revocation_before_adding_rule() {
    let dir = env::temp_dir().join(format!(
        "ufw_ttl_{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let bin_dir = dir.join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let timer_log = dir.join("timer.log");
    let upstream_log = dir.join("upstream.log");
    let upstream = dir.join("mock-ufw");
    let timer = bin_dir.join("systemd-run");
    fs::write(
        &upstream,
        "#!/bin/sh\ntest -s \"$TIMER_LOG\" || exit 9\nprintf '%s\\n' \"$*\" > \"$UPSTREAM_LOG\"\n",
    )
    .unwrap();
    fs::write(
        &timer,
        "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$TIMER_LOG\"\n",
    )
    .unwrap();
    for path in [&upstream, &timer] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let config = dir.join("ufw-guard.conf");
    fs::write(&config, "auto_append_user = false\n").unwrap();
    let path = env::join_paths(
        std::iter::once(bin_dir).chain(env::split_paths(&env::var_os("PATH").unwrap())),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_ufw"))
        .args([
            "allow",
            "22/tcp",
            "comment",
            "Allow SSH ingress",
            "--ttl",
            "30m",
        ])
        .env("PATH", path)
        .env("UFW_GUARD_UPSTREAM_PATH", &upstream)
        .env("UFW_GUARD_CONFIG", config)
        .env("UFW_GUARD_LOG_FILE", dir.join("audit.log"))
        .env("UFW_GUARD_NON_INTERACTIVE", "1")
        .env("TIMER_LOG", &timer_log)
        .env("UPSTREAM_LOG", &upstream_log)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("scheduled rule removal in 30m"));
    let scheduled = fs::read_to_string(timer_log).unwrap();
    assert!(scheduled.contains("--on-active=30m --"));
    assert!(scheduled.contains("delete allow 22/tcp"));
    let added = fs::read_to_string(upstream_log).unwrap();
    assert!(added.contains("Allow SSH ingress [ttl: 30m, expires-unix:"));
    assert!(added.contains("ttl-id:"));
    fs::remove_dir_all(dir).unwrap();
}
