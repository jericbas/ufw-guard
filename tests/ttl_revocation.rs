use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use ufw_guard::ttl_revocation::{systemd_run_arguments, EXPIRATION_FLAG};

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

#[test]
fn scheduler_arguments_keep_the_timer_command_as_separate_arguments() {
    assert_eq!(
        systemd_run_arguments(
            "30m",
            Path::new("/usr/local/sbin/ufw"),
            "42-123",
            Path::new("/usr/sbin/ufw.real"),
            &args(&["delete", "allow", "22"])
        ),
        args(&[
            "--on-active=30m",
            "--",
            "/usr/local/sbin/ufw",
            EXPIRATION_FLAG,
            "42-123",
            "/usr/sbin/ufw.real",
            "delete",
            "allow",
            "22"
        ]),
    );
}

#[test]
fn stale_expiration_skips_a_rule_without_its_unique_marker() {
    let dir = env::temp_dir().join(format!(
        "ufw_ttl_expiration_{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    let upstream = dir.join("mock-ufw");
    let log = dir.join("delete.log");
    fs::write(
        &upstream,
        "#!/bin/sh\nif [ \"$1 $2\" = \"show added\" ]; then echo \"ufw allow 22/tcp comment 'SSH [ttl-id: newer-rule]'\"; else printf '%s\\n' \"$*\" > \"$DELETE_LOG\"; fi\n",
    )
    .unwrap();
    fs::set_permissions(&upstream, fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_ufw"))
        .args([
            "--expire-rule",
            "old-rule",
            upstream.to_str().unwrap(),
            "delete",
            "allow",
            "22/tcp",
        ])
        .env("DELETE_LOG", &log)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("skipping removal"));
    assert!(!log.exists());
    fs::remove_dir_all(dir).unwrap();
}
