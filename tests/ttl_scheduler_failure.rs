use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn scheduler_failure_prevents_rule_creation() {
    let dir = env::temp_dir().join(format!(
        "ufw_ttl_scheduler_failure_{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let bin_dir = dir.join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let upstream = dir.join("mock-ufw");
    let upstream_log = dir.join("upstream.log");
    let scheduler = bin_dir.join("systemd-run");
    fs::write(&upstream, "#!/bin/sh\nprintf 'added' > \"$UPSTREAM_LOG\"\n").unwrap();
    fs::write(
        &scheduler,
        "#!/bin/sh\necho 'scheduler unavailable' >&2\nexit 1\n",
    )
    .unwrap();
    for path in [&upstream, &scheduler] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let config = dir.join("ufw-guard.conf");
    fs::write(&config, "auto_append_user = false\n").unwrap();
    let path = env::join_paths(
        std::iter::once(bin_dir).chain(env::split_paths(&env::var_os("PATH").unwrap())),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_ufw"))
        .args(["allow", "22/tcp", "comment", "Temporary SSH", "--ttl", "5m"])
        .env("PATH", path)
        .env("UFW_GUARD_UPSTREAM_PATH", &upstream)
        .env("UFW_GUARD_CONFIG", config)
        .env("UFW_GUARD_LOG_FILE", dir.join("audit.log"))
        .env("UFW_GUARD_NON_INTERACTIVE", "1")
        .env("UPSTREAM_LOG", &upstream_log)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("scheduler unavailable"));
    assert!(!upstream_log.exists());
    fs::remove_dir_all(dir).unwrap();
}
