use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn noninteractive_permanent_rule_prints_warning_and_forwards_clean_args() {
    let dir = env::temp_dir().join(format!(
        "ufw_ttl_warning_{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    let upstream = dir.join("mock-ufw");
    let log = dir.join("upstream.log");
    fs::write(
        &upstream,
        "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$UPSTREAM_LOG\"\n",
    )
    .unwrap();
    fs::set_permissions(&upstream, fs::Permissions::from_mode(0o755)).unwrap();
    let config = dir.join("ufw-guard.conf");
    fs::write(&config, "auto_append_user = false\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_ufw"))
        .args(["allow", "22/tcp", "--force-no-comment"])
        .env("UFW_GUARD_UPSTREAM_PATH", &upstream)
        .env("UFW_GUARD_CONFIG", config)
        .env("UFW_GUARD_LOG_FILE", dir.join("audit.log"))
        .env("UFW_GUARD_NON_INTERACTIVE", "1")
        .env("UPSTREAM_LOG", &log)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("No TTL set"));
    assert_eq!(fs::read_to_string(log).unwrap().trim(), "allow 22/tcp");
    fs::remove_dir_all(dir).unwrap();
}
