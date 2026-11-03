use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn setup_mock_ufw() -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let temp_dir = env::temp_dir().join(format!("ufw_test_{}", now));
    fs::create_dir_all(&temp_dir).unwrap();

    let mock_bin = temp_dir.join("mock_ufw");
    let log_file = temp_dir.join("mock_ufw.log");

    let script = format!("#!/bin/sh\necho \"$@\" > {}\nexit 0\n", log_file.display());
    let mut file = File::create(&mock_bin).unwrap();
    file.write_all(script.as_bytes()).unwrap();
    drop(file);

    let mut perms = fs::metadata(&mock_bin).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&mock_bin, perms).unwrap();

    (temp_dir, mock_bin, log_file)
}

#[test]
fn test_integration_flow() {
    let (temp_dir, mock_bin, log_file) = setup_mock_ufw();
    let bin = env!("CARGO_BIN_EXE_ufw");

    // 1. Status passthrough
    let out = Command::new(bin)
        .arg("status")
        .env("UFW_GUARD_UPSTREAM_PATH", &mock_bin)
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(fs::read_to_string(&log_file).unwrap().trim(), "status");

    // 2. Bypass flag
    let out_bypass = Command::new(bin)
        .args(["allow", "22/tcp", "--force-no-comment"])
        .env("UFW_GUARD_UPSTREAM_PATH", &mock_bin)
        .output()
        .unwrap();
    assert!(out_bypass.status.success());
    assert_eq!(
        fs::read_to_string(&log_file).unwrap().trim(),
        "allow 22/tcp"
    );

    // 3. Valid comment rule
    let out_rule = Command::new(bin)
        .args(["allow", "443", "comment", "Web Ingress"])
        .env("UFW_GUARD_UPSTREAM_PATH", &mock_bin)
        .output()
        .unwrap();
    assert!(out_rule.status.success());
    assert_eq!(
        fs::read_to_string(&log_file).unwrap().trim(),
        "allow 443 comment Web Ingress"
    );

    // 4. Missing comment in non-interactive environment fails
    let out_missing = Command::new(bin)
        .args(["allow", "80"])
        .env("UFW_GUARD_UPSTREAM_PATH", &mock_bin)
        .output()
        .unwrap();
    assert!(!out_missing.status.success());

    let _ = fs::remove_dir_all(&temp_dir);
}
