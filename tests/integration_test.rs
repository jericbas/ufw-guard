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
    let audit_log = temp_dir.join("audit.log");
    let bin = env!("CARGO_BIN_EXE_ufw");

    // 1. Status passthrough
    let out = Command::new(bin)
        .arg("status")
        .env("UFW_GUARD_UPSTREAM_PATH", &mock_bin)
        .env("UFW_GUARD_LOG_FILE", &audit_log)
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(fs::read_to_string(&log_file).unwrap().trim(), "status");

    // 2. Bypass flag with audit capture
    let out_bypass = Command::new(bin)
        .args(["allow", "22/tcp", "--force-no-comment"])
        .env("UFW_GUARD_UPSTREAM_PATH", &mock_bin)
        .env("UFW_GUARD_LOG_FILE", &audit_log)
        .env("SUDO_USER", "secops_admin")
        .output()
        .unwrap();
    assert!(out_bypass.status.success());
    assert_eq!(
        fs::read_to_string(&log_file).unwrap().trim(),
        "allow 22/tcp"
    );

    // 3. Valid comment rule with automatic metadata attribution
    let out_rule = Command::new(bin)
        .args(["allow", "443", "comment", "Web Ingress"])
        .env("UFW_GUARD_UPSTREAM_PATH", &mock_bin)
        .env("UFW_GUARD_LOG_FILE", &audit_log)
        .env("UFW_GUARD_AUTO_ATTRIBUTION", "1")
        .env("UFW_GUARD_ATTRIBUTION_DATE", "2026-11-04")
        .env("SUDO_USER", "secops_admin")
        .output()
        .unwrap();
    assert!(out_rule.status.success());
    assert_eq!(
        fs::read_to_string(&log_file).unwrap().trim(),
        "allow 443 comment Web Ingress [by: secops_admin @ 2026-11-04]"
    );

    // 4. Missing comment in non-interactive environment fails
    let out_missing = Command::new(bin)
        .args(["allow", "80"])
        .env("UFW_GUARD_UPSTREAM_PATH", &mock_bin)
        .env("UFW_GUARD_LOG_FILE", &audit_log)
        .env("UFW_GUARD_NON_INTERACTIVE", "1")
        .output()
        .unwrap();
    assert!(!out_missing.status.success());

    // 5. Placeholder comment rejection in non-interactive environment fails
    let out_placeholder = Command::new(bin)
        .args(["allow", "80", "comment", "test"])
        .env("UFW_GUARD_UPSTREAM_PATH", &mock_bin)
        .env("UFW_GUARD_LOG_FILE", &audit_log)
        .env("UFW_GUARD_NON_INTERACTIVE", "1")
        .output()
        .unwrap();
    assert!(!out_placeholder.status.success());
    let stderr_str = String::from_utf8(out_placeholder.stderr).unwrap();
    assert!(stderr_str.contains("generic placeholder"));

    // 6. Verify audit log captures events
    let audit_content = fs::read_to_string(&audit_log).unwrap();
    assert!(audit_content.contains(r#""event":"bypass""#));
    assert!(audit_content.contains(r#""user":"secops_admin""#));
    assert!(audit_content.contains(r#""event":"rule_executed""#));
    assert!(audit_content.contains(r#""event":"rule_rejected""#));

    let _ = fs::remove_dir_all(&temp_dir);
}

fn mock_with_script(body: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = env::temp_dir().join(format!("ufw_test_cfg_{}", now));
    fs::create_dir_all(&dir).unwrap();
    let bin = dir.join("mock_ufw");
    fs::write(&bin, format!("#!/bin/sh\n{}\n", body)).unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
    (dir, bin)
}

#[test]
fn test_audit_reports_uncommented_rules() {
    let (dir, bin) = mock_with_script(
        "if [ \"$1 $2\" = \"show added\" ]; then\n\
         echo \"Added user rules (see 'ufw status' for running firewall):\"\n\
         echo \"ufw allow 22/tcp\"\n\
         echo \"ufw allow 80/tcp comment 'Web ingress'\"\n\
         fi",
    );
    let out = Command::new(env!("CARGO_BIN_EXE_ufw"))
        .arg("--audit")
        .env("UFW_GUARD_UPSTREAM_PATH", &bin)
        .env("UFW_GUARD_CONFIG", dir.join("none.conf"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("#1: ufw allow 22/tcp  (missing comment)"));
    assert!(stdout.contains("1 of 2 rule(s) non-compliant."));
}

#[test]
fn test_audit_clean_exits_zero() {
    let (dir, bin) = mock_with_script("echo \"ufw allow 80/tcp comment 'Web ingress'\"");
    let out = Command::new(env!("CARGO_BIN_EXE_ufw"))
        .arg("--audit")
        .env("UFW_GUARD_UPSTREAM_PATH", &bin)
        .env("UFW_GUARD_CONFIG", dir.join("none.conf"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn test_remediate_requires_terminal() {
    let (dir, bin) = mock_with_script("exit 0");
    let out = Command::new(env!("CARGO_BIN_EXE_ufw"))
        .arg("--remediate")
        .env("UFW_GUARD_UPSTREAM_PATH", &bin)
        .env("UFW_GUARD_CONFIG", dir.join("none.conf"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn test_config_file_disables_bypass_and_requires_delete_comment() {
    let (dir, bin) = mock_with_script("echo \"$@\"");
    let conf = dir.join("ufw-guard.conf");
    fs::write(
        &conf,
        "allow_bypass = false\nrequire_comment_on_delete = true\n",
    )
    .unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_ufw"))
            .args(args)
            .env("UFW_GUARD_UPSTREAM_PATH", &bin)
            .env("UFW_GUARD_CONFIG", &conf)
            .env("UFW_GUARD_NON_INTERACTIVE", "1")
            .env("UFW_GUARD_AUDIT_ENABLED", "0")
            .env("UFW_GUARD_BYPASS", "1")
            .output()
            .unwrap()
    };
    let out = run(&["allow", "22/tcp", "--force-no-comment"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Bypass is disabled"));

    // Env bypass is ignored under strict policy: uncommented rule is rejected.
    assert_eq!(run(&["allow", "22/tcp"]).status.code(), Some(1));

    assert_eq!(run(&["delete", "allow", "22/tcp"]).status.code(), Some(1));
    let out = run(&["delete", "allow", "22/tcp", "comment", "Closing legacy SSH"]);
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "delete allow 22/tcp"
    );
}

#[test]
fn test_malformed_config_fails_closed() {
    let (dir, bin) = mock_with_script("exit 0");
    let conf = dir.join("bad.conf");
    fs::write(&conf, "allow_bypass = nope\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ufw"))
        .arg("status")
        .env("UFW_GUARD_UPSTREAM_PATH", &bin)
        .env("UFW_GUARD_CONFIG", &conf)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
}
