//! Upstream binary validation and execution passthrough.

use std::env;
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const DEFAULT_UPSTREAM_PATH: &str = "/usr/sbin/ufw";
pub const DIVERTED_UPSTREAM_PATH: &str = "/usr/sbin/ufw.real";
pub const UPSTREAM_PATH_ENV: &str = "UFW_GUARD_UPSTREAM_PATH";

pub fn resolve_upstream_path() -> PathBuf {
    let override_path = env::var_os(UPSTREAM_PATH_ENV).map(PathBuf::from);
    resolve_upstream_path_with(
        override_path,
        Path::new(DIVERTED_UPSTREAM_PATH),
        Path::new(DEFAULT_UPSTREAM_PATH),
    )
}

fn resolve_upstream_path_with(
    override_path: Option<PathBuf>,
    diverted_path: &Path,
    default_path: &Path,
) -> PathBuf {
    if let Some(path) = override_path {
        return path;
    }
    if diverted_path.is_file() {
        return diverted_path.to_path_buf();
    }
    default_path.to_path_buf()
}

pub fn validate_upstream_binary(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Err(format!(
            "Upstream UFW binary not found at {}",
            path.display()
        ));
    }
    let metadata = path
        .metadata()
        .map_err(|e| format!("Cannot read metadata for {}: {}", path.display(), e))?;

    let permissions = metadata.permissions();
    if permissions.mode() & 0o111 == 0 {
        return Err(format!(
            "Upstream UFW binary at {} is not executable",
            path.display()
        ));
    }

    Ok(())
}

pub fn execute_upstream(path: &Path, args: &[String]) -> Result<(), String> {
    validate_upstream_binary(path)?;

    let mut command = Command::new(path);
    command.args(args);

    #[cfg(unix)]
    {
        let err = command.exec();
        Err(format!(
            "Failed to exec upstream binary {}: {}",
            path.display(),
            err
        ))
    }

    #[cfg(not(unix))]
    {
        let mut child = command
            .spawn()
            .map_err(|e| format!("Failed to spawn {}: {}", path.display(), e))?;
        let status = child
            .wait()
            .map_err(|e| format!("Error waiting on child: {}", e))?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn test_resolve_default_path() {
        assert_eq!(
            resolve_upstream_path_with(
                None,
                Path::new("/dev/null/ufw-guard-no-diversion"),
                Path::new(DEFAULT_UPSTREAM_PATH),
            ),
            PathBuf::from(DEFAULT_UPSTREAM_PATH),
        );
    }

    #[test]
    fn test_resolve_diverted_path() {
        let diverted = env::temp_dir().join(format!("ufw-real-{}", std::process::id()));
        File::create(&diverted).unwrap();
        assert_eq!(
            resolve_upstream_path_with(None, &diverted, Path::new(DEFAULT_UPSTREAM_PATH)),
            diverted,
        );
        let _ = fs::remove_file(diverted);
    }

    #[test]
    fn test_upstream_override_precedes_diverted_path() {
        let override_path = PathBuf::from("/tmp/custom-ufw");
        let diverted = Path::new("/usr/sbin/ufw.real");
        assert_eq!(
            resolve_upstream_path_with(
                Some(override_path.clone()),
                diverted,
                Path::new(DEFAULT_UPSTREAM_PATH),
            ),
            override_path,
        );
    }

    #[test]
    fn test_non_existent_binary() {
        let fake = Path::new("/tmp/nonexistent_ufw_path_test_1234");
        assert!(validate_upstream_binary(fake).is_err());
    }

    #[test]
    fn test_valid_executable_binary() {
        let temp_dir = env::temp_dir();
        let test_bin = temp_dir.join("ufw_test_mock_bin");
        File::create(&test_bin).unwrap();
        let mut perms = fs::metadata(&test_bin).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&test_bin, perms).unwrap();

        assert!(validate_upstream_binary(&test_bin).is_ok());
        let _ = fs::remove_file(test_bin);
    }
}
