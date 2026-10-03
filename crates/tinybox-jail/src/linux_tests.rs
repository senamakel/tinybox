//! Tests for the Linux Landlock backend.

use super::*;
use std::path::Path;

#[test]
fn landlock_spawns_with_configured_system_read_paths() -> std::io::Result<()> {
    let root = tempfile::tempdir()?;
    let mut jail = Jail::new(root.path(), "landlock-test");
    for path in ["/usr", "/bin", "/lib", "/lib64"] {
        if Path::new(path).exists() {
            jail = jail.add_read_only(path);
        }
    }

    let backend = LandlockBackend::new();
    if !backend.is_available() {
        let error = backend
            .spawn(&jail, Command::new("/usr/bin/true"))
            .err()
            .map(|error| error.kind());
        assert_eq!(error, Some(std::io::ErrorKind::PermissionDenied));
        return Ok(());
    }

    let mut child = backend.spawn(&jail, Command::new("/usr/bin/true"))?;
    assert!(child.wait()?.success());
    Ok(())
}

#[test]
fn landlock_grants_writes_to_read_write_paths_outside_the_root() -> std::io::Result<()> {
    let backend = LandlockBackend::new();
    if !backend.is_available() {
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    let scratch = tempfile::tempdir()?;
    let denied = tempfile::tempdir()?;
    let mut jail = Jail::new(root.path(), "landlock-rw").add_read_write(scratch.path());
    for path in ["/usr", "/bin", "/lib", "/lib64"] {
        if Path::new(path).exists() {
            jail = jail.add_read_only(path);
        }
    }

    let write = |dir: &Path| -> std::io::Result<bool> {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(format!("echo ok > '{}'", dir.join("out").display()));
        Ok(backend.spawn(&jail, cmd)?.wait()?.success())
    };

    assert!(write(scratch.path())?, "read_write path must be writable");
    assert_eq!(std::fs::read_to_string(scratch.path().join("out"))?, "ok\n");
    assert!(!write(denied.path())?, "paths not granted must stay unwritable");
    assert!(!denied.path().join("out").exists());
    Ok(())
}
