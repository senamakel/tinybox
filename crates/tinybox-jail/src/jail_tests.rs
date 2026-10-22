use super::*;

#[cfg(unix)]
#[derive(Debug, Default)]
struct InvocationBackend(std::sync::Mutex<Option<crate::JailInvocation>>);

#[cfg(unix)]
impl crate::JailBackend for InvocationBackend {
    fn name(&self) -> &'static str {
        "invocation-test"
    }

    fn is_available(&self) -> bool {
        true
    }

    fn constraint_support(&self) -> tinybox_core::ConstraintSupport {
        [
            tinybox_core::Constraint::Filesystem,
            tinybox_core::Constraint::Cpu,
            tinybox_core::Constraint::Memory,
            tinybox_core::Constraint::Pids,
        ]
        .into_iter()
        .fold(
            tinybox_core::ConstraintSupport::NONE,
            |support, constraint| support.with(constraint, tinybox_core::Enforcement::Enforced),
        )
    }

    fn spawn(&self, _jail: &Jail, mut command: Command) -> std::io::Result<Child> {
        command.spawn()
    }

    fn spawn_owned_invocation_captured(
        &self,
        jail: &Jail,
        invocation: &crate::JailInvocation,
        command: Command,
    ) -> std::io::Result<crate::OwnedChild> {
        *self
            .0
            .lock()
            .map_err(|_| std::io::Error::other("invocation lock poisoned"))? =
            Some(invocation.clone());
        crate::OwnedChild::from_std(self.spawn_captured(jail, command)?)
    }
}

#[test]
fn defaults_are_permissive() {
    let j = Jail::new("/tmp", "x");
    assert!(j.allow_net);
    assert!(j.allow_subprocess);
    assert_eq!(j.label, "x");
    assert_eq!(j.read_only.len(), 0);
    assert_eq!(j.resources, None);
}

#[cfg(unix)]
#[test]
fn typed_invocation_reaches_backend_without_losing_exec_fields_or_resource_plan()
-> std::io::Result<()> {
    use std::io::{Read, Write};
    let root = tempfile::tempdir()?;
    let canonical_root = root.path().canonicalize()?;
    let backend = InvocationBackend::default();
    let resources = crate::ResourceLimitPlan {
        cpu_millis: Some(750),
        memory_bytes: Some(32 * 1024 * 1024),
        pids_max: Some(4),
        disk_bytes: None,
    };
    let invocation = crate::JailInvocation::new(
        tinybox_core::ExecRequest::new([
            "/bin/sh",
            "-c",
            "printf '%s|%s|%s|%s|' \"$APPROVED\" \"${HOME-unset}\" \"$PWD\" \"$1\"; printf stderr-kept >&2; IFS= read -r input; printf '%s' \"$input\"",
            "sh",
            "argument-kept",
        ])
        .with_cwd(root.path())
        .with_env("APPROVED", "yes")
        .with_stdin(b"stdin-kept\n".to_vec()),
        true,
        Some(resources),
    );
    let jail = Jail::new(root.path(), "typed-invocation");
    let mut child = crate::spawn_owned_invocation_captured_with(&backend, &jail, &invocation)?;
    child
        .take_stdin()
        .ok_or_else(|| std::io::Error::other("captured stdin missing"))?
        .write_all(b"stdin-kept\n")?;
    let mut stdout = String::new();
    let mut stderr = String::new();
    child
        .stdout_mut()
        .ok_or_else(|| std::io::Error::other("captured stdout missing"))?
        .read_to_string(&mut stdout)?;
    child
        .take_stderr()
        .ok_or_else(|| std::io::Error::other("captured stderr missing"))?
        .read_to_string(&mut stderr)?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "typed invocation child did not exit",
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };

    assert_eq!(status.code(), Some(0));
    assert_eq!(
        stdout,
        format!(
            "yes|unset|{}|argument-kept|stdin-kept",
            canonical_root.display()
        )
    );
    assert_eq!(stderr, "stderr-kept");
    assert_eq!(
        backend
            .0
            .lock()
            .map_err(|_| std::io::Error::other("invocation lock poisoned"))?
            .as_ref(),
        Some(&invocation)
    );
    Ok(())
}

#[test]
fn typed_invocation_refuses_an_unsupported_requested_dimension_before_spawn() -> std::io::Result<()>
{
    let root = tempfile::tempdir()?;
    let marker = root.path().join("must-not-run");
    let command =
        tinybox_core::ExecRequest::new(["/bin/sh", "-c", "printf launched > must-not-run"])
            .with_cwd(root.path());
    let invocation = crate::JailInvocation::new(
        command,
        true,
        Some(crate::ResourceLimitPlan {
            disk_bytes: Some(1024),
            ..crate::ResourceLimitPlan::default()
        }),
    );
    let error = crate::spawn_owned_invocation_captured_with(
        &crate::NoopBackend,
        &Jail::new(root.path(), "unsupported-limit"),
        &invocation,
    )
    .err();

    assert_eq!(
        error.map(|error| error.kind()),
        Some(std::io::ErrorKind::Unsupported)
    );
    assert!(!marker.exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn default_typed_invocation_adapter_keeps_captured_output_and_status() -> std::io::Result<()> {
    use std::io::Read;

    let root = tempfile::tempdir()?;
    let invocation = crate::JailInvocation::new(
        tinybox_core::ExecRequest::new(["/bin/sh", "-c", "printf adapter-kept; exit 7"]),
        true,
        None,
    );
    let mut child = crate::spawn_owned_invocation_captured_with(
        &crate::NoopBackend,
        &Jail::new(root.path(), "typed-adapter"),
        &invocation,
    )?;
    let mut stdout = String::new();
    child
        .take_stdout()
        .ok_or_else(|| std::io::Error::other("captured stdout missing"))?
        .read_to_string(&mut stdout)?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "typed adapter child did not exit",
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };

    assert_eq!(stdout, "adapter-kept");
    assert_eq!(status.code(), Some(7));
    Ok(())
}

#[test]
fn requested_resources_become_hard_constraints() {
    let mut jail = Jail::new("/tmp", "x");
    jail.resources = Some(tinybox_core::Resources::DEFAULT);
    assert_eq!(
        jail.constraints(),
        vec![
            tinybox_core::Constraint::Filesystem,
            tinybox_core::Constraint::Cpu,
            tinybox_core::Constraint::Memory,
            tinybox_core::Constraint::Pids,
            tinybox_core::Constraint::Disk,
        ]
    );
}

#[test]
fn deny_net_is_idempotent() {
    let j = Jail::new("/tmp", "x").deny_net().deny_net();
    assert!(!j.allow_net);
}

#[test]
fn deny_subprocess_is_idempotent() {
    let j = Jail::new("/tmp", "x").deny_subprocess().deny_subprocess();
    assert!(!j.allow_subprocess);
}

#[test]
fn add_read_only_appends_in_order() {
    let j = Jail::new("/tmp", "x")
        .add_read_only("/a")
        .add_read_only("/b")
        .add_read_only("/c");
    assert_eq!(j.read_only.len(), 3);
    assert_eq!(j.read_only[0], PathBuf::from("/a"));
    assert_eq!(j.read_only[2], PathBuf::from("/c"));
}

#[test]
fn canonicalize_resolves_real_path() {
    let dir = std::env::temp_dir();
    let mut j = Jail::new(&dir, "x");
    j.canonicalize().unwrap();
    // After canonicalize, root has no `..` and resolves to a real path.
    assert!(j.root.is_absolute());
    assert!(j.root.exists());
}

#[test]
fn canonicalize_swallows_missing_read_only() {
    // read_only entries that don't exist are silently dropped from
    // canonicalization (they stay as-is). Verify no panic.
    let dir = std::env::temp_dir();
    let mut j = Jail::new(&dir, "x").add_read_only("/this/never/existed");
    j.canonicalize().unwrap();
    assert_eq!(j.read_only.len(), 1);
}

#[test]
fn canonicalize_errors_on_missing_root() {
    let mut j = Jail::new("/no/such/root/here", "x");
    let err = j.canonicalize().unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn defaults_have_no_extra_read_write_paths() {
    let j = Jail::new("/tmp", "x");
    assert_eq!(j.read_write, Vec::<PathBuf>::new());
}

#[test]
fn add_read_write_appends_in_order_and_leaves_read_only_alone() {
    let j = Jail::new("/tmp", "x")
        .add_read_write("/a")
        .add_read_write("/b");
    assert_eq!(j.read_write, vec![PathBuf::from("/a"), PathBuf::from("/b")]);
    assert_eq!(j.read_only, Vec::<PathBuf>::new());
    assert_eq!(j.root, PathBuf::from("/tmp"));
}

#[test]
fn canonicalize_resolves_read_write_paths() {
    let root = tempfile::tempdir().unwrap();
    let extra = tempfile::tempdir().unwrap();
    let dotted = extra.path().join("sub").join("..");
    std::fs::create_dir_all(extra.path().join("sub")).unwrap();
    let mut j = Jail::new(root.path(), "x").add_read_write(&dotted);
    j.canonicalize().unwrap();
    assert_eq!(j.read_write, vec![extra.path().canonicalize().unwrap()]);
}

#[test]
fn canonicalize_keeps_missing_read_write_as_is() {
    let root = tempfile::tempdir().unwrap();
    let mut j = Jail::new(root.path(), "x").add_read_write("/this/never/existed");
    j.canonicalize().unwrap();
    assert_eq!(j.read_write, vec![PathBuf::from("/this/never/existed")]);
}

#[cfg(unix)]
#[test]
fn owned_captured_spawn_preserves_both_pipes_and_exit_status() -> std::io::Result<()> {
    use std::io::Read;
    use std::time::{Duration, Instant};

    let root = tempfile::tempdir()?;
    let jail = Jail::new(root.path(), "owned-captured-spawn");
    let backend = crate::NoopBackend;
    let mut command = std::process::Command::new("/bin/sh");
    command.args([
        "-c",
        "printf stdout-marker; printf stderr-marker >&2; exit 23",
    ]);

    let mut child = crate::spawn_owned_captured_with(&backend, &jail, command)?;
    let mut stdout = String::new();
    let mut stderr = String::new();
    child
        .stdout_mut()
        .expect("captured stdout")
        .read_to_string(&mut stdout)?;
    child
        .stderr_mut()
        .expect("captured stderr")
        .read_to_string(&mut stderr)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "child did not exit",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    };

    assert_eq!(stdout, "stdout-marker");
    assert_eq!(stderr, "stderr-marker");
    assert_eq!(status.code(), Some(23));
    assert!(!status.success());
    Ok(())
}

#[cfg(unix)]
#[test]
fn canonicalize_deduplicates_denials_that_resolve_through_symlink_aliases() -> std::io::Result<()> {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    let credential = store.path().join("credential");
    std::fs::write(&credential, b"secret")?;
    let alias = root.path().join("credential-alias");
    symlink(&credential, &alias)?;
    let mut jail = Jail::new(root.path(), "alias-denial");
    jail.deny_read = vec![alias, credential.clone()];

    jail.canonicalize()?;

    assert_eq!(jail.deny_read, vec![credential.canonicalize()?]);
    Ok(())
}

#[cfg(unix)]
#[test]
fn a_nested_grant_through_a_symlink_planted_in_a_writable_root_is_refused() -> std::io::Result<()> {
    let root = tempfile::tempdir()?;
    let secret = tempfile::tempdir()?;
    std::os::unix::fs::symlink(secret.path(), root.path().join("vendor"))?;
    let mut jail = Jail::new(root.path(), "t").add_read_only(root.path().join("vendor"));
    let err = jail.canonicalize().err().map(|e| e.kind());
    assert_eq!(err, Some(std::io::ErrorKind::InvalidInput));

    // Same through a read-write grant, and through a deeper component.
    let rw = tempfile::tempdir()?;
    std::fs::create_dir(rw.path().join("a"))?;
    std::os::unix::fs::symlink(secret.path(), rw.path().join("a").join("link"))?;
    let mut jail = Jail::new(root.path(), "t")
        .add_read_write(rw.path())
        .add_read_only(rw.path().join("a").join("link").join("x"));
    assert!(jail.canonicalize().is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn a_symlinked_grant_outside_any_writable_ancestor_is_still_allowed() -> std::io::Result<()> {
    let root = tempfile::tempdir()?;
    let target = tempfile::tempdir()?;
    let holder = tempfile::tempdir()?;
    let link = holder.path().join("tools");
    std::os::unix::fs::symlink(target.path(), &link)?;
    let mut jail = Jail::new(root.path(), "t").add_read_only(&link);
    jail.canonicalize()?;
    assert_eq!(jail.read_only, vec![target.path().canonicalize()?]);
    Ok(())
}

#[cfg(unix)]
#[test]
fn the_check_sees_a_planted_link_however_the_root_is_spelled() -> std::io::Result<()> {
    let root = tempfile::tempdir()?;
    let secret = tempfile::tempdir()?;
    std::os::unix::fs::symlink(secret.path(), root.path().join("vendor"))?;
    let holder = tempfile::tempdir()?;
    let alias = holder.path().join("alias");
    std::os::unix::fs::symlink(root.path(), &alias)?;
    // Root given by its real path, grant spelled through the alias (and the
    // reverse): both must be refused.
    for (writable, grant) in [
        (root.path().to_path_buf(), alias.join("vendor")),
        (alias.clone(), root.path().join("vendor")),
    ] {
        let err = crate::reject_symlinked_grants(&[writable.as_path()], &[grant.as_path()])
            .err()
            .map(|e| e.kind());
        assert_eq!(err, Some(std::io::ErrorKind::InvalidInput), "{grant:?}");
    }
    Ok(())
}
