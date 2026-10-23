use super::*;

#[test]
fn appcontainer_backend_is_available_through_owned_process_supervision() {
    assert!(AppContainerBackend::new().is_available());
    assert_eq!(crate::detect::pick_owned_backend().name(), "appcontainer");
    assert_eq!(
        crate::detect::pick_backend().name(),
        crate::detect::UNSUPPORTED_BACKEND_NAME,
        "the legacy std::process::Child API remains fail-closed on Windows"
    );
}

#[test]
fn appcontainer_plan_check_keeps_cpu_unsupported_and_reports_job_limits() {
    use tinybox_core::{Constraint, Enforcement};

    let support = AppContainerBackend::new().constraint_support();
    assert_eq!(
        support.enforcement(Constraint::Cpu),
        Enforcement::Unsupported,
        "Windows CPU quota enforcement remains deferred"
    );
    assert_eq!(
        support.enforcement(Constraint::Memory),
        Enforcement::Enforced
    );
    assert_eq!(support.enforcement(Constraint::Pids), Enforcement::Enforced);
}

#[test]
fn appcontainer_profiles_are_unique_to_avoid_reusing_old_path_acl_grants() {
    let first = unique_profile_name();
    let second = unique_profile_name();
    assert_ne!(first, second);
    assert!(first.len() <= 64, "profile name exceeds Windows' limit");
    assert!(second.len() <= 64, "profile name exceeds Windows' limit");
}

#[test]
fn appcontainer_job_limits_map_memory_and_process_count_without_cpu_claims() {
    use tinybox_core::{Constraint, Enforcement};

    let root = tempfile::tempdir().unwrap();
    let limits = job_limits(
        &Jail::new(root.path(), "job-limit-map"),
        Some(ResourceLimitPlan {
            memory_bytes: Some(128 * 1024 * 1024),
            pids_max: Some(3),
            ..ResourceLimitPlan::default()
        }),
    )
    .unwrap();
    assert!(limits.kills_on_close());
    assert_eq!(limits.job_memory_limit(), Some(128 * 1024 * 1024));
    assert_eq!(limits.active_process_limit(), Some(3));
    assert_eq!(
        AppContainerBackend::new()
            .constraint_support()
            .enforcement(Constraint::Cpu),
        Enforcement::Unsupported
    );
}

#[test]
fn appcontainer_owned_launch_captures_output_from_a_confined_child() -> io::Result<()> {
    use std::io::Read;
    use tinybox_core::ExecRequest;
    use win_custody::{Process, ProcessAccess};

    let backend = AppContainerBackend::new();
    let root = tempfile::tempdir()?;
    let command = std::env::var_os("ComSpec")
        .unwrap_or_else(|| r"C:\Windows\System32\cmd.exe".into())
        .to_string_lossy()
        .into_owned();
    let invocation = JailInvocation::new(
        ExecRequest::new([
            command.as_str(),
            "/D",
            "/C",
            "echo appcontainer-owned > marker.txt & type marker.txt",
        ])
        .with_cwd(root.path()),
        true,
        None,
    );
    let mut child = crate::spawn_owned_invocation_captured_with(
        &backend,
        &Jail::new(root.path(), "owned-child-live-test"),
        &invocation,
    )?;
    let pid = child
        .id()
        .ok_or_else(|| io::Error::other("AppContainer child PID unavailable"))?;
    let process = Process::open(pid, ProcessAccess::QueryLimitedAndSynchronize)?;
    assert!(process.is_app_container()?);

    let mut output = String::new();
    child
        .take_stdout()
        .ok_or_else(|| io::Error::other("captured stdout missing"))?
        .read_to_string(&mut output)?;
    let status = child
        .try_wait()?
        .ok_or_else(|| io::Error::other("AppContainer child still running after stdout closed"))?;

    assert!(status.success(), "unexpected child status: {status:?}");
    assert_eq!(output.trim(), "appcontainer-owned");
    assert_eq!(
        std::fs::read_to_string(root.path().join("marker.txt"))?.trim(),
        "appcontainer-owned"
    );
    Ok(())
}

#[test]
fn windows_appcontainer_process_limit_refuses_child_creation() -> io::Result<()> {
    use std::io::Read;
    use tinybox_core::ExecRequest;

    let root = tempfile::tempdir()?;
    let command = std::env::var_os("ComSpec")
        .unwrap_or_else(|| r"C:\Windows\System32\cmd.exe".into())
        .to_string_lossy()
        .into_owned();
    let invocation = JailInvocation::new(
        ExecRequest::new([
            command.as_str(),
            "/D",
            "/C",
            "start \"\" /B cmd.exe /D /C \"echo child > child.txt\" & timeout /T 2 >NUL",
        ])
        .with_cwd(root.path()),
        true,
        Some(ResourceLimitPlan {
            pids_max: Some(1),
            ..ResourceLimitPlan::default()
        }),
    );
    let mut child = crate::spawn_owned_invocation_captured_with(
        &AppContainerBackend::new(),
        &Jail::new(root.path(), "owned-child-pids-test"),
        &invocation,
    )?;
    let mut output = String::new();
    child
        .take_stdout()
        .ok_or_else(|| io::Error::other("captured stdout missing"))?
        .read_to_string(&mut output)?;
    let status = child
        .try_wait()?
        .ok_or_else(|| io::Error::other("AppContainer child still running after stdout closed"))?;

    assert!(
        status.success(),
        "unexpected parent status: {status:?}; {output}"
    );
    assert!(
        !root.path().join("child.txt").exists(),
        "the one-process Job Object limit must prevent descendant creation"
    );
    Ok(())
}

#[test]
fn appcontainer_denies_reads_and_writes_outside_granted_roots() -> io::Result<()> {
    use std::io::Read;
    use tinybox_core::ExecRequest;

    let root = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    let secret = outside.path().join("secret.txt");
    let escaped = outside.path().join("escaped.txt");
    let copied = root.path().join("copied.txt");
    std::fs::write(&secret, b"outside-secret")?;
    let command = std::env::var_os("ComSpec")
        .unwrap_or_else(|| r"C:\Windows\System32\cmd.exe".into())
        .to_string_lossy()
        .into_owned();
    let script = format!(
        "type \"{}\" > \"{}\" 2>NUL & echo escaped > \"{}\"",
        secret.display(),
        copied.display(),
        escaped.display()
    );
    let invocation = JailInvocation::new(
        ExecRequest::new([command.as_str(), "/D", "/C", script.as_str()]).with_cwd(root.path()),
        true,
        None,
    );
    let mut child = crate::spawn_owned_invocation_captured_with(
        &AppContainerBackend::new(),
        &Jail::new(root.path(), "owned-child-denial-test").deny_net(),
        &invocation,
    )?;
    let mut output = String::new();
    child
        .take_stdout()
        .ok_or_else(|| io::Error::other("captured stdout missing"))?
        .read_to_string(&mut output)?;
    let _ = child
        .try_wait()?
        .ok_or_else(|| io::Error::other("AppContainer child still running after stdout closed"))?;

    assert!(
        !escaped.exists(),
        "write outside the grant should be denied"
    );
    assert_eq!(
        std::fs::read(&copied)?,
        [],
        "reading an outside file should be denied"
    );
    assert!(!output.contains("outside-secret"));
    Ok(())
}
