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
fn appcontainer_drive_environment_uses_a_dos_path_for_verbatim_cwds() {
    let cwd = Path::new(r"\\?\C:\sandbox\root");

    let (drive, environment_cwd) = drive_current_directory(cwd).unwrap();

    assert_eq!(drive, 'C');
    assert_eq!(environment_cwd, Path::new(r"C:\sandbox\root"));
}

#[test]
fn appcontainer_local_app_data_must_be_present_and_absolute() {
    assert_eq!(
        validate_local_app_data(None).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    assert_eq!(
        validate_local_app_data(Some(OsString::from(r"relative\profile")))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    let nul_path = OsString::from_wide(&[
        u16::from(b'C'),
        u16::from(b':'),
        u16::from(b'\\'),
        u16::from(b'x'),
        0,
    ]);
    assert_eq!(
        validate_local_app_data(Some(nul_path)).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(
        validate_local_app_data(Some(OsString::from(r"C:\Users\agent\AppData\Local"))).unwrap(),
        OsString::from(r"C:\Users\agent\AppData\Local")
    );
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
fn appcontainer_untyped_owned_launch_does_not_inherit_the_host_environment() -> io::Result<()> {
    use std::io::Read;

    const ALLOWED_ENV: &str = "TINYBOX_APPCONTAINER_EXPLICIT_ENV";
    let root = tempfile::tempdir()?;
    let command = std::env::var_os("ComSpec")
        .unwrap_or_else(|| r"C:\Windows\System32\cmd.exe".into())
        .to_string_lossy()
        .into_owned();
    let mut command = Command::new(command);
    command
        .args([
            "/D",
            "/C",
            "echo %TINYBOX_APPCONTAINER_EXPLICIT_ENV% & echo %SystemRoot% & echo %LOCALAPPDATA% & if defined PATH (echo inherited) else (echo cleared)",
        ])
        .current_dir(root.path())
        .env(ALLOWED_ENV, "explicit-value");

    let mut child = crate::spawn_owned_captured_with(
        &AppContainerBackend::new(),
        &Jail::new(root.path(), "owned-command-env-test"),
        command,
    )?;
    let mut output = String::new();
    child
        .take_stdout()
        .ok_or_else(|| io::Error::other("captured stdout missing"))?
        .read_to_string(&mut output)?;
    let status = child
        .try_wait()?
        .ok_or_else(|| io::Error::other("AppContainer child still running after stdout closed"))?;

    assert!(status.success(), "unexpected child status: {status:?}");
    let lines = output.lines().map(str::trim).collect::<Vec<_>>();
    assert_eq!(lines.first(), Some(&"explicit-value"));
    assert_eq!(
        lines.get(1).map(|value| value.to_ascii_lowercase()),
        std::env::var("SystemRoot")
            .ok()
            .map(|value| value.to_ascii_lowercase())
    );
    let host_local_app_data = std::env::var("LOCALAPPDATA")
        .map_err(io::Error::other)?
        .to_ascii_lowercase();
    let child_local_app_data = lines
        .get(2)
        .ok_or_else(|| io::Error::other("child did not print LOCALAPPDATA"))?
        .to_ascii_lowercase();
    let package_root = format!("{}\\packages\\", host_local_app_data.trim_end_matches('\\'));
    let package_profile = child_local_app_data.strip_prefix(&package_root);
    assert!(
        package_profile
            .is_some_and(|profile| profile.starts_with("tinybox.") && profile.ends_with("\\ac")),
        "AppContainer LOCALAPPDATA should resolve inside its package profile: child={child_local_app_data:?}, host={host_local_app_data:?}"
    );
    assert_eq!(lines.get(3), Some(&"cleared"));
    Ok(())
}

#[test]
fn appcontainer_process_limit_child_creation_is_denied() -> io::Result<()> {
    use std::thread;
    use std::time::{Duration, Instant};
    use tinybox_core::ExecRequest;

    let root = tempfile::tempdir()?;
    let test_executable = std::env::current_exe()?;
    let executable_directory = test_executable.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "test executable has no parent directory",
        )
    })?;
    const CHILD_PROBE: &str = "TINYBOX_APPCONTAINER_PROCESS_LIMIT_CHILD_PROBE";
    let invocation = JailInvocation::new(
        ExecRequest::new(vec![
            test_executable.to_string_lossy().into_owned(),
            "--exact".to_owned(),
            "windows::tests::appcontainer_process_limit_child_probe".to_owned(),
            "--nocapture".to_owned(),
        ])
        .with_cwd(root.path())
        .with_env(CHILD_PROBE, "1"),
        true,
        Some(ResourceLimitPlan {
            pids_max: Some(1),
            ..ResourceLimitPlan::default()
        }),
    );
    let jail = Jail::new(root.path(), "owned-child-pids-test").add_read_only(executable_directory);
    let mut child = crate::spawn_owned_invocation_captured_with(
        &AppContainerBackend::new(),
        &jail,
        &invocation,
    )?;
    // The probe test attempts to start a command and records an error if the
    // Job Object rejects it. Avoid shell `start`: it waits inside cmd.exe when
    // the active-process limit blocks child creation. Also avoid reading
    // stdout to EOF because any unexpected descendant could inherit its pipe.
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            child.terminate()?;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "AppContainer process-limit child probe did not exit within 10 seconds",
            ));
        }
        thread::sleep(Duration::from_millis(25));
    };

    assert!(status.success(), "process-limit probe failed: {status:?}");
    assert!(
        !root.path().join("child.txt").exists(),
        "the one-process Job Object limit must prevent descendant creation"
    );
    Ok(())
}

#[test]
fn appcontainer_process_limit_child_probe() {
    if std::env::var_os("TINYBOX_APPCONTAINER_PROCESS_LIMIT_CHILD_PROBE").is_none() {
        return;
    }

    let root = std::env::current_dir().expect("AppContainer probe cwd should be available");
    let command = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join("System32")
        .join("cmd.exe");
    match Command::new(command)
        .args(["/D", "/C", "echo child > child.txt"])
        .current_dir(root)
        .spawn()
    {
        Err(error) => eprintln!("Job Object refused child creation: {error}"),
        Ok(mut child) => {
            let status = child.wait().expect("join the attempted descendant");
            assert!(
                !status.success(),
                "the one-process Job Object limit must terminate the attempted descendant"
            );
            eprintln!("Job Object terminated attempted descendant: {status:?}");
        }
    }
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
        "type \"{}\" > copied.txt 2>NUL & echo escaped > \"{}\"",
        secret.display(),
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
    )
    .map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("spawn outside-root denial probe: {error}"),
        )
    })?;
    let mut output = String::new();
    child
        .take_stdout()
        .ok_or_else(|| io::Error::other("captured stdout missing"))?
        .read_to_string(&mut output)?;
    let mut error_output = String::new();
    child
        .take_stderr()
        .ok_or_else(|| io::Error::other("captured stderr missing"))?
        .read_to_string(&mut error_output)?;
    let status = child
        .try_wait()?
        .ok_or_else(|| io::Error::other("AppContainer child still running after stdout closed"))?;

    assert!(
        !escaped.exists(),
        "write outside the grant should be denied"
    );
    let copied_contents = std::fs::read(&copied).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "read in-root redirection output after child status {status:?}, output {output:?}, and stderr {error_output:?}: {error}"
            ),
        )
    })?;
    assert!(
        copied_contents.is_empty(),
        "reading an outside file should be denied"
    );
    assert!(!output.contains("outside-secret"));
    Ok(())
}
