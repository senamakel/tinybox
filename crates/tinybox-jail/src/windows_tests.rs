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
fn appcontainer_owned_termination_stops_descendants_after_parent_exit() -> io::Result<()> {
    use std::{
        io::Read,
        thread,
        time::{Duration, Instant},
    };
    use tinybox_core::ExecRequest;
    use win_custody::{Process, ProcessAccess, WaitOutcome};

    const DESCENDANT_PID_FILE: &str = "TINYBOX_APPCONTAINER_DESCENDANT_PID_FILE";
    const PARENT_PROBE: &str = "windows::tests::appcontainer_owned_descendant_parent_probe";
    let root = tempfile::tempdir()?;
    let executable = std::env::current_exe()?;
    let executable_directory = executable.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "test executable has no parent")
    })?;
    let pid_file = root.path().join("descendant.pid");
    let invocation = JailInvocation::new(
        ExecRequest::new([
            executable.to_string_lossy().into_owned(),
            "--exact".to_owned(),
            PARENT_PROBE.to_owned(),
            "--nocapture".to_owned(),
        ])
        .with_cwd(root.path())
        .with_env(DESCENDANT_PID_FILE, pid_file.to_string_lossy().into_owned()),
        true,
        None,
    );
    let jail =
        Jail::new(root.path(), "owned-descendant-cleanup-test").add_read_only(executable_directory);
    let mut child = crate::spawn_owned_invocation_captured_with(
        &AppContainerBackend::new(),
        &jail,
        &invocation,
    )?;
    let parent_deadline = Instant::now() + Duration::from_secs(10);
    let parent_status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= parent_deadline {
            child.terminate()?;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "AppContainer descendant parent did not exit within 10 seconds",
            ));
        }
        thread::sleep(Duration::from_millis(25));
    };
    let mut parent_stdout = String::new();
    child
        .take_stdout()
        .ok_or_else(|| io::Error::other("parent probe stdout missing"))?
        .read_to_string(&mut parent_stdout)?;
    let mut parent_stderr = String::new();
    child
        .take_stderr()
        .ok_or_else(|| io::Error::other("parent probe stderr missing"))?
        .read_to_string(&mut parent_stderr)?;
    assert!(
        parent_status.success(),
        "parent probe failed: {parent_status:?}, stdout={parent_stdout:?}, stderr={parent_stderr:?}"
    );

    let pid = std::fs::read_to_string(&pid_file)?
        .parse::<u32>()
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid child PID: {error}"),
            )
        })?;
    let descendant =
        Process::open(pid, ProcessAccess::QueryLimitedAndSynchronize).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("open descendant process {pid}: {error}"),
            )
        })?;
    let descendant_exit_code = descendant
        .exit_code()
        .map_err(|error| io::Error::new(error.kind(), format!("query descendant: {error}")))?;
    let descendant_stdout = std::fs::read_to_string(root.path().join("descendant.stdout"))?;
    let descendant_stderr = std::fs::read_to_string(root.path().join("descendant.stderr"))?;
    assert_eq!(
        descendant_exit_code, None,
        "descendant exited too early: stdout={descendant_stdout:?}, stderr={descendant_stderr:?}"
    );

    child
        .terminate()
        .map_err(|error| io::Error::new(error.kind(), format!("terminate owned Job: {error}")))?;

    assert_eq!(
        descendant
            .wait(Some(Duration::from_secs(5)))
            .map_err(|error| io::Error::new(
                error.kind(),
                format!("wait for descendant: {error}")
            ))?,
        WaitOutcome::Signaled,
        "terminating an owned child must also stop its surviving Job descendants"
    );
    assert!(
        descendant
            .exit_code()
            .map_err(|error| io::Error::new(
                error.kind(),
                format!("query terminated descendant: {error}")
            ))?
            .is_some()
    );
    Ok(())
}

#[test]
fn appcontainer_owned_descendant_parent_probe() -> io::Result<()> {
    use std::{
        thread,
        time::{Duration, Instant},
    };

    let Some(pid_file) = std::env::var_os("TINYBOX_APPCONTAINER_DESCENDANT_PID_FILE") else {
        return Ok(());
    };
    let root = std::env::current_dir()?;
    let child_stdout = std::fs::File::create(root.join("descendant.stdout")).map_err(|error| {
        io::Error::new(error.kind(), format!("create descendant stdout: {error}"))
    })?;
    let child_stderr = std::fs::File::create(root.join("descendant.stderr")).map_err(|error| {
        io::Error::new(error.kind(), format!("create descendant stderr: {error}"))
    })?;
    let local_app_data = root.join("LocalAppData");
    let temp_directory = local_app_data.join("Temp");
    std::fs::create_dir_all(&temp_directory)?;
    // Windows denies launching the test executable from inside the
    // AppContainer. Use a system utility that remains alive without reading
    // the inherited stdin pipe, then record its PID before this parent exits.
    let powershell = std::env::var_os("SystemRoot")
        .map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from)
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    let mut descendant = Command::new(powershell)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Start-Sleep -Seconds 300",
        ])
        .env("LOCALAPPDATA", &local_app_data)
        .env("APPDATA", &root)
        .env("USERPROFILE", &root)
        .env("TEMP", &temp_directory)
        .env("TMP", &temp_directory)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::from(child_stdout))
        .stderr(std::process::Stdio::from(child_stderr))
        .spawn()
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("spawn PowerShell descendant probe: {error}"),
            )
        })?;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(status) = descendant.try_wait()? {
            let stdout = std::fs::read_to_string(root.join("descendant.stdout"))?;
            let stderr = std::fs::read_to_string(root.join("descendant.stderr"))?;
            return Err(io::Error::other(format!(
                "PowerShell descendant exited before readiness: {status:?}, stdout={stdout:?}, stderr={stderr:?}"
            )));
        }
        if Instant::now() >= deadline {
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
    std::fs::write(pid_file, descendant.id().to_string())?;
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
fn appcontainer_process_limit_enforces_maximum_child_count() -> io::Result<()> {
    use std::thread;
    use std::time::{Duration, Instant};
    use tinybox_core::ExecRequest;

    const CHILD_PROBE: &str = "TINYBOX_APPCONTAINER_PROCESS_LIMIT_CHILD_PROBE";
    let test_executable = std::env::current_exe()?;
    let executable_directory = test_executable.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "test executable has no parent directory",
        )
    })?;

    let run_probe = |root: &Path, pids_max: u64, child_expected: bool| -> io::Result<()> {
        let invocation = JailInvocation::new(
            ExecRequest::new(vec![
                test_executable.to_string_lossy().into_owned(),
                "--exact".to_owned(),
                "windows::tests::appcontainer_process_limit_child_probe".to_owned(),
                "--nocapture".to_owned(),
            ])
            .with_cwd(root)
            .with_env(
                CHILD_PROBE,
                if child_expected { "allowed" } else { "denied" },
            ),
            true,
            Some(ResourceLimitPlan {
                pids_max: Some(pids_max),
                ..ResourceLimitPlan::default()
            }),
        );
        let jail = Jail::new(root, "owned-child-pids-test").add_read_only(executable_directory);
        let mut child = crate::spawn_owned_invocation_captured_with(
            &AppContainerBackend::new(),
            &jail,
            &invocation,
        )?;
        // The probe test attempts to start a command. Avoid shell `start`: it
        // waits inside cmd.exe when the active-process limit blocks creation.
        // The outer wait is bounded and terminates the Job Object on timeout.
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
        assert_eq!(
            std::fs::read(root.join("process-limit-probe-ran.txt"))?,
            b"started",
            "the nested test harness must execute the process-limit probe"
        );
        assert_eq!(
            root.join("child.txt").exists(),
            child_expected,
            "the process-count limit should match the allowed child count"
        );
        Ok(())
    };

    let allowed_root = tempfile::tempdir()?;
    run_probe(allowed_root.path(), 2, true)?;

    let denied_root = tempfile::tempdir()?;
    run_probe(denied_root.path(), 1, false)?;
    Ok(())
}

#[test]
fn appcontainer_process_limit_child_probe() {
    let Some(expectation) = std::env::var_os("TINYBOX_APPCONTAINER_PROCESS_LIMIT_CHILD_PROBE")
    else {
        return;
    };

    let root = std::env::current_dir().expect("AppContainer probe cwd should be available");
    std::fs::write(root.join("process-limit-probe-ran.txt"), b"started")
        .expect("AppContainer probe should mark that its test body ran");
    let command = std::env::var_os("SystemRoot")
        .map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from)
        .join("System32")
        .join("cmd.exe");
    let child = Command::new(command)
        .args(["/D", "/C", "echo child > child.txt"])
        .current_dir(root)
        .spawn();
    match (expectation.to_string_lossy().as_ref(), child) {
        ("denied", Err(error)) => eprintln!("Job Object refused child creation: {error}"),
        ("allowed", Err(error)) => {
            panic!("Job Object unexpectedly refused an allowed child: {error}")
        }
        (other, Err(error)) => panic!("unknown process-limit expectation {other:?}: {error}"),
        (other, Ok(mut child)) => {
            let status = child.wait().expect("join the attempted descendant");
            assert_eq!(
                status.success(),
                other == "allowed",
                "Job Object process limit returned unexpected descendant status: {status:?}"
            );
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

#[test]
fn appcontainer_child_cannot_connect_to_host_loopback() -> io::Result<()> {
    use std::io::Read;
    use std::net::{TcpListener, TcpStream};
    use std::time::{Duration, Instant};
    use tinybox_core::ExecRequest;

    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;

    // Prove the host can reach the controlled endpoint before using it as the
    // denial probe. Keep the listener open for the AppContainer attempt.
    let host_control = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let host_accepted = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "host loopback control connection was not accepted",
                    ));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error),
        }
    };
    drop(host_control);
    drop(host_accepted);

    let root = tempfile::tempdir()?;
    let marker = root.path().join("loopback-probe.txt");
    let executable = std::env::current_exe()?;
    let executable_arg = executable.to_string_lossy().into_owned();
    let address_arg = address.to_string();
    let marker_arg = marker.to_string_lossy().into_owned();
    let invocation = JailInvocation::new(
        ExecRequest::new([
            executable_arg.as_str(),
            "--exact",
            "windows::tests::appcontainer_loopback_child_probe",
            "--nocapture",
        ])
        .with_cwd(root.path())
        .with_env("TINYBOX_APPCONTAINER_LOOPBACK_PROBE", address_arg)
        .with_env("TINYBOX_APPCONTAINER_LOOPBACK_MARKER", marker_arg),
        true,
        None,
    );
    let mut child = crate::spawn_owned_invocation_captured_with(
        &AppContainerBackend::new(),
        &Jail::new(root.path(), "loopback-denial-test").deny_net(),
        &invocation,
    )
    .map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("spawn AppContainer loopback probe: {error}"),
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
    let child_deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= child_deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "AppContainer network probe did not exit within 10 seconds",
            ));
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    assert!(
        status.success(),
        "AppContainer probe failed: status {status:?}, stdout {output:?}, stderr {error_output:?}"
    );
    let result = std::fs::read_to_string(marker)?;
    assert!(
        result.starts_with("denied:"),
        "AppContainer reached the host loopback listener: {result:?}"
    );
    Ok(())
}

#[test]
fn appcontainer_loopback_child_probe() {
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;

    let (Some(address), Some(marker)) = (
        std::env::var_os("TINYBOX_APPCONTAINER_LOOPBACK_PROBE"),
        std::env::var_os("TINYBOX_APPCONTAINER_LOOPBACK_MARKER"),
    ) else {
        return;
    };
    let address = address
        .to_string_lossy()
        .parse::<SocketAddr>()
        .expect("parent should pass a valid loopback address");
    let result = match TcpStream::connect_timeout(&address, Duration::from_secs(2)) {
        Ok(_stream) => "connected".to_owned(),
        Err(error) => format!("denied: {error}"),
    };
    std::fs::write(marker, result).expect("AppContainer probe should write its result");
}

#[test]
fn live_appcontainer_memory_limit_blocks_over_budget_allocation() -> io::Result<()> {
    const MEMORY_LIMIT: u64 = 128 * 1024 * 1024;

    if std::env::var_os("TINYBOX_REQUIRE_APPCONTAINER_RESOURCE_TESTS").as_deref()
        != Some(std::ffi::OsStr::new("1"))
    {
        eprintln!("skipped: set TINYBOX_REQUIRE_APPCONTAINER_RESOURCE_TESTS=1 on Windows");
        return Ok(());
    }

    let executable = std::env::current_exe()?;
    let executable_arg = executable.to_string_lossy().into_owned();
    let executable_directory = executable.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "test executable has no parent directory",
        )
    })?;

    let control_root = tempfile::tempdir()?;
    run_appcontainer_memory_probe(
        control_root.path(),
        &executable_arg,
        executable_directory,
        None,
    )?;

    let limited_root = tempfile::tempdir()?;
    run_appcontainer_memory_probe(
        limited_root.path(),
        &executable_arg,
        executable_directory,
        Some(MEMORY_LIMIT),
    )?;
    Ok(())
}

fn run_appcontainer_memory_probe(
    root: &Path,
    executable_arg: &str,
    executable_directory: &Path,
    memory_limit: Option<u64>,
) -> io::Result<()> {
    use std::io::Read;
    use std::time::{Duration, Instant};
    use tinybox_core::ExecRequest;

    let started = root.join("memory-probe-started.txt");
    let completed = root.join("memory-probe-completed.txt");
    let refused = root.join("memory-probe-refused.txt");
    let invocation = JailInvocation::new(
        ExecRequest::new([
            executable_arg,
            "--exact",
            "windows::tests::appcontainer_memory_limit_child_probe",
            "--nocapture",
        ])
        .with_cwd(root)
        .with_env("TINYBOX_APPCONTAINER_MEMORY_PROBE", "1"),
        true,
        memory_limit.map(|memory_bytes| ResourceLimitPlan {
            memory_bytes: Some(memory_bytes),
            ..ResourceLimitPlan::default()
        }),
    );
    let jail = Jail::new(root, "appcontainer-memory-live-test")
        .add_read_only(executable_directory)
        .deny_net();
    let mut child = crate::spawn_owned_invocation_captured_with(
        &AppContainerBackend::new(),
        &jail,
        &invocation,
    )?;
    let stdout = child
        .take_stdout()
        .ok_or_else(|| io::Error::other("captured stdout missing"))?;
    let stderr = child
        .take_stderr()
        .ok_or_else(|| io::Error::other("captured stderr missing"))?;
    let stdout_reader = std::thread::spawn(move || {
        let mut output = String::new();
        stdout
            .take(64 * 1024)
            .read_to_string(&mut output)
            .map(|_| output)
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut output = String::new();
        stderr
            .take(64 * 1024)
            .read_to_string(&mut output)
            .map(|_| output)
    });

    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            child.terminate()?;
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "AppContainer memory probe exceeded 15 seconds",
            ));
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let output = stdout_reader
        .join()
        .map_err(|_| io::Error::other("stdout reader thread panicked"))??;
    let error_output = stderr_reader
        .join()
        .map_err(|_| io::Error::other("stderr reader thread panicked"))??;
    if !started.exists() {
        return Err(io::Error::other(format!(
            "AppContainer memory probe did not reach its allocation body: status={status:?}, stdout={output:?}, stderr={error_output:?}"
        )));
    }
    if memory_limit.is_none() {
        assert!(
            status.success(),
            "unlimited memory control failed: status={status:?}, stdout={output:?}, stderr={error_output:?}"
        );
        assert!(
            completed.exists(),
            "unlimited control did not touch all pages"
        );
        assert!(!refused.exists(), "unlimited control refused allocation");
    } else {
        assert!(!completed.exists(), "limited child touched all pages");
        assert!(
            refused.exists() || !status.success(),
            "memory limit did not block the over-budget allocation: status={status:?}, stdout={output:?}, stderr={error_output:?}"
        );
    }
    Ok(())
}

#[test]
fn appcontainer_memory_limit_child_probe() -> io::Result<()> {
    const CHUNK_BYTES: usize = 16 * 1024 * 1024;
    const CHUNKS: usize = 16;

    if std::env::var_os("TINYBOX_APPCONTAINER_MEMORY_PROBE").is_none() {
        return Ok(());
    }

    let root = std::env::current_dir()?;
    std::fs::write(root.join("memory-probe-started.txt"), b"started")?;
    let mut allocations = Vec::new();
    for _ in 0..CHUNKS {
        let mut chunk = Vec::new();
        if chunk.try_reserve_exact(CHUNK_BYTES).is_err() {
            std::fs::write(root.join("memory-probe-refused.txt"), b"refused")?;
            return Ok(());
        }
        chunk.resize(CHUNK_BYTES, 0xA5);
        allocations.push(chunk);
    }
    std::fs::write(root.join("memory-probe-completed.txt"), b"allocated")?;
    Ok(())
}
