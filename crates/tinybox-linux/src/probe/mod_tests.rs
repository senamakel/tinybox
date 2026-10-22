use super::*;
use std::time::Duration;

#[test]
fn an_unrestricted_kernel_is_available() {
    assert_eq!(
        UsernsStatus::from_sysctls(Some("63000\n"), None, Some("0\n")),
        UsernsStatus::Available
    );
    assert_eq!(
        UsernsStatus::from_sysctls(None, None, None),
        UsernsStatus::Available
    );
}

#[test]
fn zero_max_user_namespaces_disables_them() {
    assert_eq!(
        UsernsStatus::from_sysctls(Some("0\n"), None, None),
        UsernsStatus::DisabledBySysctl
    );
    assert_eq!(
        UsernsStatus::from_sysctls(None, Some("0"), None),
        UsernsStatus::DisabledBySysctl
    );
}

#[test]
fn the_ubuntu_24_04_apparmor_restriction_is_named() {
    assert_eq!(
        UsernsStatus::from_sysctls(Some("63000"), None, Some("1\n")),
        UsernsStatus::RestrictedByAppArmor
    );
}

#[test]
fn a_hard_disable_outranks_the_apparmor_restriction() {
    assert_eq!(
        UsernsStatus::from_sysctls(Some("0"), None, Some("1")),
        UsernsStatus::DisabledBySysctl
    );
}

#[test]
fn a_missing_bwrap_is_reported_before_the_namespace_state() {
    let probe = NamespaceProbe {
        bwrap: None,
        userns: UsernsStatus::RestrictedByAppArmor,
        probe_error: None,
    };
    assert!(!probe.is_usable());
    assert!(probe.problem().unwrap_or_default().contains("bubblewrap"));
}

#[test]
fn each_blocked_state_gives_an_actionable_message() {
    let bwrap = Some(PathBuf::from("/usr/bin/bwrap"));
    let ok = NamespaceProbe {
        bwrap: bwrap.clone(),
        userns: UsernsStatus::Available,
        probe_error: None,
    };
    assert!(ok.is_usable());
    let disabled = NamespaceProbe {
        bwrap: bwrap.clone(),
        userns: UsernsStatus::DisabledBySysctl,
        probe_error: None,
    };
    assert!(
        disabled
            .problem()
            .unwrap_or_default()
            .contains("max_user_namespaces")
    );
    let restricted = NamespaceProbe {
        bwrap,
        userns: UsernsStatus::RestrictedByAppArmor,
        probe_error: Some("Operation not permitted".to_owned()),
    };
    assert!(
        restricted
            .problem()
            .unwrap_or_default()
            .contains("AppArmor")
    );
}

#[test]
fn a_successful_bwrap_probe_overrides_the_app_armor_sysctl_hint() {
    let probe = NamespaceProbe {
        bwrap: Some(PathBuf::from("/usr/bin/bwrap")),
        userns: UsernsStatus::RestrictedByAppArmor,
        probe_error: None,
    };

    assert!(probe.is_usable());
    assert_eq!(
        probe.availability(),
        tinybox_core::SandboxAvailability::Available
    );
}

#[test]
fn a_failed_bwrap_probe_becomes_typed_unavailability_with_actionable_context() {
    let probe = NamespaceProbe {
        bwrap: Some(PathBuf::from("/usr/bin/bwrap")),
        userns: UsernsStatus::RestrictedByAppArmor,
        probe_error: Some("exited with exit status: 1: Operation not permitted".to_owned()),
    };

    assert!(matches!(
        probe.availability(),
        tinybox_core::SandboxAvailability::Unavailable { reason }
            if reason.contains("Operation not permitted") && reason.contains("AppArmor")
    ));
}

#[cfg(unix)]
#[test]
fn path_search_finds_only_executable_files() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir()?;
    let plain = dir.path().join("bwrap");
    std::fs::write(&plain, "")?;
    let path = std::env::join_paths([dir.path()])?;
    assert_eq!(
        find_on_path("bwrap", &path),
        None,
        "a non-executable file is not found"
    );

    std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o755))?;
    assert_eq!(find_on_path("bwrap", &path), Some(plain));
    assert_eq!(find_on_path("absent", &path), None);
    Ok(())
}

#[test]
fn detect_runs_on_this_machine_without_panicking() {
    let probe = NamespaceProbe::detect();
    assert_eq!(probe.is_usable(), probe.problem().is_none());
}

#[cfg(unix)]
#[test]
fn a_successful_bwrap_userns_probe_is_available() -> Result<(), Box<dyn std::error::Error>> {
    let script = ProbeScript::new("exit 0\n")?;

    assert_eq!(
        probe_bwrap_with_timeout(&script.path, Duration::from_secs(1)),
        Ok(())
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn a_failed_bwrap_userns_probe_preserves_its_diagnostic() -> Result<(), Box<dyn std::error::Error>>
{
    let script = ProbeScript::new("echo 'user namespace denied' >&2\nexit 17\n")?;

    let error = probe_bwrap_with_timeout(&script.path, Duration::from_secs(1))
        .expect_err("a failing probe must not report readiness");
    assert!(error.contains("user namespace denied"), "{error}");
    assert!(error.contains("17"), "{error}");
    Ok(())
}

#[cfg(unix)]
#[test]
fn a_timed_out_bwrap_userns_probe_is_killed_and_reaped() -> Result<(), Box<dyn std::error::Error>> {
    let script = ProbeScript::new("exec sleep 30\n")?;
    let started = std::time::Instant::now();

    let error = probe_bwrap_with_timeout(&script.path, Duration::from_millis(50))
        .expect_err("a stuck probe must not report readiness");

    assert!(error.contains("timed out"), "{error}");
    assert!(started.elapsed() < Duration::from_secs(2));
    Ok(())
}

#[cfg(unix)]
struct ProbeScript {
    _directory: tempfile::TempDir,
    path: PathBuf,
}

#[cfg(unix)]
impl ProbeScript {
    fn new(body: &str) -> Result<Self, Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir()?;
        let path = directory.path().join("bwrap-probe");
        std::fs::write(&path, format!("#!/bin/sh\n{body}"))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
        Ok(Self {
            _directory: directory,
            path,
        })
    }
}

#[cfg(unix)]
#[test]
fn the_probe_uses_only_the_fixed_read_only_bwrap_command() -> Result<(), Box<dyn std::error::Error>>
{
    let script = ProbeScript::new(
        "[ \"$#\" -eq 6 ] && \\\n+         [ \"$1\" = --unshare-user ] && [ \"$2\" = --ro-bind ] && \\\n+         [ \"$3\" = / ] && [ \"$4\" = / ] && [ \"$5\" = -- ] && \\\n+         [ \"$6\" = /bin/true ]\n",
    )?;

    assert_eq!(
        probe_bwrap_with_timeout(&script.path, Duration::from_secs(1)),
        Ok(())
    );
    Ok(())
}
