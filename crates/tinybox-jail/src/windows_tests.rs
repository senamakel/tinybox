#![allow(unsafe_code)]

use super::*;

#[test]
fn net_capability_names_is_outbound_client_only() {
    // `Jail.allow_net` is documented as "Allow outbound network" in
    // `jail.rs`, so the granted capability set must be strictly
    // outbound-client.
    assert!(NET_CAPABILITY_NAMES.contains(&"internetClient"));
    // The following would over-grant inbound bind() rights and are
    // intentionally NOT exposed via the coarse `allow_net` switch.
    // A future caller that needs them should add a separate `Jail`
    // flag (e.g. `allow_private_lan_server`) and gate them on it.
    assert!(!NET_CAPABILITY_NAMES.contains(&"privateNetworkClientServer"));
    assert!(!NET_CAPABILITY_NAMES.contains(&"internetClientServer"));
}

#[test]
fn derive_capability_resolves_well_known_internet_client() {
    // `internetClient` is one of the Windows manifest-defined
    // capabilities present on every supported Windows version
    // (10+). DeriveCapabilitySidsFromName must succeed and return
    // at least one non-null capability SID.
    let deriv = unsafe { derive_capability("internetClient") }
        .expect("internetClient must resolve on any supported Windows");
    assert!(
        !deriv.capability_sids.is_empty(),
        "expected at least one capability SID for internetClient"
    );
    for &sid in &deriv.capability_sids {
        assert!(!sid.is_null(), "capability SID must not be null");
    }
    // Dropping `deriv` here exercises the Drop impl that LocalFrees
    // every SID + array — a no-op for the test runner unless it
    // double-frees, which would crash the process.
}

#[test]
fn sanitize_profile_name_keeps_alnum_and_dot() {
    let s = sanitize_profile_name("agent.delegate-7");
    assert!(s.starts_with("openhuman."));
    // hyphen mapped to underscore
    assert!(s.contains("agent.delegate_7"));
    assert!(s.len() <= 70); // "openhuman." (10) + label (≤60)
}

#[test]
fn sanitize_profile_name_truncates_long_labels() {
    let long: String = "a".repeat(200);
    let s = sanitize_profile_name(&long);
    // Per the in-function comment: truncate to 60 then prefix.
    assert!(s.len() <= 70);
    assert!(s.starts_with("openhuman."));
}

/// PR #4723 review — `AppContainerBackend::is_available()` must
/// stay `false` until the spawn path can return a
/// `std::process::Child`. Reporting available strands a
/// successfully-spawned `cmd.exe` process because `spawn_in_container`
/// currently answers `Err(Unsupported)` after `CreateProcessW`, and
/// callers (e.g. `execute_local_jail`) drop the child on the floor.
/// Flip back to `true` in the same commit that lands the
/// `OwnedHandle -> Child` bridge.
#[test]
fn appcontainer_backend_reports_unavailable_until_child_bridge_lands() {
    assert!(
        !AppContainerBackend::new().is_available(),
        "AppContainer must report unavailable while its spawn path \
         cannot yield a waitable std::process::Child — see #4705 / \
         PR #4723 for the orphan-spawn hazard"
    );
}

#[test]
fn path_grants_give_read_write_paths_the_same_access_as_the_root() {
    let jail = Jail::new(r"C:\work\root", "x")
        .add_read_write(r"C:\state\capture\1")
        .add_read_only(r"C:\tools");
    let grants = path_grants(&jail);
    let rw = GENERIC_READ | GENERIC_WRITE | DELETE;
    assert_eq!(
        grants,
        vec![
            (Path::new(r"C:\work\root"), rw),
            (Path::new(r"C:\state\capture\1"), rw),
            (Path::new(r"C:\tools"), GENERIC_READ),
        ]
    );
}

#[test]
fn path_grants_keep_write_access_on_paths_also_listed_read_only() {
    let jail = Jail::new(r"C:\work\root", "x")
        .add_read_write(r"C:\state\capture")
        .add_read_only(r"C:\work\root")
        .add_read_only(r"C:\state\capture")
        .add_read_only(r"C:\tools");
    let rw = GENERIC_READ | GENERIC_WRITE | DELETE;
    assert_eq!(
        path_grants(&jail),
        vec![
            (Path::new(r"C:\work\root"), rw),
            (Path::new(r"C:\state\capture"), rw),
            (Path::new(r"C:\tools"), GENERIC_READ),
        ]
    );
}

#[test]
fn job_object_limit_plan_sets_memory_process_cpu_and_kill_on_close() {
    use tinybox_core::Resources;

    let limits = job_object_limit_plan(
        Resources {
            cpu_millis: 1_500,
            memory_bytes: 512 * 1024 * 1024,
            pids_max: 17,
            disk_bytes: Resources::DEFAULT.disk_bytes,
        },
        4,
        &[
            tinybox_core::Constraint::Cpu,
            tinybox_core::Constraint::Memory,
            tinybox_core::Constraint::Pids,
        ],
    )
    .expect("valid Windows Job Object limits");

    assert_eq!(limits.process_memory_bytes, Some(512 * 1024 * 1024));
    assert_eq!(limits.active_processes, Some(17));
    assert_eq!(limits.cpu_rate, Some(3_750));
    assert!(limits.kill_on_close);
}

#[test]
fn soft_resource_values_do_not_create_hard_job_limits() {
    let limits = job_object_limit_plan(tinybox_core::Resources::DEFAULT, 8, &[])
        .expect("valid soft defaults");
    assert_eq!(limits.process_memory_bytes, None);
    assert_eq!(limits.active_processes, None);
    assert_eq!(limits.cpu_rate, None);
    assert!(limits.kill_on_close);
}

#[test]
fn windows_capabilities_report_only_job_object_resource_limits() {
    use tinybox_core::{Constraint, Enforcement};

    let support = windows_constraint_support(true);
    assert_eq!(support.enforcement(Constraint::Cpu), Enforcement::Enforced);
    assert_eq!(
        support.enforcement(Constraint::Memory),
        Enforcement::Enforced
    );
    assert_eq!(support.enforcement(Constraint::Pids), Enforcement::Enforced);
    assert_eq!(
        support.enforcement(Constraint::Disk),
        Enforcement::Unsupported
    );
}

#[test]
fn unsupported_windows_disk_limit_is_a_typed_preflight_refusal() {
    use tinybox_core::{Constraint, Enforcement, Error};

    let error = windows_constraint_support(true)
        .require("appcontainer", &[Constraint::Disk])
        .expect_err("Job Objects do not enforce disk quotas");
    assert!(matches!(
        error,
        Error::ConstraintNotEnforced {
            sandbox,
            constraint: Constraint::Disk,
            enforcement: Enforcement::Unsupported,
        } if sandbox == "appcontainer"
    ));
}

#[test]
fn owned_backend_selection_uses_appcontainer_without_changing_legacy_selection() {
    let backend = crate::detect::pick_owned_backend();
    assert_eq!(backend.name(), "appcontainer");
    assert!(!backend.is_available());
    assert!(backend.is_owned_available());
    assert_eq!(
        backend
            .constraint_support()
            .enforcement(tinybox_core::Constraint::Memory),
        tinybox_core::Enforcement::Enforced
    );
}

#[test]
fn supported_job_object_requirements_pass_hard_preflight() {
    use tinybox_core::Constraint;

    windows_constraint_support(true)
        .require(
            "appcontainer",
            &[Constraint::Cpu, Constraint::Memory, Constraint::Pids],
        )
        .expect("Job Objects enforce the selected hard limits");
}

#[test]
fn jail_preflight_accepts_supported_limits_and_refuses_hard_disk_limit() {
    use tinybox_core::{Constraint, Enforcement};

    let backend = AppContainerBackend::new();
    let supported = Jail::new(r"C:\work", "limits").with_hard_requirements([
        Constraint::Cpu,
        Constraint::Memory,
        Constraint::Pids,
    ]);
    assert!(backend.require_resources(&supported).is_ok());

    let disk = Jail::new(r"C:\work", "limits").with_hard_requirements([Constraint::Disk]);
    assert!(matches!(
        backend.require_resources(&disk),
        Err(tinybox_core::Error::ConstraintNotEnforced {
            constraint: Constraint::Disk,
            enforcement: Enforcement::Unsupported,
            ..
        })
    ));
}

#[test]
fn box_spec_preflight_uses_only_explicit_hard_requirements() {
    use tinybox_core::{Constraint, HostRef, Placement, SandboxRef, WorkspaceSource};

    let placement = Placement::new(
        HostRef::new("local").expect("valid host ref"),
        SandboxRef::new("appcontainer").expect("valid sandbox ref"),
    );
    let spec = tinybox_core::BoxSpec::new(
        placement,
        WorkspaceSource::LocalDir(PathBuf::from(r"C:\workspace")),
    );
    let backend = AppContainerBackend::new();
    assert!(backend.plan_check_spec(&spec).constraints.is_empty());
    backend
        .require_spec(&spec)
        .expect("soft resource defaults do not become hard requirements");

    let spec = spec.with_hard_requirements([Constraint::Cpu, Constraint::Memory, Constraint::Pids]);
    let jail = Jail::new(r"C:\workspace", "spec-limits").with_box_spec(&spec);
    assert!(backend.require_resources(&jail).is_ok());
    backend
        .require_spec(&spec)
        .expect("Job Objects enforce all listed resource requirements");

    let disk_spec = spec.with_hard_requirements([Constraint::Disk]);
    assert!(backend.require_spec(&disk_spec).is_err());
}

#[test]
fn owned_appcontainer_child_captures_output_waits_and_kills_on_drop() -> std::io::Result<()> {
    use std::io::Read;

    let root = tempfile::tempdir()?;
    let backend = AppContainerBackend::new();
    let mut echo = Command::new("cmd.exe");
    echo.args(["/C", "echo owned-child-ok"]);
    let jail = Jail::new(root.path(), "owned-child-capture").deny_net();
    let mut child = crate::spawn_owned_captured_with(&backend, &jail, echo)?;
    let mut output = String::new();
    child
        .take_stdout()
        .expect("captured stdout")
        .read_to_string(&mut output)?;
    assert!(output.contains("owned-child-ok"));
    assert!(child.try_wait()?.is_some(), "EOF follows process exit");

    let mut waiting = Command::new("cmd.exe");
    waiting.args(["/C", "set /p waiting="]);
    let jail = Jail::new(root.path(), "owned-child-terminate").deny_net();
    let mut child = crate::spawn_owned_captured_with(&backend, &jail, waiting)?;
    let _keep_stdin_open = child.take_stdin();
    let mut stdout = child.take_stdout().expect("captured stdout");
    child.terminate()?;
    let mut remaining = Vec::new();
    stdout.read_to_end(&mut remaining)?;
    assert!(child.try_wait()?.is_some(), "terminated job exits");

    let mut waiting = Command::new("cmd.exe");
    waiting.args(["/C", "set /p waiting="]);
    let jail = Jail::new(root.path(), "owned-child-cleanup").deny_net();
    let mut child = crate::spawn_owned_captured_with(&backend, &jail, waiting)?;
    let _keep_stdin_open = child.take_stdin();
    let mut stdout = child.take_stdout().expect("captured stdout");
    drop(child);
    let mut remaining = Vec::new();
    stdout.read_to_end(&mut remaining)?;
    Ok(())
}
