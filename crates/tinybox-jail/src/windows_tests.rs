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

#[test]
fn appcontainer_backend_is_available_through_owned_process_supervision() {
    assert!(
        AppContainerBackend::new().is_available(),
        "AppContainer is available through TinyBox's owned-process API"
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
    assert_eq!(
        support.enforcement(Constraint::Pids),
        Enforcement::Enforced
    );
}

#[test]
fn appcontainer_owned_launch_captures_output_from_a_confined_child() -> std::io::Result<()> {
    use std::io::Read;
    use tinybox_core::ExecRequest;

    let backend = AppContainerBackend::new();
    let root = tempfile::tempdir()?;
    let command = std::env::var_os("ComSpec")
        .unwrap_or_else(|| r"C:\Windows\System32\cmd.exe".into());
    let invocation = JailInvocation::new(
        ExecRequest::new([command, "/D".into(), "/C".into(), "echo appcontainer-owned".into()])
            .with_cwd(root.path()),
        true,
        None,
    );
    let mut child = crate::spawn_owned_invocation_captured_with(
        &backend,
        &Jail::new(root.path(), "owned-child-live-test"),
        &invocation,
    )?;
    let mut output = String::new();
    child
        .stdout_mut()
        .ok_or_else(|| std::io::Error::other("captured stdout missing"))?
        .read_to_string(&mut output)?;
    let status = child
        .try_wait()?
        .ok_or_else(|| std::io::Error::other("AppContainer child still running after stdout closed"))?;

    assert!(status.success(), "unexpected child status: {status:?}");
    assert_eq!(output.trim(), "appcontainer-owned");
    Ok(())
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
