//! Tests for backend selection and the unavailable-backend result.

use super::*;

fn marker_command(marker: &std::path::Path) -> Command {
    #[cfg(windows)]
    {
        let mut command = Command::new("cmd.exe");
        command.args(["/D", "/C"]);
        command.arg(format!("echo launched > \"{}\"", marker.display()));
        command
    }
    #[cfg(not(windows))]
    {
        let mut command = Command::new("sh");
        command.args(["-c", "printf launched > \"$1\"", "tinybox-marker"]);
        command.arg(marker);
        command
    }
}

#[test]
fn unavailable_backend_rejects_spawning() {
    let backend = UnsupportedBackend;
    assert_eq!(backend.name(), UNSUPPORTED_BACKEND_NAME);
    assert!(!backend.is_available());
    let error = backend
        .spawn(&Jail::new(".", "unsupported"), Command::new("true"))
        .err()
        .map(|error| error.kind());
    assert_eq!(error, Some(std::io::ErrorKind::Unsupported));
}

#[test]
fn backend_detection_returns_a_backend() {
    assert_ne!(pick_backend().name().len(), 0);
}

#[test]
fn detection_prefers_the_platform_backend_when_it_works() {
    let picked = pick_backend();
    let expected = candidates()
        .into_iter()
        .find(|backend| backend.is_available());
    if let Some(backend) = expected {
        assert_eq!(picked.name(), backend.name());
        assert!(picked.is_available());
    } else {
        assert_eq!(picked.name(), UNSUPPORTED_BACKEND_NAME);
        assert!(!picked.is_available());
    }
}

#[cfg(all(target_os = "linux", feature = "landlock"))]
#[test]
fn linux_prefers_bubblewrap_then_landlock() {
    if crate::bwrap::BubblewrapBackend::new().is_available() {
        assert_eq!(pick_backend().name(), "bubblewrap");
    } else if crate::linux::LandlockBackend::new().is_available() {
        assert_eq!(pick_backend().name(), "landlock");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_candidates_rank_bubblewrap_before_landlock() {
    let names: Vec<_> = candidates().iter().map(|b| b.name()).collect();
    assert_eq!(names, ["bubblewrap", "landlock"]);
}

#[test]
fn windows_appcontainer_is_never_a_candidate() {
    assert!(
        candidates()
            .iter()
            .all(|backend| backend.name() != "appcontainer")
    );
}

#[test]
fn unavailable_candidates_are_skipped_and_empty_candidates_fail_closed() {
    for candidates in [
        vec![],
        vec![Arc::new(UnsupportedBackend) as Arc<dyn JailBackend>],
    ] {
        let picked = pick_from(candidates);
        assert_eq!(picked.name(), UNSUPPORTED_BACKEND_NAME);
        assert!(!picked.is_available());
    }
}

#[test]
fn required_spawn_with_no_available_jail_refuses_before_running_payload() -> std::io::Result<()> {
    let backend = pick_from(Vec::new());
    assert_eq!(backend.name(), UNSUPPORTED_BACKEND_NAME);
    assert!(!backend.is_available());

    let root = tempfile::tempdir()?;
    let marker = root.path().join("payload-ran");
    let error = crate::spawn_required_with(
        backend.as_ref(),
        &crate::Jail::new(root.path(), "no-jail"),
        marker_command(&marker),
    )
    .expect_err("strict spawn must refuse when there are no jail backends");

    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    assert!(matches!(
        error
            .get_ref()
            .and_then(|source| source.downcast_ref::<tinybox_core::Error>()),
        Some(tinybox_core::Error::ConstraintNotEnforced {
            sandbox,
            constraint: tinybox_core::Constraint::Filesystem,
            enforcement: tinybox_core::Enforcement::Unsupported,
        }) if sandbox == UNSUPPORTED_BACKEND_NAME
    ));
    assert!(!marker.exists(), "unconfined payload must never run");
    Ok(())
}

#[cfg(target_os = "windows")]
#[test]
fn windows_default_required_spawn_fails_closed_without_appcontainer() -> std::io::Result<()> {
    let backend = pick_backend();
    assert_eq!(backend.name(), UNSUPPORTED_BACKEND_NAME);
    assert!(!backend.is_available());

    let root = tempfile::tempdir()?;
    let marker = root.path().join("payload-ran");
    let error = crate::spawn_required(
        &crate::Jail::new(root.path(), "windows-no-appcontainer"),
        marker_command(&marker),
    )
    .expect_err("Windows strict spawn must fail closed while AppContainer is unavailable");

    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    assert!(matches!(
        error
            .get_ref()
            .and_then(|source| source.downcast_ref::<tinybox_core::Error>()),
        Some(tinybox_core::Error::ConstraintNotEnforced {
            sandbox,
            constraint: tinybox_core::Constraint::Filesystem,
            enforcement: tinybox_core::Enforcement::Unsupported,
        }) if sandbox == UNSUPPORTED_BACKEND_NAME
    ));
    assert!(!marker.exists(), "unconfined payload must never run");
    Ok(())
}

#[test]
fn selection_uses_the_first_available_candidate() {
    let picked = pick_from(vec![
        Arc::new(UnsupportedBackend),
        Arc::new(crate::noop::NoopBackend),
    ]);
    assert_eq!(picked.name(), crate::noop::NOOP_BACKEND_NAME);
}
