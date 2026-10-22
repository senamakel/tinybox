//! Tests for typed native process invocation conversion.

use super::*;

#[test]
fn command_keeps_inherited_environment_when_clear_is_false() -> std::io::Result<()> {
    let invocation = JailInvocation::new(
        ExecRequest::new(["/bin/true"]).with_env("APPROVED", "yes"),
        false,
        None,
    );
    let command = invocation.command()?;

    assert_eq!(command.get_program(), "/bin/true");
    assert_eq!(command.get_current_dir(), None);
    assert!(
        command
            .get_envs()
            .any(|(key, value)| key == "APPROVED" && value == Some("yes".as_ref()))
    );
    Ok(())
}

#[test]
fn empty_argv_and_empty_or_zero_resource_plans_are_rejected() {
    let empty_argv = JailInvocation::new(ExecRequest::new(Vec::<String>::new()), true, None);
    assert_eq!(
        empty_argv.command().err().map(|error| error.kind()),
        Some(std::io::ErrorKind::InvalidInput)
    );

    let empty_plan = JailInvocation::new(
        ExecRequest::new(["/bin/true"]),
        true,
        Some(ResourceLimitPlan::default()),
    );
    assert_eq!(
        empty_plan.command().err().map(|error| error.kind()),
        Some(std::io::ErrorKind::InvalidInput)
    );

    let zero_plan = JailInvocation::new(
        ExecRequest::new(["/bin/true"]),
        true,
        Some(ResourceLimitPlan {
            memory_bytes: Some(0),
            ..ResourceLimitPlan::default()
        }),
    );
    assert_eq!(
        zero_plan.command().err().map(|error| error.kind()),
        Some(std::io::ErrorKind::InvalidInput)
    );
}
