//! Process-group membership checks for observed SSH cleanup.

#[cfg(unix)]
use super::*;

#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(unix)]
use std::process::{Command, Output};
#[cfg(unix)]
use tempfile::TempDir;

#[cfg(unix)]
fn run_members_probe(action: &str) -> Result<(Output, TempDir)> {
    let directory =
        tempfile::tempdir().map_err(|error| Error::io("create probe directory", &error))?;
    let script = format!(
        "dir={}; group=$$;\n{}\n{}",
        tinybox_core::shell::quote(&directory.path().display().to_string()),
        MEMBERS_REMAIN_FUNCTION,
        action
    );
    let mut command = Command::new("/bin/sh");
    command.arg("-c").arg(script).process_group(0);
    let output = command
        .output()
        .map_err(|error| Error::io("run process-group probe", &error))?;
    Ok((output, directory))
}

#[cfg(unix)]
#[test]
fn members_remain_ignores_processes_used_by_its_own_probe() -> Result<()> {
    let (output, directory) = run_members_probe("members_remain")?;

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        std::fs::read_dir(directory.path())
            .map_err(|error| Error::io("inspect probe directory", &error))?
            .count(),
        0
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn members_remain_reports_a_real_process_in_the_group() -> Result<()> {
    let action = "/bin/sleep 600 &\nprobe_member=$!\nmembers_remain\nprobe_status=$?\nkill \"$probe_member\" 2>/dev/null || true\nwait \"$probe_member\" 2>/dev/null || true\nexit \"$probe_status\"";
    let (output, directory) = run_members_probe(action)?;

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        std::fs::read_dir(directory.path())
            .map_err(|error| Error::io("inspect probe directory", &error))?
            .count(),
        0
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn members_remain_fails_closed_for_probe_errors_and_malformed_rows() -> Result<()> {
    for mode in ["setsid-fails", "ps-fails", "malformed"] {
        let action = format!(
            "probe_mode={mode}\nsetsid() {{ if [ \"$probe_mode\" = setsid-fails ]; then return 1; fi; \"$@\"; }}\nps() {{ case \"$probe_mode\" in ps-fails) return 1 ;; malformed) printf 'not-a-pid\\n' ;; esac; }}\nmembers_remain",
            mode = tinybox_core::shell::quote(mode)
        );
        let (output, directory) = run_members_probe(&action)?;

        assert_eq!(output.status.code(), Some(0), "probe mode {mode}");
        assert_eq!(
            std::fs::read_dir(directory.path())
                .map_err(|error| Error::io("inspect probe directory", &error))?
                .count(),
            0,
            "probe mode {mode}"
        );
    }
    Ok(())
}
