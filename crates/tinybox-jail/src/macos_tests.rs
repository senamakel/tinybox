//! Tests for Seatbelt profiles and launcher command forwarding.

use super::*;
use std::fs;
use std::process::Stdio;

#[test]
fn profile_allow_net_by_default_has_no_deny() {
    let jail = Jail::new("/tmp", "x");
    let p = render_profile(&jail);
    assert!(p.contains("(allow default)"));
    assert!(!p.contains("(deny network*)"));
}

#[test]
fn profile_deny_subprocess_emits_deny_rules() {
    let jail = Jail::new("/tmp", "x").deny_subprocess();
    let p = render_profile(&jail);
    assert!(p.contains("(deny process-fork)"));
    assert!(!p.contains("(deny process-exec)"));
}

#[cfg(target_os = "macos")]
#[test]
fn live_seatbelt_deny_subprocess_blocks_child_creation() -> std::io::Result<()> {
    use std::process::Command;

    const REQUIRE_SEATBELT_TEST: &str = "TINYBOX_REQUIRE_SEATBELT_TESTS";
    if !std::path::Path::new("/usr/bin/sandbox-exec").is_file() {
        if std::env::var_os(REQUIRE_SEATBELT_TEST).is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "required macOS Seatbelt test cannot run: /usr/bin/sandbox-exec is absent",
            ));
        }
        eprintln!("[seatbelt-live] SKIP: /usr/bin/sandbox-exec is absent");
        return Ok(());
    }

    let root = tempfile::tempdir()?;
    const FORK_PROBE: &str = r#"
#include <errno.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void emit(const char *message, size_t length) {
    (void)write(STDOUT_FILENO, message, length);
}

int main(void) {
    emit("before\n", 7);
    pid_t child = fork();
    if (child == 0) {
        emit("child-executed\n", 15);
        _exit(0);
    }
    if (child < 0) {
        if (errno == EPERM) {
            emit("fork-denied\n", 12);
            emit("after\n", 6);
            return 0;
        }
        return 2;
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return 3;
    }
    emit("after\n", 6);
    return 0;
}
"#;
    let source = root.path().join("fork_probe.c");
    std::fs::write(&source, FORK_PROBE)?;
    let helper = root.path().join("fork_probe");
    let compilation = match Command::new("cc")
        .args(["-Wall", "-Werror", "-o"])
        .arg(&helper)
        .arg(&source)
        .output()
    {
        Ok(compilation) => compilation,
        Err(error) if std::env::var_os(REQUIRE_SEATBELT_TEST).is_none() => {
            eprintln!("[seatbelt-live] SKIP: C compiler unavailable: {error}");
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    assert!(
        compilation.status.success(),
        "could not compile fork probe: stdout: {:?}, stderr: {:?}",
        String::from_utf8_lossy(&compilation.stdout),
        String::from_utf8_lossy(&compilation.stderr)
    );

    let allowed_command = Command::new(&helper);
    let allowed = SeatbeltBackend::new()
        .spawn_captured(
            &Jail::new(root.path(), "seatbelt-subprocess-control"),
            allowed_command,
        )?
        .wait_with_output()?;
    let allowed_stdout = String::from_utf8_lossy(&allowed.stdout);
    assert!(
        allowed.status.success(),
        "unrestricted control failed: status {}, stdout: {allowed_stdout:?}, stderr: {:?}",
        allowed.status,
        String::from_utf8_lossy(&allowed.stderr)
    );
    assert!(
        allowed_stdout.contains("before"),
        "unexpected stdout: {allowed_stdout:?}"
    );
    assert!(
        allowed_stdout.contains("child-executed"),
        "unrestricted control did not run the child; stdout: {allowed_stdout:?}, stderr: {:?}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    assert!(
        allowed_stdout.contains("after"),
        "unexpected stdout: {allowed_stdout:?}"
    );

    let jail = Jail::new(root.path(), "seatbelt-no-subprocess").deny_subprocess();
    let command = Command::new(&helper);
    let output = SeatbeltBackend::new()
        .spawn_captured(&jail, command)?
        .wait_with_output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        output.status.success(),
        "the jailed process should continue after fork is denied; status: {}, stdout: {stdout:?}, stderr: {:?}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("before"), "unexpected stdout: {stdout:?}");
    assert!(
        stdout.contains("fork-denied"),
        "fork was not denied: {stdout:?}"
    );
    assert!(
        !stdout.contains("child-executed"),
        "Seatbelt allowed the child process; stdout: {stdout:?}, stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("after"), "unexpected stdout: {stdout:?}");
    eprintln!("[seatbelt-live] deny-subprocess behavior passed");
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn live_seatbelt_denies_configured_file_reads() -> std::io::Result<()> {
    use std::process::Command;

    const REQUIRE_SEATBELT_TEST: &str = "TINYBOX_REQUIRE_SEATBELT_TESTS";
    if !std::path::Path::new("/usr/bin/sandbox-exec").is_file() {
        if std::env::var_os(REQUIRE_SEATBELT_TEST).is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "required macOS Seatbelt test cannot run: /usr/bin/sandbox-exec is absent",
            ));
        }
        eprintln!("[seatbelt-live] SKIP: /usr/bin/sandbox-exec is absent");
        return Ok(());
    }

    let temp = tempfile::tempdir()?;
    let root = temp.path().canonicalize()?;
    let allowed_file = root.join("allowed.txt");
    let protected_file = root.join("protected.txt");
    fs::write(&allowed_file, b"allowed")?;
    fs::write(&protected_file, b"protected")?;

    const READ_PROBE: &str = r#"
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <unistd.h>

static void emit(const char *message, size_t length) {
    (void)write(STDOUT_FILENO, message, length);
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    char byte;
    int allowed = open(argv[1], O_RDONLY);
    if (allowed < 0 || read(allowed, &byte, 1) != 1) return 3;
    (void)close(allowed);
    emit("allowed-read\n", 13);

    int protected = open(argv[2], O_RDONLY);
    if (protected < 0) {
        if (errno != EACCES && errno != EPERM) return 4;
        emit("protected-denied\n", 17);
    } else {
        emit("protected-read\n", 15);
        (void)close(protected);
    }
    emit("continued\n", 10);
    return 0;
}
"#;
    let source = root.join("file_probe.c");
    fs::write(&source, READ_PROBE)?;
    let helper = root.join("file_probe");
    let compilation = match Command::new("cc")
        .args(["-Wall", "-Werror", "-o"])
        .arg(&helper)
        .arg(&source)
        .output()
    {
        Ok(compilation) => compilation,
        Err(error) if std::env::var_os(REQUIRE_SEATBELT_TEST).is_none() => {
            eprintln!("[seatbelt-live] SKIP: C compiler unavailable: {error}");
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    assert!(
        compilation.status.success(),
        "could not compile file probe: stdout: {:?}, stderr: {:?}",
        String::from_utf8_lossy(&compilation.stdout),
        String::from_utf8_lossy(&compilation.stderr)
    );

    let run_probe = |jail: &Jail| -> std::io::Result<std::process::Output> {
        let mut command = Command::new(&helper);
        command.arg(&allowed_file).arg(&protected_file);
        SeatbeltBackend::new()
            .spawn_captured(jail, command)?
            .wait_with_output()
    };

    let allowed = run_probe(&Jail::new(&root, "seatbelt-file-read-control"))?;
    let allowed_stdout = String::from_utf8_lossy(&allowed.stdout);
    assert!(
        allowed.status.success(),
        "unrestricted file-read control failed: status {}, stdout: {allowed_stdout:?}, stderr: {:?}",
        allowed.status,
        String::from_utf8_lossy(&allowed.stderr)
    );
    assert!(
        allowed_stdout.contains("allowed-read"),
        "stdout: {allowed_stdout:?}"
    );
    assert!(
        allowed_stdout.contains("protected-read"),
        "stdout: {allowed_stdout:?}"
    );
    assert!(
        allowed_stdout.contains("continued"),
        "stdout: {allowed_stdout:?}"
    );

    let mut jail = Jail::new(&root, "seatbelt-deny-file-read");
    jail.deny_read.push(protected_file.clone());
    jail.canonicalize()?;
    let denied = run_probe(&jail)?;
    let denied_stdout = String::from_utf8_lossy(&denied.stdout);
    assert!(
        denied.status.success(),
        "denied file-read probe did not continue: status {}, stdout: {denied_stdout:?}, stderr: {:?}",
        denied.status,
        String::from_utf8_lossy(&denied.stderr)
    );
    assert!(
        denied_stdout.contains("allowed-read"),
        "stdout: {denied_stdout:?}"
    );
    assert!(
        denied_stdout.contains("protected-denied"),
        "stdout: {denied_stdout:?}"
    );
    assert!(
        !denied_stdout.contains("protected-read"),
        "Seatbelt allowed the protected file read; stdout: {denied_stdout:?}, stderr: {:?}",
        String::from_utf8_lossy(&denied.stderr)
    );
    assert!(
        denied_stdout.contains("continued"),
        "stdout: {denied_stdout:?}"
    );
    eprintln!("[seatbelt-live] deny-file-read behavior passed");
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn live_seatbelt_canonicalizes_private_tmp_deny_aliases() -> std::io::Result<()> {
    use std::process::Command;

    const REQUIRE_SEATBELT_TEST: &str = "TINYBOX_REQUIRE_SEATBELT_TESTS";
    if !std::path::Path::new("/usr/bin/sandbox-exec").is_file() {
        if std::env::var_os(REQUIRE_SEATBELT_TEST).is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "required macOS Seatbelt test cannot run: /usr/bin/sandbox-exec is absent",
            ));
        }
        eprintln!("[seatbelt-live] SKIP: /usr/bin/sandbox-exec is absent");
        return Ok(());
    }

    let temp = tempfile::Builder::new()
        .prefix("tinybox-private-alias-")
        .tempdir_in("/tmp")?;
    let alias_root = temp.path().to_path_buf();
    let root = alias_root.canonicalize()?;
    assert_ne!(
        alias_root, root,
        "the live test requires /tmp to resolve through its /private alias"
    );
    let protected_via_alias = alias_root.join("protected.txt");
    let protected_canonical = root.join("protected.txt");
    fs::write(&protected_via_alias, b"protected")?;

    const READ_PROBE: &str = r#"
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <unistd.h>

static void emit(const char *message, size_t length) {
    (void)write(STDOUT_FILENO, message, length);
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    char byte;
    int file = open(argv[1], O_RDONLY);
    if (file < 0 || read(file, &byte, 1) != 1) return 3;
    (void)close(file);
    emit("control-readable\n", 17);

    file = open(argv[2], O_RDONLY);
    if (file < 0 && (errno == EACCES || errno == EPERM)) {
        emit("alias-denied\n", 13);
    } else if (file >= 0) {
        emit("alias-readable\n", 15);
        (void)close(file);
    } else {
        return 4;
    }
    emit("continued\n", 10);
    return 0;
}
"#;
    let source = root.join("private_alias_probe.c");
    fs::write(&source, READ_PROBE)?;
    let helper = root.join("private_alias_probe");
    let compilation = Command::new("cc")
        .args(["-Wall", "-Werror", "-o"])
        .arg(&helper)
        .arg(&source)
        .output()?;
    assert!(
        compilation.status.success(),
        "could not compile private-alias probe: stdout: {:?}, stderr: {:?}",
        String::from_utf8_lossy(&compilation.stdout),
        String::from_utf8_lossy(&compilation.stderr)
    );

    let run_probe = |jail: &Jail| -> std::io::Result<std::process::Output> {
        let mut command = Command::new(&helper);
        command.arg(&protected_canonical).arg(&protected_canonical);
        SeatbeltBackend::new()
            .spawn_captured(jail, command)?
            .wait_with_output()
    };

    let control = run_probe(&Jail::new(&root, "private-alias-control"))?;
    let control_stdout = String::from_utf8_lossy(&control.stdout);
    assert!(
        control.status.success(),
        "unrestricted file-read control failed: status {}, stdout: {control_stdout:?}, stderr: {:?}",
        control.status,
        String::from_utf8_lossy(&control.stderr)
    );
    assert!(
        control_stdout.contains("alias-readable"),
        "stdout: {control_stdout:?}"
    );
    assert!(
        control_stdout.contains("continued"),
        "stdout: {control_stdout:?}"
    );

    let mut jail = Jail::new(&root, "private-alias-denial");
    jail.deny_read.push(protected_via_alias);
    jail.canonicalize()?;
    assert_eq!(jail.deny_read, [protected_canonical.clone()]);
    let denied = run_probe(&jail)?;
    let denied_stdout = String::from_utf8_lossy(&denied.stdout);
    assert!(
        denied.status.success(),
        "denied file-read probe did not continue: status {}, stdout: {denied_stdout:?}, stderr: {:?}",
        denied.status,
        String::from_utf8_lossy(&denied.stderr)
    );
    assert!(
        denied_stdout.contains("control-readable"),
        "stdout: {denied_stdout:?}"
    );
    assert!(
        denied_stdout.contains("alias-denied"),
        "stdout: {denied_stdout:?}"
    );
    assert!(
        !denied_stdout.contains("alias-readable"),
        "stdout: {denied_stdout:?}"
    );
    assert!(
        denied_stdout.contains("continued"),
        "stdout: {denied_stdout:?}"
    );
    eprintln!("[seatbelt-live] /private tmp deny alias behavior passed");
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn live_seatbelt_denies_configured_file_writes_without_stopping_the_process() -> std::io::Result<()>
{
    use std::process::Command;

    const REQUIRE_SEATBELT_TEST: &str = "TINYBOX_REQUIRE_SEATBELT_TESTS";
    if !std::path::Path::new("/usr/bin/sandbox-exec").is_file() {
        if std::env::var_os(REQUIRE_SEATBELT_TEST).is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "required macOS Seatbelt test cannot run: /usr/bin/sandbox-exec is absent",
            ));
        }
        eprintln!("[seatbelt-live] SKIP: /usr/bin/sandbox-exec is absent");
        return Ok(());
    }

    let temp = tempfile::tempdir()?;
    let root = temp.path().canonicalize()?;
    let allowed_file = root.join("allowed.txt");
    let protected_file = root.join("protected.txt");
    fs::write(&allowed_file, b"allowed-original")?;
    fs::write(&protected_file, b"protected-original-bytes")?;

    const WRITE_PROBE: &str = r#"
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

static void emit(const char *message, size_t length) {
    (void)write(STDOUT_FILENO, message, length);
}

static int replace_file(const char *path, const char *contents, size_t length) {
    int file = open(path, O_WRONLY | O_TRUNC);
    if (file < 0) return -1;
    ssize_t written = write(file, contents, length);
    int saved_errno = errno;
    (void)close(file);
    errno = saved_errno;
    return written == (ssize_t)length ? 0 : -1;
}

int main(int argc, char **argv) {
    if (argc != 4) return 2;
    if (replace_file(argv[1], "allowed-replaced", 16) != 0) return 3;
    emit("allowed-write\n", 14);

    if (strcmp(argv[3], "control") == 0) {
        if (replace_file(argv[2], "control-replaced", 16) != 0) return 4;
        emit("control-protected-write\n", 24);
    } else {
        int protected = open(argv[2], O_WRONLY | O_TRUNC);
        if (protected < 0) {
            if (errno != EACCES && errno != EPERM) return 5;
            emit("protected-write-denied\n", 23);
        } else {
            const char *unexpected = "unexpected-write";
            (void)write(protected, unexpected, strlen(unexpected));
            (void)close(protected);
            emit("protected-write-allowed\n", 24);
        }
    }

    emit("continued\n", 10);
    return 0;
}
"#;
    let source = root.join("write_probe.c");
    fs::write(&source, WRITE_PROBE)?;
    let helper = root.join("write_probe");
    let compilation = match Command::new("cc")
        .args(["-Wall", "-Werror", "-o"])
        .arg(&helper)
        .arg(&source)
        .output()
    {
        Ok(compilation) => compilation,
        Err(error) if std::env::var_os(REQUIRE_SEATBELT_TEST).is_none() => {
            eprintln!("[seatbelt-live] SKIP: C compiler unavailable: {error}");
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    assert!(
        compilation.status.success(),
        "could not compile write probe: stdout: {:?}, stderr: {:?}",
        String::from_utf8_lossy(&compilation.stdout),
        String::from_utf8_lossy(&compilation.stderr)
    );

    let run_probe = |jail: &Jail, mode: &str| -> std::io::Result<std::process::Output> {
        let mut command = Command::new(&helper);
        command.arg(&allowed_file).arg(&protected_file).arg(mode);
        SeatbeltBackend::new()
            .spawn_captured(jail, command)?
            .wait_with_output()
    };

    let control = run_probe(&Jail::new(&root, "seatbelt-file-write-control"), "control")?;
    let control_stdout = String::from_utf8_lossy(&control.stdout);
    assert!(
        control.status.success(),
        "unrestricted file-write control failed: status {}, stdout: {control_stdout:?}, stderr: {:?}",
        control.status,
        String::from_utf8_lossy(&control.stderr)
    );
    assert!(
        control_stdout.contains("allowed-write"),
        "stdout: {control_stdout:?}"
    );
    assert!(
        control_stdout.contains("control-protected-write"),
        "unrestricted control could not write the protected target: stdout: {control_stdout:?}, stderr: {:?}",
        String::from_utf8_lossy(&control.stderr)
    );
    assert!(
        control_stdout.contains("continued"),
        "stdout: {control_stdout:?}"
    );
    assert_eq!(fs::read(&allowed_file)?, b"allowed-replaced");
    assert_eq!(fs::read(&protected_file)?, b"control-replaced");

    fs::write(&allowed_file, b"allowed-original")?;
    fs::write(&protected_file, b"protected-original-bytes")?;
    let mut jail = Jail::new(&root, "seatbelt-deny-file-write");
    jail.deny_read.push(protected_file.clone());
    jail.canonicalize()?;
    let profile = render_profile(&jail);
    let denied_path = format!(
        "(deny file-read* file-write*\n  (subpath \"{}\")",
        escape(&protected_file.to_string_lossy())
    );
    assert!(
        profile.contains(&denied_path),
        "profile does not deny reads and writes for the configured protected path: {profile}"
    );

    let denied = run_probe(&jail, "deny")?;
    let denied_stdout = String::from_utf8_lossy(&denied.stdout);
    assert!(
        denied.status.success(),
        "denied file-write probe did not continue: status {}, stdout: {denied_stdout:?}, stderr: {:?}",
        denied.status,
        String::from_utf8_lossy(&denied.stderr)
    );
    assert!(
        denied_stdout.contains("allowed-write"),
        "allowed writes under the jail root should still work: stdout: {denied_stdout:?}, stderr: {:?}",
        String::from_utf8_lossy(&denied.stderr)
    );
    assert!(
        denied_stdout.contains("protected-write-denied"),
        "O_TRUNC was not denied with EPERM/EACCES: stdout: {denied_stdout:?}, stderr: {:?}",
        String::from_utf8_lossy(&denied.stderr)
    );
    assert!(
        !denied_stdout.contains("protected-write-allowed"),
        "Seatbelt allowed O_TRUNC on the protected file: stdout: {denied_stdout:?}, stderr: {:?}",
        String::from_utf8_lossy(&denied.stderr)
    );
    assert!(
        denied_stdout.contains("continued"),
        "stdout: {denied_stdout:?}"
    );
    assert_eq!(fs::read(&allowed_file)?, b"allowed-replaced");
    assert_eq!(
        fs::read(&protected_file)?,
        b"protected-original-bytes",
        "protected file changed despite the denied O_TRUNC attempt"
    );
    eprintln!("[seatbelt-live] deny-file-write behavior passed");
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn live_seatbelt_denies_network_connections_without_stopping_the_process() -> std::io::Result<()> {
    use std::net::TcpListener;
    use std::process::Command;

    const REQUIRE_SEATBELT_TEST: &str = "TINYBOX_REQUIRE_SEATBELT_TESTS";
    if !std::path::Path::new("/usr/bin/sandbox-exec").is_file() {
        if std::env::var_os(REQUIRE_SEATBELT_TEST).is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "required macOS Seatbelt test cannot run: /usr/bin/sandbox-exec is absent",
            ));
        }
        eprintln!("[seatbelt-live] SKIP: /usr/bin/sandbox-exec is absent");
        return Ok(());
    }

    let temp = tempfile::tempdir()?;
    let root = temp.path().canonicalize()?;
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port().to_string();

    const CONNECT_PROBE: &str = r#"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void emit(const char *message, size_t length) {
    (void)write(STDOUT_FILENO, message, length);
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    unsigned long port = strtoul(argv[1], NULL, 10);
    if (port == 0 || port > 65535) return 3;

    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) return 4;
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short)port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int result = connect(socket_fd, (struct sockaddr *)&address, sizeof(address));
    if (strcmp(argv[2], "control") == 0) {
        if (result != 0) return 5;
        emit("control-connected\n", 18);
    } else if (result < 0 && (errno == EACCES || errno == EPERM)) {
        emit("connection-denied\n", 18);
    } else if (result == 0) {
        emit("connection-allowed\n", 19);
    } else {
        return 6;
    }

    emit("continued\n", 10);
    (void)close(socket_fd);
    return 0;
}
"#;
    let source = root.join("connect_probe.c");
    fs::write(&source, CONNECT_PROBE)?;
    let helper = root.join("connect_probe");
    let compilation = match Command::new("cc")
        .args(["-Wall", "-Werror", "-o"])
        .arg(&helper)
        .arg(&source)
        .output()
    {
        Ok(compilation) => compilation,
        Err(error) if std::env::var_os(REQUIRE_SEATBELT_TEST).is_none() => {
            eprintln!("[seatbelt-live] SKIP: C compiler unavailable: {error}");
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    assert!(
        compilation.status.success(),
        "could not compile network probe: stdout: {:?}, stderr: {:?}",
        String::from_utf8_lossy(&compilation.stdout),
        String::from_utf8_lossy(&compilation.stderr)
    );

    let run_probe = |jail: &Jail, mode: &str| -> std::io::Result<std::process::Output> {
        let mut command = Command::new(&helper);
        command.arg(&port).arg(mode);
        SeatbeltBackend::new()
            .spawn_captured(jail, command)?
            .wait_with_output()
    };

    let control = run_probe(&Jail::new(&root, "seatbelt-network-control"), "control")?;
    let control_stdout = String::from_utf8_lossy(&control.stdout);
    assert!(
        control.status.success(),
        "unrestricted network control failed: status {}, stdout: {control_stdout:?}, stderr: {:?}",
        control.status,
        String::from_utf8_lossy(&control.stderr)
    );
    assert!(
        control_stdout.contains("control-connected"),
        "unrestricted helper could not connect to the loopback listener: stdout: {control_stdout:?}, stderr: {:?}",
        String::from_utf8_lossy(&control.stderr)
    );
    assert!(
        control_stdout.contains("continued"),
        "stdout: {control_stdout:?}"
    );
    listener.accept()?;
    listener.set_nonblocking(true)?;

    let jail = Jail::new(&root, "seatbelt-deny-network").deny_net();
    let profile = render_profile(&jail);
    assert!(
        profile.contains("(deny network*)\n"),
        "profile does not contain the configured network denial: {profile}"
    );
    let denied = run_probe(&jail, "deny")?;
    let denied_stdout = String::from_utf8_lossy(&denied.stdout);
    assert!(
        denied.status.success(),
        "denied network probe did not continue: status {}, stdout: {denied_stdout:?}, stderr: {:?}",
        denied.status,
        String::from_utf8_lossy(&denied.stderr)
    );
    assert!(
        denied_stdout.contains("connection-denied"),
        "loopback connect was not denied with EPERM/EACCES: stdout: {denied_stdout:?}, stderr: {:?}",
        String::from_utf8_lossy(&denied.stderr)
    );
    assert!(
        !denied_stdout.contains("connection-allowed"),
        "Seatbelt allowed the jailed connection: stdout: {denied_stdout:?}, stderr: {:?}",
        String::from_utf8_lossy(&denied.stderr)
    );
    assert!(
        denied_stdout.contains("continued"),
        "stdout: {denied_stdout:?}"
    );
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "the jailed process established a connection to the loopback listener"
    );
    eprintln!("[seatbelt-live] deny-network behavior passed");
    Ok(())
}

#[test]
fn profile_allow_subprocess_default_has_no_process_deny() {
    let jail = Jail::new("/tmp", "x");
    let p = render_profile(&jail);
    assert!(!p.contains("(deny process-fork)"));
    assert!(!p.contains("(deny process-exec)"));
}

#[test]
fn profile_denies_reads_and_writes_of_denied_paths_last() {
    let mut jail = Jail::new("/Users/a/project", "x");
    assert!(!render_profile(&jail).contains("file-read*"));
    jail.deny_read = vec!["/Users/a/.ssh".into(), "/Users/a/.netrc".into()];
    let p = render_profile(&jail);
    let denial = p
        .find("(deny file-read* file-write*")
        .expect("denied paths are emitted");
    // After the write allows, so it overrides them.
    assert!(denial > p.find("(allow file-write*").unwrap());
    assert!(p[denial..].contains("(subpath \"/Users/a/.ssh\")"));
    assert!(p[denial..].contains("(subpath \"/Users/a/.netrc\")"));
    assert!(SeatbeltBackend::new().carves_denials());
}

#[test]
fn escape_handles_backslash_and_quote() {
    assert_eq!(escape("a\\b"), "a\\\\b");
    assert_eq!(escape("a\"b"), "a\\\"b");
    assert_eq!(escape("a\\\"b"), "a\\\\\\\"b");
    assert_eq!(escape("plain"), "plain");
}

#[test]
fn is_available_reflects_sandbox_exec_presence() {
    let backend = SeatbeltBackend::new();
    let expected = std::path::Path::new("/usr/bin/sandbox-exec").exists();
    assert_eq!(backend.is_available(), expected);
    assert_eq!(backend.name(), "seatbelt");
}

#[test]
fn seatbelt_passes_cwd_through() {
    let backend = SeatbeltBackend::new();
    if !backend.is_available() {
        return;
    }
    let root = std::env::temp_dir().join(format!("oh-cwd-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let mut jail = Jail::new(&root, "cwd");
    // `/tmp` canonicalizes to `/private/tmp` on macOS — subpath
    // matching in the Seatbelt profile is by canonical path, so
    // unless we resolve first the write inside root gets denied.
    // This is exactly what the `spawn` facade does for callers.
    jail.canonicalize().unwrap();
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg("pwd > pwd.out")
        .current_dir(&root)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = backend.spawn(&jail, cmd).expect("spawn");
    let status = child.wait().expect("wait");
    assert!(status.success());
    let written = fs::read_to_string(root.join("pwd.out")).unwrap();
    // pwd resolves through /private on macOS — we just check it ends
    // with the basename of root.
    let last = root.file_name().unwrap().to_string_lossy().to_string();
    assert!(
        written.trim().ends_with(&last),
        "pwd output {written:?} did not end with {last}"
    );
    fs::remove_dir_all(&root).ok();
}

#[test]
fn seatbelt_passes_env_through() {
    let backend = SeatbeltBackend::new();
    if !backend.is_available() {
        return;
    }
    let root = std::env::temp_dir().join(format!("oh-env-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let mut jail = Jail::new(&root, "env");
    jail.canonicalize().unwrap();
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg("echo $OPENHUMAN_TEST_VAR > env.out")
        .env("OPENHUMAN_TEST_VAR", "hello-from-jail")
        .current_dir(&root)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = backend.spawn(&jail, cmd).expect("spawn");
    child.wait().expect("wait");
    let written = fs::read_to_string(root.join("env.out")).unwrap();
    assert_eq!(written.trim(), "hello-from-jail");
    fs::remove_dir_all(&root).ok();
}

#[test]
fn profile_allows_default_and_jails_writes() {
    let jail = Jail::new("/tmp/abc", "test").deny_net();
    let p = render_profile(&jail);
    assert!(p.contains("(allow default)"));
    assert!(p.contains("(deny file-write*)"));
    assert!(p.contains("(subpath \"/tmp/abc\")"));
    assert!(p.contains("(literal \"/dev/null\")"));
    assert!(!p.contains("(subpath \"/dev\")"));
    assert!(p.contains("(deny network*)"));
}

#[test]
fn seatbelt_allows_redirecting_output_to_dev_null() {
    let backend = SeatbeltBackend::new();
    if !backend.is_available() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path();
    let mut jail = Jail::new(root_path, "null-redirection");
    jail.canonicalize().unwrap();

    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg(
            "set -e; echo ignored >/dev/null; echo hidden 2>/dev/null >&2; echo completed > output",
        )
        .current_dir(root_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = backend.spawn(&jail, cmd).expect("spawn");
    let status = child.wait().expect("wait");

    assert!(
        status.success(),
        "shell redirection to /dev/null was denied"
    );
    assert_eq!(
        fs::read_to_string(root_path.join("output")).unwrap(),
        "completed\n"
    );
}

#[test]
fn seatbelt_spawn_runs_true() {
    let backend = SeatbeltBackend::new();
    if !backend.is_available() {
        return;
    }
    let dir = std::env::temp_dir();
    let jail = Jail::new(&dir, "test.true");
    let mut cmd = Command::new("/usr/bin/true");
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    let mut child = backend.spawn(&jail, cmd).expect("spawn");
    let status = child.wait().expect("wait");
    assert!(status.success(), "sandboxed /usr/bin/true exited non-zero");
}

#[test]
fn seatbelt_blocks_write_outside_root() {
    let backend = SeatbeltBackend::new();
    if !backend.is_available() {
        return;
    }
    // Root = a fresh tempdir. Try to touch a file *outside* it.
    let root = std::env::temp_dir().join(format!("openhuman-encap-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let outside =
        std::env::temp_dir().join(format!("openhuman-encap-outside-{}", std::process::id()));
    let _ = fs::remove_file(&outside);

    let jail = Jail::new(&root, "test.blocked");
    let mut cmd = Command::new("/usr/bin/touch");
    cmd.arg(&outside)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = backend.spawn(&jail, cmd).expect("spawn");
    let status = child.wait().expect("wait");

    // If the touch succeeded (file exists), seatbelt enforcement is not
    // available in this environment (e.g. the process is already running
    // inside a sandbox that supersedes sandbox-exec, or a corporate MDM
    // policy disables it). Skip rather than panic — the production
    // encapsulation path is guarded by `is_available()` at runtime.
    if outside.exists() {
        let _ = fs::remove_file(&outside);
        let _ = fs::remove_dir_all(&root);
        eprintln!(
            "seatbelt_blocks_write_outside_root: skipped — \
             sandbox-exec present but not enforcing in this environment"
        );
        return;
    }
    // Enforced path: the write was actually blocked, so `touch` must have
    // exited non-zero.
    assert!(
        !status.success(),
        "touch outside jail should fail when seatbelt is enforcing"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn profile_allows_writes_under_read_write_paths() {
    let jail = Jail::new("/work/root", "x")
        .add_read_write("/state/capture/1")
        .add_read_write("/state/with \"quote\"");
    let p = render_profile(&jail);
    let allow = p
        .split("(allow file-write*")
        .nth(1)
        .expect("profile has a file-write allow block");
    assert!(allow.contains("(subpath \"/work/root\")"));
    assert!(allow.contains("(subpath \"/state/capture/1\")"));
    assert!(allow.contains("(subpath \"/state/with \\\"quote\\\"\")"));
}

#[test]
fn profile_without_read_write_paths_only_allows_root_and_tmp() {
    let p = render_profile(&Jail::new("/work/root", "x"));
    assert_eq!(p.matches("(subpath ").count(), 2);
}

#[test]
fn launcher_preserves_arguments_environment_overrides_and_working_directory() {
    let jail = Jail::new("/work", "forwarding");
    let mut cmd = Command::new("/bin/tool");
    cmd.arg("a b")
        .arg("$(literal)")
        .env("SET", "value")
        .env_remove("REMOVE")
        .current_dir("/work");
    let wrapper = prepare_command(&jail, &cmd, std::ffi::OsStr::new("launcher"));
    assert_eq!(wrapper.get_program(), "launcher");
    let args: Vec<_> = wrapper.get_args().collect();
    assert_eq!(
        args,
        vec![
            "-p",
            &render_profile(&jail),
            "/bin/tool",
            "a b",
            "$(literal)"
        ]
    );
    assert_eq!(
        wrapper.get_current_dir(),
        Some(std::path::Path::new("/work"))
    );
    let env: Vec<_> = wrapper.get_envs().collect();
    assert!(env.contains(&(
        std::ffi::OsStr::new("SET"),
        Some(std::ffi::OsStr::new("value"))
    )));
    assert!(
        env.iter()
            .all(|(key, _)| *key != std::ffi::OsStr::new("REMOVE"))
    );
    let defaults = prepare_command(
        &jail,
        &Command::new("true"),
        std::ffi::OsStr::new("launcher"),
    );
    assert!(defaults.get_current_dir().is_none());
    assert_default_name::<SeatbeltBackend>("seatbelt");
}

#[test]
fn missing_launcher_returns_an_error() {
    let result = SeatbeltBackend::new().spawn(
        &Jail::new("/work", "missing"),
        Command::new("/nonexistent/tinybox-command"),
    );
    if !SeatbeltBackend::new().is_available() {
        assert_eq!(
            result.err().map(|e| e.kind()),
            Some(std::io::ErrorKind::NotFound)
        );
    }
}

/// Check the default-construction contract through the backend trait.
fn assert_default_name<B: JailBackend + Default>(name: &str) {
    assert_eq!(B::default().name(), name);
}

/// Exercise the real wrapper environment using a fake launcher on Unix hosts.
#[cfg(unix)]
#[test]
fn launcher_does_not_restore_inherited_environment_after_env_clear() -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    const SENTINEL: &str = "TINYBOX_JAIL_TEST_INHERITED_SECRET";
    if std::env::var_os(SENTINEL).is_none() {
        // Set a parent-only sentinel in a subprocess; never mutate the shared
        // environment of parallel test threads.
        let output = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "macos::tests::launcher_does_not_restore_inherited_environment_after_env_clear",
                "--nocapture",
            ])
            .env(SENTINEL, "parent-only-secret")
            .output()?;
        assert!(
            output.status.success(),
            "isolated test failed: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    let launcher = root.path().join("launcher");
    fs::write(&launcher, "#!/bin/sh\nshift 2\nexec \"$@\"\n")?;
    fs::set_permissions(&launcher, fs::Permissions::from_mode(0o700))?;
    let mut cmd = Command::new("/usr/bin/env");
    cmd.env_clear().env("JAIL_EXPLICIT", "allowed");
    let output = prepare_command(
        &Jail::new(root.path(), "environment"),
        &cmd,
        launcher.as_os_str(),
    )
    .output()?;
    assert!(output.status.success());
    // The shell may synthesize PWD/SHLVL and other local variables. The
    // boundary is the parent sentinel, not a whitelist of shell internals.
    let env = String::from_utf8_lossy(&output.stdout);
    assert!(env.lines().any(|line| line == "JAIL_EXPLICIT=allowed"));
    assert!(
        !env.lines()
            .any(|line| line.starts_with(&format!("{SENTINEL}="))),
        "the launcher restored the inherited parent sentinel"
    );
    Ok(())
}

/// The launcher must lead its own process group, or a caller that times the
/// jailed command out can only kill `sandbox-exec` while the shell pipeline it
/// launched keeps running. Spawn a shell with a background grandchild, signal
/// the launcher's group, and the grandchild must be gone.
#[test]
fn launcher_leads_a_process_group_so_a_group_kill_reaches_grandchildren() {
    let backend = SeatbeltBackend::new();
    if !backend.is_available() {
        return;
    }
    let root = std::env::temp_dir().join(format!("oh-pg-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let mut jail = Jail::new(&root, "pg");
    jail.canonicalize().unwrap();
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg("sleep 30 & echo $! > gc.pid; wait")
        .current_dir(&root)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = backend.spawn(&jail, cmd).expect("spawn");

    let pidfile = root.join("gc.pid");
    let grandchild = loop {
        if let Ok(text) = fs::read_to_string(&pidfile)
            && let Ok(pid) = text.trim().parse::<u32>()
        {
            break pid;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    // Signal the launcher's group, as a timeout would.
    let killed = Command::new("kill")
        .args(["-KILL", &format!("-{}", child.id())])
        .status()
        .expect("kill runs");
    assert!(
        killed.success(),
        "the launcher must lead a group that can be signalled"
    );
    let _ = child.wait();

    let mut gone = false;
    for _ in 0..100 {
        let alive = Command::new("kill")
            .args(["-0", &grandchild.to_string()])
            .status()
            .is_ok_and(|s| s.success());
        if !alive {
            gone = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    fs::remove_dir_all(&root).ok();
    assert!(gone, "grandchild {grandchild} survived the group kill");
}

#[test]
fn executable_presence_cannot_satisfy_hard_seatbelt_denials() {
    use tinybox_core::{Constraint, ConstraintSupport, Enforcement};
    assert_eq!(declared_constraint_support(false), ConstraintSupport::NONE);
    // No process-isolation guarantee can follow from a launcher-presence check,
    // even on macOS where the launcher exists.
    assert_eq!(
        SeatbeltBackend::new().isolation(),
        tinybox_core::IsolationLevel::None
    );
    let present = declared_constraint_support(true);
    for constraint in [
        Constraint::Filesystem,
        Constraint::Network,
        Constraint::Subprocess,
    ] {
        assert_eq!(present.enforcement(constraint), Enforcement::BestEffort);
        assert!(matches!(
            present.require("seatbelt", &[constraint]),
            Err(tinybox_core::Error::ConstraintNotEnforced {
                enforcement: Enforcement::BestEffort,
                ..
            })
        ));
    }
}

#[test]
fn seatbelt_reports_resource_limits_unsupported() {
    use tinybox_core::{Constraint, Enforcement};

    let support = declared_constraint_support(true);
    for constraint in [
        Constraint::Cpu,
        Constraint::Memory,
        Constraint::Pids,
        Constraint::Disk,
    ] {
        assert_eq!(
            support.enforcement(constraint),
            Enforcement::Unsupported,
            "Seatbelt must not claim {constraint} enforcement without a native limit",
        );
        assert!(matches!(
            support.require("seatbelt", &[constraint]),
            Err(tinybox_core::Error::ConstraintNotEnforced {
                sandbox,
                constraint: rejected,
                enforcement: Enforcement::Unsupported,
            }) if sandbox == "seatbelt" && rejected == constraint
        ));
    }
}

#[cfg(unix)]
#[test]
fn captured_launcher_preserves_all_three_owned_pipes() -> std::io::Result<()> {
    use std::io::Write;
    let root = tempfile::tempdir()?;
    // A stable fixture avoids ETXTBSY when parallel fork/exec temporarily
    // inherits a just-created executable's writable descriptor.
    let launcher = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/captured-launcher.sh");
    let jail = Jail::new(root.path(), "captured-fixture");
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "cat; printf diagnostic >&2"])
        .env_clear();
    let mut child = prepare_captured_command(&jail, &command, launcher.as_os_str()).spawn()?;
    let mut input = child
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("missing stdin"))?;
    input.write_all(b"owned-input")?;
    drop(input);
    let output = child.wait_with_output()?;
    assert!(output.status.success());
    assert_eq!(output.stdout, b"owned-input");
    assert_eq!(output.stderr, b"diagnostic");
    Ok(())
}
