//! Bounded collection of standard-library children created by native jail backends.
use super::{observer_cancelled, pipe, read_with_observer};
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tinybox_core::{Error, ExecOutput, ExecRequest, ExecutionObserver, Host, OutputStream, Result};
use tinybox_jail::{Jail, JailBackend, JailInvocation, OwnedChild, ResourceLimitPlan};
use tokio::io::AsyncWriteExt;
use tokio::sync::{oneshot, watch};

type Retained = Arc<tokio::sync::Mutex<Option<OwnedChild>>>;
struct State {
    active: AtomicUsize,
    failed: Mutex<BTreeMap<i32, Retained>>,
    cleanup: tokio::sync::Mutex<()>,
    finished: watch::Sender<u64>,
}
struct Active(Arc<State>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
        self.0
            .finished
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }
}

fn spawn_owned(
    backend: &dyn JailBackend,
    jail: &Jail,
    invocation: Option<&JailInvocation>,
    command: std::process::Command,
) -> std::io::Result<OwnedChild> {
    if let Some(invocation) = invocation {
        tinybox_jail::spawn_owned_invocation_with_command(backend, jail, invocation, command)
    } else {
        tinybox_jail::spawn_owned_captured_with(backend, jail, command)
    }
}

#[cfg(target_os = "linux")]
const MEMORY_EVENT_FILE_ENV: &str = "TINYBOX_INTERNAL_MEMORY_EVENT_FILE";
#[cfg(target_os = "linux")]
const PIDS_EVENT_FILE_ENV: &str = "TINYBOX_INTERNAL_PIDS_EVENT_FILE";
#[cfg(target_os = "linux")]
const CPU_EVENT_FILE_ENV: &str = "TINYBOX_INTERNAL_CPU_EVENT_FILE";
#[cfg(target_os = "linux")]
static MEMORY_EVENT_FILE_SEQUENCE: AtomicUsize = AtomicUsize::new(1);
#[cfg(target_os = "linux")]
static PIDS_EVENT_FILE_SEQUENCE: AtomicUsize = AtomicUsize::new(1);
#[cfg(target_os = "linux")]
static CPU_EVENT_FILE_SEQUENCE: AtomicUsize = AtomicUsize::new(1);

/// Private handoff written by the trusted launcher before it stops the scope.
#[cfg(target_os = "linux")]
struct MemoryEventReport(std::path::PathBuf);

#[cfg(target_os = "linux")]
impl MemoryEventReport {
    fn prepare(command: &mut std::process::Command, jail: &Jail) -> Option<Self> {
        let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")?;
        Self::prepare_in(command, jail, std::path::Path::new(&runtime_dir))
    }

    fn prepare_in(
        command: &mut std::process::Command,
        jail: &Jail,
        runtime_dir: &std::path::Path,
    ) -> Option<Self> {
        use std::io::Write;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let has_scope = command
            .get_args()
            .filter_map(|arg| arg.to_str())
            .any(|arg| {
                arg.strip_prefix("--unit=")
                    .and_then(|unit| std::path::Path::new(unit).extension())
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("scope"))
                    && arg.starts_with("--unit=tinybox-native-")
            });
        let has_memory_limit = command
            .get_args()
            .filter_map(|arg| arg.to_str())
            .any(|arg| arg.contains("MemoryMax="));
        let args: Vec<_> = command.get_args().filter_map(|arg| arg.to_str()).collect();
        let masks_runtime = args.windows(2).any(|pair| pair == ["--tmpfs", "/run"]);
        let masks_cgroup = args.windows(2).any(|pair| pair == ["--tmpfs", "/sys"]);
        let clears_target_environment = args.contains(&"--clearenv");
        if !has_scope
            || !has_memory_limit
            || !masks_runtime
            || !masks_cgroup
            || !clears_target_environment
        {
            return None;
        }
        let metadata = std::fs::metadata(runtime_dir).ok()?;
        let process_uid = std::fs::metadata("/proc/self").ok()?.uid();
        if !metadata.is_dir() || metadata.uid() != process_uid || metadata.mode() & 0o077 != 0 {
            return None;
        }
        let sequence = MEMORY_EVENT_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = runtime_dir.join(format!(
            "tinybox-memory-event-{}-{sequence}",
            std::process::id()
        ));
        if jail_exposes_path(jail, &path) {
            return None;
        }
        let mut report = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .ok()?;
        if report.write_all(b"0\n").is_err() {
            let _ = std::fs::remove_file(&path);
            return None;
        }
        command.env(MEMORY_EVENT_FILE_ENV, &path);
        Some(Self(path))
    }

    fn oom_kill_observed(&self) -> bool {
        // This launcher names a fresh systemd scope for every run, so the
        // cgroup-v2 counter begins at zero; a positive final value proves the
        // scope's own OOM-kill event rather than an unrelated SIGKILL.
        std::fs::read_to_string(&self.0)
            .ok()
            .and_then(|contents| parse_oom_kill_counter(&contents))
            .is_some_and(|count| count > 0)
    }
}

#[cfg(target_os = "linux")]
impl Drop for MemoryEventReport {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(target_os = "linux")]
fn parse_oom_kill_counter(events: &str) -> Option<u64> {
    events.trim().parse().ok()
}

#[cfg(target_os = "linux")]
fn jail_exposes_path(jail: &Jail, path: &std::path::Path) -> bool {
    std::iter::once(&jail.root)
        .chain(&jail.read_only)
        .chain(&jail.read_write)
        .any(|mount| path.starts_with(mount))
}

#[cfg(target_os = "linux")]
fn report_memory_termination(
    report: Option<&MemoryEventReport>,
    target: Option<&Arc<dyn ExecutionObserver>>,
) {
    if report.is_some_and(MemoryEventReport::oom_kill_observed)
        && let Some(observer) = target
    {
        observer.termination_cause(tinybox_core::TerminationCause::MemoryLimit);
    }
}

#[cfg(target_os = "linux")]
fn prepare_memory_event_report(
    command: &mut std::process::Command,
    jail: &Jail,
    observer_attached: bool,
) -> Option<MemoryEventReport> {
    observer_attached
        .then(|| MemoryEventReport::prepare(command, jail))
        .flatten()
}

/// Private handoff for a proven cgroup-v2 pids limit event.
#[cfg(target_os = "linux")]
struct PidsEventReport(std::path::PathBuf);

#[cfg(target_os = "linux")]
impl PidsEventReport {
    fn prepare(command: &mut std::process::Command, jail: &Jail) -> Option<Self> {
        let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")?;
        Self::prepare_in(command, jail, std::path::Path::new(&runtime_dir))
    }

    fn prepare_in(
        command: &mut std::process::Command,
        jail: &Jail,
        runtime_dir: &std::path::Path,
    ) -> Option<Self> {
        use std::io::Write;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let args: Vec<_> = command.get_args().filter_map(|arg| arg.to_str()).collect();
        let has_scope = args.iter().any(|arg| {
            arg.strip_prefix("--unit=")
                .and_then(|unit| std::path::Path::new(unit).extension())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("scope"))
                && arg.starts_with("--unit=tinybox-native-")
        });
        let has_pids_limit = args
            .iter()
            .any(|arg| arg.starts_with("--property=TasksMax="));
        let masks_runtime = args.windows(2).any(|pair| pair == ["--tmpfs", "/run"]);
        let masks_cgroup = args.windows(2).any(|pair| pair == ["--tmpfs", "/sys"]);
        let clears_target_environment = args.contains(&"--clearenv");
        if !has_scope
            || !has_pids_limit
            || !masks_runtime
            || !masks_cgroup
            || !clears_target_environment
        {
            return None;
        }
        let metadata = std::fs::metadata(runtime_dir).ok()?;
        let process_uid = std::fs::metadata("/proc/self").ok()?.uid();
        if !metadata.is_dir() || metadata.uid() != process_uid || metadata.mode() & 0o077 != 0 {
            return None;
        }
        let sequence = PIDS_EVENT_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = runtime_dir.join(format!(
            "tinybox-pids-event-{}-{sequence}",
            std::process::id()
        ));
        if jail_exposes_path(jail, &path) {
            return None;
        }
        let mut report = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .ok()?;
        if report.write_all(b"0\n").is_err() {
            let _ = std::fs::remove_file(&path);
            return None;
        }
        command.env(PIDS_EVENT_FILE_ENV, &path);
        Some(Self(path))
    }

    fn max_event_observed(&self) -> bool {
        // Each invocation receives a fresh systemd scope. A positive `max`
        // counter therefore proves this scope hit its own pids limit.
        std::fs::read_to_string(&self.0)
            .ok()
            .and_then(|contents| parse_pids_max_counter(&contents))
            .is_some_and(|count| count > 0)
    }
}

#[cfg(target_os = "linux")]
impl Drop for PidsEventReport {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(target_os = "linux")]
fn parse_pids_max_counter(events: &str) -> Option<u64> {
    events.trim().parse().ok()
}

#[cfg(target_os = "linux")]
fn report_pids_termination(
    report: Option<&PidsEventReport>,
    target: Option<&Arc<dyn ExecutionObserver>>,
) {
    if report.is_some_and(PidsEventReport::max_event_observed)
        && let Some(observer) = target
    {
        observer.termination_cause(tinybox_core::TerminationCause::PidsLimit);
    }
}

#[cfg(target_os = "linux")]
fn prepare_pids_event_report(
    command: &mut std::process::Command,
    jail: &Jail,
    observer_attached: bool,
) -> Option<PidsEventReport> {
    observer_attached
        .then(|| PidsEventReport::prepare(command, jail))
        .flatten()
}

/// Private handoff for a proven cgroup-v2 CPU quota throttling event.
#[cfg(target_os = "linux")]
struct CpuEventReport(std::path::PathBuf);

#[cfg(target_os = "linux")]
impl CpuEventReport {
    fn prepare(command: &mut std::process::Command, jail: &Jail) -> Option<Self> {
        let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")?;
        Self::prepare_in(command, jail, std::path::Path::new(&runtime_dir))
    }

    fn prepare_in(
        command: &mut std::process::Command,
        jail: &Jail,
        runtime_dir: &std::path::Path,
    ) -> Option<Self> {
        use std::io::Write;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let args: Vec<_> = command.get_args().filter_map(|arg| arg.to_str()).collect();
        let has_scope = args.iter().any(|arg| {
            arg.strip_prefix("--unit=")
                .and_then(|unit| std::path::Path::new(unit).extension())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("scope"))
                && arg.starts_with("--unit=tinybox-native-")
        });
        let has_cpu_limit = args
            .iter()
            .any(|arg| arg.starts_with("--property=CPUQuota="));
        let masks_runtime = args.windows(2).any(|pair| pair == ["--tmpfs", "/run"]);
        let masks_cgroup = args.windows(2).any(|pair| pair == ["--tmpfs", "/sys"]);
        let clears_target_environment = args.contains(&"--clearenv");
        if !has_scope
            || !has_cpu_limit
            || !masks_runtime
            || !masks_cgroup
            || !clears_target_environment
        {
            return None;
        }
        let metadata = std::fs::metadata(runtime_dir).ok()?;
        let process_uid = std::fs::metadata("/proc/self").ok()?.uid();
        if !metadata.is_dir() || metadata.uid() != process_uid || metadata.mode() & 0o077 != 0 {
            return None;
        }
        let sequence = CPU_EVENT_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = runtime_dir.join(format!(
            "tinybox-cpu-event-{}-{sequence}",
            std::process::id()
        ));
        if jail_exposes_path(jail, &path) {
            return None;
        }
        let mut report = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .ok()?;
        if report.write_all(b"nr_throttled 0\n").is_err() {
            let _ = std::fs::remove_file(&path);
            return None;
        }
        command.env(CPU_EVENT_FILE_ENV, &path);
        Some(Self(path))
    }

    fn throttling_observed(&self) -> bool {
        // The fresh systemd scope's `nr_throttled` counter increments only
        // when its own CPU quota throttles execution.
        std::fs::read_to_string(&self.0)
            .ok()
            .and_then(|contents| parse_cpu_throttled_counter(&contents))
            .is_some_and(|count| count > 0)
    }
}

#[cfg(target_os = "linux")]
impl Drop for CpuEventReport {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(target_os = "linux")]
fn parse_cpu_throttled_counter(events: &str) -> Option<u64> {
    let mut count = None;
    let mut found_counter = false;
    for line in events.lines() {
        if let Some(value) = line.strip_prefix("nr_throttled ") {
            if found_counter {
                return None;
            }
            found_counter = true;
            count = Some(value.parse().ok()?);
        }
    }
    count
}

#[cfg(target_os = "linux")]
fn report_cpu_termination(
    report: Option<&CpuEventReport>,
    target: Option<&Arc<dyn ExecutionObserver>>,
) {
    if report.is_some_and(CpuEventReport::throttling_observed)
        && let Some(observer) = target
    {
        observer.termination_cause(tinybox_core::TerminationCause::CpuQuota);
    }
}

#[cfg(target_os = "linux")]
fn prepare_cpu_event_report(
    command: &mut std::process::Command,
    jail: &Jail,
    observer_attached: bool,
) -> Option<CpuEventReport> {
    observer_attached
        .then(|| CpuEventReport::prepare(command, jail))
        .flatten()
}

#[cfg(target_os = "linux")]
fn prepare_event_reports(
    command: &mut std::process::Command,
    jail: &Jail,
    observer_attached: bool,
) -> (
    Option<MemoryEventReport>,
    Option<PidsEventReport>,
    Option<CpuEventReport>,
) {
    (
        prepare_memory_event_report(command, jail, observer_attached),
        prepare_pids_event_report(command, jail, observer_attached),
        prepare_cpu_event_report(command, jail, observer_attached),
    )
}

#[cfg(target_os = "linux")]
fn report_event_terminations(
    reports: &(
        Option<MemoryEventReport>,
        Option<PidsEventReport>,
        Option<CpuEventReport>,
    ),
    observer: Option<&Arc<dyn ExecutionObserver>>,
) {
    report_memory_termination(reports.0.as_ref(), observer);
    report_pids_termination(reports.1.as_ref(), observer);
    report_cpu_termination(reports.2.as_ref(), observer);
}

// Standard children do not kill on drop. Keep ownership across supervisor panics
// and aborts so the module can acknowledge cleanup through its normal drain path.
struct RetainedOnDrop {
    child: Option<OwnedChild>,
    group: i32,
    state: Arc<State>,
}
impl Drop for RetainedOnDrop {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            #[cfg(unix)]
            {
                use nix::{
                    sys::signal::{Signal, killpg},
                    unistd::Pid,
                };
                let _ = killpg(Pid::from_raw(self.group), Signal::SIGKILL);
            }
            let _ = child.terminate();
            self.state
                .failed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(self.group, Arc::new(tokio::sync::Mutex::new(Some(child))));
        }
    }
}

/// Local collection whose child is created inside a selected native directory jail.
/// Unavailable backends fail explicitly; this provider never selects an unconfined fallback.
#[derive(Clone)]
pub struct JailLocalHost {
    jail: Jail,
    backend: Arc<dyn JailBackend>,
    resource_plan: Option<ResourceLimitPlan>,
    limit: usize,
    state: Arc<State>,
}
impl std::fmt::Debug for JailLocalHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JailLocalHost")
            .field("backend", &self.backend.name())
            .finish_non_exhaustive()
    }
}
impl JailLocalHost {
    /// Use the detected backend without weakening unavailable confinement.
    /// # Errors
    /// Rejects unavailable backends and platforms without supervised standard children.
    pub fn new(jail: Jail, limit: usize) -> std::io::Result<Self> {
        Self::with_backend(jail, tinybox_jail::default_backend(), limit)
    }
    /// Use an explicitly selected provider; hosts apply policy to its enforcement facts.
    /// # Errors
    /// Rejects unavailable providers and unsupported native ownership platforms.
    pub fn with_backend(
        jail: Jail,
        backend: Arc<dyn JailBackend>,
        limit: usize,
    ) -> std::io::Result<Self> {
        let resource_plan = jail.resources.map(|resources| ResourceLimitPlan {
            cpu_millis: Some(u64::from(resources.cpu_millis)),
            memory_bytes: Some(resources.memory_bytes),
            pids_max: Some(u64::from(resources.pids_max)),
            disk_bytes: Some(resources.disk_bytes),
        });
        Self::with_backend_and_resource_plan(jail, backend, limit, resource_plan)
    }

    /// Use an explicitly selected provider and independently optional
    /// resource dimensions from the native request.
    /// # Errors
    /// Rejects unavailable providers and unsupported native ownership platforms.
    pub fn with_backend_and_resource_plan(
        jail: Jail,
        backend: Arc<dyn JailBackend>,
        limit: usize,
        resource_plan: Option<ResourceLimitPlan>,
    ) -> std::io::Result<Self> {
        if !cfg!(unix) || !backend.is_available() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "native jail supervision is unavailable",
            ));
        }
        let (finished, _) = watch::channel(0);
        Ok(Self {
            jail,
            backend,
            resource_plan,
            limit,
            state: Arc::new(State {
                active: AtomicUsize::new(0),
                failed: Mutex::new(BTreeMap::new()),
                cleanup: tokio::sync::Mutex::new(()),
                finished,
            }),
        })
    }
    /// Whether a failed cleanup still retains its native child.
    #[must_use]
    pub fn has_pending_cleanup(&self) -> bool {
        !self
            .state
            .failed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
    }
    /// Join supervisors and retry all retained native cleanup.
    /// # Errors
    /// Retains failed kill/reap ownership for another cleanup attempt.
    pub async fn drain_checked(&self) -> Result<()> {
        let mut finished = self.state.finished.subscribe();
        while self.state.active.load(Ordering::SeqCst) != 0 {
            if finished.changed().await.is_err() {
                break;
            }
        }
        self.retry_retained_cleanup().await
    }

    async fn retry_retained_cleanup(&self) -> Result<()> {
        let _guard = self.state.cleanup.lock().await;
        let slots: Vec<_> = self
            .state
            .failed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|(id, slot)| (*id, slot.clone()))
            .collect();
        let mut failure = None;
        for (group, slot) in slots {
            let mut child = slot.lock().await;
            if let Some(child) = child.as_mut()
                && let Err(error) = terminate(child, group).await
            {
                failure.get_or_insert(error);
                continue;
            }
            child.take();
            self.state
                .failed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&group);
        }
        if let Some(error) = failure {
            Err(error)
        } else {
            Ok(())
        }
    }
}
impl JailLocalHost {
    async fn collect(
        &self,
        request: &ExecRequest,
        observer: Option<Arc<dyn ExecutionObserver>>,
    ) -> Result<ExecOutput> {
        let invocation = JailInvocation::new(request.clone(), true, self.resource_plan);
        let command = invocation
            .command()
            .map_err(|error| Error::io("prepare native jail command", &error))?;
        self.collect_command(command, request.stdin.clone(), observer, Some(invocation))
            .await
    }

    /// Collect a prepared shell inside this host's explicit native jail.
    /// The caller clears and supplies the approved environment before invocation.
    /// # Errors
    /// Reports unavailable spawn, output bounds and retained kill/reap failures.
    pub async fn run_command_observed(
        &self,
        mut command: std::process::Command,
        payload: Option<Vec<u8>>,
        observer: Arc<dyn ExecutionObserver>,
    ) -> Result<ExecOutput> {
        command.stdin(if payload.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        });
        self.collect_command(command, payload, Some(observer), None)
            .await
    }

    async fn collect_command(
        &self,
        mut command: std::process::Command,
        payload: Option<Vec<u8>>,
        observer: Option<Arc<dyn ExecutionObserver>>,
        invocation: Option<JailInvocation>,
    ) -> Result<ExecOutput> {
        #[cfg(target_os = "linux")]
        let (memory_event_report, pids_event_report, cpu_event_report) =
            prepare_event_reports(&mut command, &self.jail, observer.is_some());
        prepare_supervised_command(&mut command);
        let jail = self.jail.clone();
        let backend = self.backend.clone();
        let state = self.state.clone();
        let limit = self.limit;
        let event_observer = observer.clone();
        let invocation = invocation.clone();
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|error| failure("supervise native jail", error.to_string()))?;
        let (cancel, mut cancelled) = oneshot::channel::<()>();
        state.active.fetch_add(1, Ordering::SeqCst);
        // The owned supervisor awaits startup even when its caller disappears.
        let task = runtime.spawn(async move {
            let _active = Active(state.clone());
            if !matches!(cancelled.try_recv(), Err(oneshot::error::TryRecvError::Empty)) {
                return Err(failure("start native jail", "execution cancelled".into()));
            }
            let child = tokio::task::spawn_blocking(move || {
                spawn_owned(backend.as_ref(), &jail, invocation.as_ref(), command)
            })
            .await
            .map_err(|error| failure("start native jail", error.to_string()))?
            .map_err(|error| Error::io("spawn native jail", &error))?;
            let group = i32::try_from(child.id().ok_or_else(|| {
                failure("identify jail child", "missing native process identifier".into())
            })?)
                .map_err(|error| failure("identify jail child", error.to_string()))?;
            let mut owned = RetainedOnDrop {
                child: Some(child),
                group,
                state: state.clone(),
            };
            let child = owned.child.as_mut().ok_or_else(|| {
                failure("own jail child", "missing native child".into())
            })?;
            let pipes = (|| {
                Ok::<_, Error>((
                    tokio::fs::File::from_std(pipe(child.take_stdout(), "stdout")?),
                    tokio::fs::File::from_std(pipe(child.take_stderr(), "stderr")?),
                    child
                        .take_stdin()
                        .map(tokio::fs::File::from_std),
                ))
            })();
            let result = match pipes {
                Ok((stdout, stderr, stdin)) => {
                    let budget = Arc::new(AtomicUsize::new(0));
                    let collection = async {
                        tokio::try_join!(
                            read_with_observer(stdout, budget.clone(), limit, OutputStream::Stdout, observer.clone()),
                            read_with_observer(stderr, budget, limit, OutputStream::Stderr, observer.clone()),
                            async {
                                if let (Some(mut stdin), Some(payload)) = (stdin, payload) {
                                    stdin
                                        .write_all(&payload)
                                        .await
                                        .map_err(|error| Error::io("write stdin", &error))?;
                                }
                                Ok(())
                            },
                            wait_child(child)
                        )
                    };
                    tokio::select! {
                        result = collection => result.map(|(stdout, stderr, (), status)| ExecOutput::new(status.code().unwrap_or(128), stdout, stderr)),
                        () = observer_cancelled(observer.as_deref()) => Err(failure("collect native jail", "execution cancelled".into())),
                        _ = cancelled => Err(failure("collect native jail", "execution cancelled".into())),
                    }
                },
                Err(error) => Err(error),
            };
            let cleanup = terminate(child, group).await;
            let child = owned.child.take().ok_or_else(|| {
                failure("release jail child", "missing native child".into())
            })?;
            retain_cleanup(&state, child, group, cleanup)?;
            result
        });
        let result = task
            .await
            .map_err(|error| failure("collect native jail", error.to_string()));
        drop(cancel);
        let output = result??;
        #[cfg(target_os = "linux")]
        report_event_terminations(
            &(memory_event_report, pids_event_report, cpu_event_report),
            event_observer.as_ref(),
        );
        Ok(output)
    }
}

fn prepare_supervised_command(command: &mut std::process::Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
}

#[async_trait]
impl Host for JailLocalHost {
    fn name(&self) -> &'static str {
        crate::LOCAL
    }
    async fn run(&self, request: &ExecRequest) -> Result<ExecOutput> {
        self.collect(request, None).await
    }

    async fn run_observed(
        &self,
        request: &ExecRequest,
        observer: Arc<dyn ExecutionObserver>,
    ) -> Result<ExecOutput> {
        self.collect(request, Some(observer)).await
    }

    fn has_pending_observed_cleanup(&self) -> bool {
        self.has_pending_cleanup()
    }

    async fn retry_observed_cleanup(&self) -> Result<()> {
        self.retry_retained_cleanup().await
    }
}
fn retain_cleanup(state: &State, child: OwnedChild, group: i32, outcome: Result<()>) -> Result<()> {
    if outcome.is_err() {
        state
            .failed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(group, Arc::new(tokio::sync::Mutex::new(Some(child))));
    }
    outcome
}

async fn wait_child(child: &mut OwnedChild) -> Result<tinybox_jail::ChildStatus> {
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| Error::io("wait native jail", &error))?
        {
            return Ok(status);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}
async fn terminate(child: &mut OwnedChild, group: i32) -> Result<()> {
    #[cfg(not(unix))]
    let _ = group;
    #[cfg(unix)]
    {
        use nix::{
            sys::signal::{Signal, killpg},
            unistd::Pid,
        };
        if child
            .try_wait()
            .map_err(|error| Error::io("inspect jail child", &error))?
            .is_none()
            || super::process::group_alive(group).await?
        {
            kill_jail_group(
                group,
                |group| killpg(Pid::from_raw(group), Signal::SIGKILL),
                super::process::group_alive,
            )
            .await?;
        }
    }
    let completion = async {
        child
            .terminate()
            .map_err(|error| Error::io("kill jail child", &error))?;
        wait_child(child).await?;
        #[cfg(unix)]
        while super::process::group_alive(group).await? {
            tokio::task::yield_now().await;
        }
        Ok(())
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), completion)
        .await
        .map_err(|_| failure("drain native jail", "cleanup deadline exceeded".into()))?
}
fn failure(operation: &'static str, message: String) -> Error {
    Error::Backend {
        sandbox: "jail".into(),
        operation,
        message,
    }
}

#[cfg(unix)]
async fn kill_jail_group<F>(
    group: i32,
    kill: impl FnOnce(i32) -> std::result::Result<(), nix::errno::Errno>,
    alive: impl FnOnce(i32) -> F,
) -> Result<()>
where
    F: std::future::Future<Output = Result<bool>>,
{
    match kill(group) {
        // Darwin can deny signalling a group that exited between inspection
        // and SIGKILL. Confirm it has no live members before acknowledging it.
        Err(nix::errno::Errno::EPERM) if !alive(group).await? => Ok(()),
        Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(error) => Err(failure("kill jail group", error.to_string())),
    }
}

#[cfg(all(test, unix))]
#[path = "jailed_tests.rs"]
mod tests;
