# TinyBox contract 2.4

Contract 2.4 adds one broadcast signal to `ai.tinyhumans.tinybox.Box`:

| Signal | Body |
| --- | --- |
| `ProcessEvent` | `ProcessEvent { process: ProcessRef, event: SandboxEvent }` |

The module emits `Started` after the first successful `StartExec`,
`StartNativeShellExec`, or `StartNativeShellExecWithResources` for a process
reservation. It emits `Exited { status: Some(code) }` after the execution
supervisor observes a terminal native exit status. A native shell that reaches
its configured runtime deadline emits `LimitHit { limit: Timeout }` followed
by `Exited { status: None }`. Replaying the same start request does not
produce duplicate process events.

On Linux, when a native shell has a cgroup v2 memory limit and the private
runtime-directory handoff is available, the trusted launcher samples the new
scope's `memory.events` before teardown. A nonzero `oom_kill` counter emits
`LimitHit { limit: Memory }` before terminal `Exited`. This event is not
inferred from SIGKILL or an exit code. Other platforms and executions without
that cgroup-v2 evidence do not claim memory-limit observations.

Signals are observational and best-effort. Their bodies identify the caller's
resource and process reservations so a host can correlate them with requests.
The timeout event reports the supervisor's own configured deadline. This
contract does not claim that the module reports access denials, CPU,
process-count or disk-limit trips, failed starts, or cancelled executions.
