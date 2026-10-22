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

Signals are observational and best-effort. Their bodies identify the caller's
resource and process reservations so a host can correlate them with requests.
The timeout event reports the supervisor's own configured deadline. This
contract does not claim that the module reports access denials, CPU, memory,
process-count or disk-limit trips, failed starts, or cancelled executions.
