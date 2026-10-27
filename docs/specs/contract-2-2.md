# TinyBox contract 2.2

Contract 2.2 adds one broadcast signal to `ai.tinyhumans.tinybox.Box`:

| Signal | Body |
| --- | --- |
| `ProcessEvent` | `ProcessEvent { process: ProcessRef, event: SandboxEvent }` |

The module emits `Started` after the first successful module-owned start for a
process reservation, then emits `Exited { status: Some(code) }` after its
supervisor observes the terminal exit status. A replayed start does not
duplicate lifecycle events. For executions terminated by their wall-clock
timeout, the module emits `LimitHit { limit: Timeout }` before
`Exited { status: None }`.

Signals are observational and best-effort. Their bodies include the caller's
resource and process reservations for correlation. This contract does not
forward access denials or other resource-limit observations.
