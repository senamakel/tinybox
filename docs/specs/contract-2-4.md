# TinyBox contract 2.4

Contract 2.4 adds one broadcast signal to `ai.tinyhumans.tinybox.Box`:

| Signal | Body |
| --- | --- |
| `ProcessEvent` | `ProcessEvent { process: ProcessRef, event: SandboxEvent }` |

The module emits `Started` after the first successful `StartExec` for a
process reservation. It emits `Exited { status: Some(code) }` after the
execution supervisor observes a terminal native exit status. Replaying the
same `StartExec` request does not produce duplicate lifecycle events.

Signals are observational and best-effort. Their bodies identify the caller's
resource and process reservations so a host can correlate them with requests.
This contract does not claim that the module reports access denials, resource
limit trips, failed starts, or cancelled executions. Those events require
backend evidence and are outside this increment.
