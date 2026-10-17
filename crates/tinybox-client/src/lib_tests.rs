//! Behavioral test draft for the TinyBox typed host client.
//!
//! Intentionally unwired until RED/implementation is authorized. Proposed API:
//! `TinyBoxClient::new(module_id, ModuleClient).await` probes capabilities
//! once; typed operations then call the TinyBox module through that client.
//! These tests port behaviors from OpenHuman's `modules/tinybox_tests.rs`.

use super::*;

// Test fixture: an in-memory TinyBus service implementing `tinybox_bus::METHODS`
// records each `(member, positional_args)` and returns typed fixture replies.
// The fixture should allow selecting the advertised contract version and
// recording ordinary versus confidential calls.

#[tokio::test]
async fn construction_checks_compatibility_once_before_exposing_operations() {
    // Accept current and newer minor versions. Reject older minor versions and
    // different majors before any operation is called.
    // Assert exactly one Capabilities call during construction and no repeated
    // capability probe for later typed calls.
}

#[tokio::test]
async fn typed_operations_use_canonical_names_and_positional_arguments() {
    // Exercise analyze_command, select_shell, resolve_local_grants,
    // validate_docker_policy, file transfer, process output, and both Docker
    // run variants. Assert the exact named member, tuple JSON array, and reply
    // type for each operation, including multi-argument calls.
}

#[tokio::test]
async fn confidential_call_refusal_is_returned_without_ordinary_retry() {
    // Exercise start_exec and RunDocker against a fixture that refuses the
    // confidential path. Assert the call is attempted once and command/path
    // values are absent from any client-generated error text.
}

#[tokio::test]
async fn docker_control_deadline_is_bounded_then_extended_by_grace() {
    // Exercise DockerStatus and CleanupDocker with normal, minimum, and
    // oversized timeout_ms values. Assert the client clamps to
    // tinybox_bus::MAX_DOCKER_CONTROL_TIMEOUT_MS before adding grace and sends
    // the original typed request to the correct member.
}

#[test]
fn every_wrapper_uses_a_member_from_the_canonical_contract() {
    // Keep a complete wrapper-to-tinybox_bus::names mapping and assert every
    // member is present in tinybox_bus::METHODS; names must not be duplicated
    // as string literals or derived from positional METHODS indexes.
}
