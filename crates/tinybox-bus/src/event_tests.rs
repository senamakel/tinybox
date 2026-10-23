use super::*;
use crate::{CONTRACT_VERSION, NetworkPolicy, ResourceId, SIGNALS, names};

#[test]
fn events_keep_their_wire_labels() -> Result<(), serde_json::Error> {
    let denied = SandboxEvent::Denied {
        kind: DenialKind::Network,
        target: Some("169.254.169.254:80".into()),
    };
    assert_eq!(
        serde_json::to_value(&denied)?,
        serde_json::json!({"event":"denied","kind":"network","target":"169.254.169.254:80"})
    );
    assert_eq!(
        serde_json::to_value(SandboxEvent::LimitHit {
            limit: LimitKind::Pids
        })?,
        serde_json::json!({"event":"limit_hit","limit":"pids"})
    );
    assert_eq!(
        serde_json::to_value(SandboxEvent::Started)?,
        serde_json::json!({"event":"started"})
    );
    let exited: SandboxEvent = serde_json::from_value(serde_json::json!({"event":"exited"}))?;
    assert_eq!(exited, SandboxEvent::Exited { status: None });
    Ok(())
}

#[test]
fn process_event_signal_has_correlated_process_and_event_fields() -> Result<(), serde_json::Error> {
    let process_event = ProcessEvent {
        process: ProcessRef {
            resource: ResourceId("resource-1".into()),
            process: ResourceId("process-1".into()),
        },
        event: SandboxEvent::Exited { status: Some(7) },
    };
    let snapshot = serde_json::json!({
        "process": {"resource":"resource-1", "process":"process-1"},
        "event": {"event":"exited", "status":7}
    });
    assert_eq!(serde_json::to_value(&process_event)?, snapshot);
    assert_eq!(
        serde_json::from_value::<ProcessEvent>(snapshot)?,
        process_event
    );
    assert_eq!(names::PROCESS_EVENT, "ProcessEvent");
    assert_eq!(SIGNALS, &[names::PROCESS_EVENT]);
    assert_eq!(CONTRACT_VERSION, (2, 5));
    Ok(())
}

#[test]
fn an_allowlist_policy_round_trips_and_old_policies_still_parse() -> Result<(), serde_json::Error> {
    let policy = NetworkPolicy::Allowlist(EgressAllowlist {
        hosts: vec!["example.com".into()],
        ports: vec![443],
    });
    let value = serde_json::to_value(&policy)?;
    assert_eq!(
        value,
        serde_json::json!({"Allowlist":{"hosts":["example.com"],"ports":[443]}})
    );
    assert_eq!(serde_json::from_value::<NetworkPolicy>(value)?, policy);
    assert_eq!(
        serde_json::from_value::<NetworkPolicy>(serde_json::json!("Egress"))?,
        NetworkPolicy::Egress
    );
    Ok(())
}
