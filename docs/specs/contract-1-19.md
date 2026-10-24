# Contract 1.19: network allowlists and sandbox events

Part of tinyhumansai/openhuman#7328 (tinybox#27).

Contract 1.19 is a vocabulary bump. It appends no bus member, so `METHODS` is
unchanged. A host that sends the new vocabulary requires a module minor of at
least 19, which `tinybox_bus::is_compatible` already enforces.

## Added

- `NetworkPolicy::Allowlist(EgressAllowlist { hosts, ports })`. The enum is no
  longer `Copy`.
- `SandboxEvent { Started, Denied { kind, target }, LimitHit { limit },
  Exited { status } }`, with `DenialKind` and `LimitKind`. Events are purely
  observational; the sandbox never decides what is allowed.

## Allowlist semantics

- Names are resolved outside the box, once, and pinned. The box gets those
  addresses (or a proxy that connects only to them) and no resolver of its own,
  so a later DNS answer cannot widen the list.
- Cloud metadata endpoints (`169.254.169.254`, `169.254.170.2`,
  `100.100.100.200`, `fd00:ec2::254`, `metadata.google.internal`) are refused
  when the spec is validated, including DNS case and a terminal root dot
  (`Metadata.Google.Internal.`). Legacy numeric IPv4 spellings for these
  endpoints are refused too, including `0251.0376.0251.0376`, `0xa9fea9fe`,
  `0xa9feaa02`, and `0x646464c8`. A backend must also block a metadata address
  when an allowlisted hostname resolves to one.
- Explicit loopback destinations are refused during validation, including
  IPv4/IPv6 literals, IPv4-mapped loopback, scoped IPv6 loopback such as
  `::1%1`, `localhost` names, and legacy numeric IPv4 forms accepted by common
  resolvers (`127.1`, `2130706433`, `0x7f000001`, `0177.0.0.1`). Enforcing
  backends must also reject resolved loopback addresses.
- A backend that cannot enforce the list refuses the box with
  `ConstraintNotEnforced { constraint: Network, enforcement: Unsupported }`.
  It never widens the list to `Egress`. A backend that enforces only part of it
  (for example a Seatbelt profile without host matching, or a proxy fallback)
  must report the network constraint `BestEffort`, never `Enforced`.
- `NetworkPolicy::Open` shares the host network and is the highest-risk setting
  (`NetworkPolicy::is_highest_risk`).

## Status per backend

The native Docker Linux controller enforces pinned allowlist addresses with
firewall rules and container host mappings. `passthrough`, native jail,
`namespace`, and `microvm` refuse allowlists until they have an enforcing path.
Other OS Docker hosts remain unsupported unless their controller reports a
verified enforcement capability.

## Deprecated

`tinybox_core::shell::{classify, scan, env_guard}` is command policy and now
lives in `tinysecurity-policy`. It is deprecated in 0.1.34 and removed in the
release after. `shell::analysis` (structure facts for the `AnalyzeShell` and
`AnalyzeCommand` members) remains.
