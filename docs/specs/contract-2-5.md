# TinyBox contract 2.5

Contract 2.5 adds optional `network_allowlist` to `NativeJailConfig`. The
field carries the requested hosts and TCP ports alongside the legacy
`allow_net` switch, so a host-native request cannot lose allowlist intent at
serialization boundaries.

Hosts must check `supports_native_jail_network_allowlist` against the module's
advertised contract version before sending the field. Older modules may ignore
unknown serde fields. Current native jail backends do not enforce host and
port filtering; they return the stable `ConstraintNotEnforced` error before
backend admission whenever `network_allowlist` is present. Linux Docker's
resolver-pinned allowlist path is unchanged.

This is compatibility and refusal groundwork, not native macOS or Windows
allowlist enforcement. Those platform acceptance rows remain open.
