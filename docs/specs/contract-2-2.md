# Contract 2.2: resource-aware native shell execution

Contract 2.2 adds `StartNativeShellExecWithResources`, which accepts the
existing `ShellExecRequest` and a separate `NativeJailResourceRequest`.

The method requires the existing shell request to include its native jail
configuration. TinyBox keeps shell selection, safe environment setup, private
scratch, timeout handling, cancellation, output collection, and cleanup inside
the module. The additional request carries only the explicit optional CPU,
memory, process-count, and disk limits; unsupported requested limits continue
to fail closed in the selected backend.

Contract 2.1's `StartJailedExecWithResources` remains available for callers
that construct a generic process request. The original `StartNativeShellExec`
and `StartJailedExec` members remain unchanged for legacy request shapes.
