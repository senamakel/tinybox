# tinybox TinyBus Module

This package contains the native `tinybox` module for TinyBus module ABI v1.
Install only the archive matching the host operating system and architecture.

The module claims `ai.tinyhumans.tinybox.Box` and serves the object at
`/ai/tinyhumans/tinybox/Box`. `Describe` remains the original zero-argument
discovery method; the current bus contract is version 2.5 and also exposes
`Capabilities`, typed `PlanCheck`, resource and process operations, and the
`ProcessEvent` signal. `Capabilities` reports this build's contract version and
available backends. `PlanCheck` reports each selected backend's declared
enforcement without starting work. `ProcessEvent` carries process-correlated
start and exit lifecycle events, plus timeout, denial, and resource
observations only where the backend has evidence. See the
[module API](crates/tinybox-module/src/tinybus_module/README.md) and
[contracts 2.4](docs/specs/contract-2-4.md) and
[2.5](docs/specs/contract-2-5.md) for the wire details.

Contract 2.5 carries optional host-and-port allowlist intent on native jail
requests. Current native jail backends refuse that field with a typed
unsupported-constraint error; Linux Docker has the enforcing allowlist path.
The module does not silently widen unsupported allowlists to general egress.

The archive contains one `.so`, `.dylib`, or `.dll` plus `modules.toml`. Keep
those files together when copying them into a TinyBus module directory. The
allowlist binds the native library filename to its SHA-256 digest so TinyBus can
reject a missing, renamed, or modified artifact before initialization.

The GitHub release also publishes `checksum.toml` as a separate asset. TinyBus
checks that manifest before downloading and extracting the selected platform
archive. Install directly from a tagged release with:

```sh
tinybus modules load-github \
  https://github.com/tinyhumansai/tinybox/releases/tag/v0.1.5 \
  tinybox-0.1.5-ubuntu-24.04-x86_64.tar.gz \
  <archive-sha256>
```

## Trust

TinyBus modules are trusted in-process code with the host's full address-space
privileges. Install release artifacts only from a trusted source, and restart
the host after replacing a loaded module.

That applies to this module as much as any other. tinybox exists to give a host
somewhere to put code it does *not* trust — the boxes it creates — and nothing
about installing it confines the module itself.
