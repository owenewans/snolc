<div align="center">

# snolc

modular userspace network engine for linux and android.

<a href="https://count.owenewans.org/owenewans/snolc?theme=moebooru-h&notitle"><img src="https://count.owenewans.org/owenewans/snolc?theme=moebooru-h&notitle" alt="repository views"></a>

`rust` `proxy` `networking`

</div>

## install

The installer places the `snolc` binary in `$HOME/.local/bin`.

```sh
curl -fsSL https://raw.githubusercontent.com/owenewans/snolc/v0.0.2/install.sh | sh -s -- --binary
```

Compile the same tagged source instead:

```sh
curl -fsSL https://raw.githubusercontent.com/owenewans/snolc/v0.0.2/install.sh | sh -s -- --source
```

Pass `--prefix /usr/local` to select another installation root. Binary mode
checks the signed release checksum before extraction. Source mode requires
Rust 1.98.1. Both modes install one executable and leave modules untouched.

## components

SNOLC 0.0.2 uses four repositories:

- [`snolc`](https://github.com/owenewans/snolc): engine, C ABI, Rust SDK and CLI
- [`snolc-modules`](https://github.com/owenewans/snolc-modules): official adapters, protection, carriers and policies
- [`snolpkg`](https://github.com/owenewans/snolpkg): signed module installer
- [`snolcNG`](https://github.com/owenewans/snolcNG): desktop and Android client

## network path

User traffic takes one route in each direction:

```text
adapter -> smoltcp -> policy -> yamux -> protection -> carrier
```

The engine owns scheduling, stack bridging, multiplexing, module loading and
events. Policy modules decide admission, accounting, rates and filtering. The
public compatibility generation remains `wire_version = 1`.

## usage

```sh
snolc validate snolc.toml
snolc run snolc.toml
snolc control /run/snolc/snolc.sock policy-main request.toml
```

SNOLC loads native modules into its process. Install modules only from a source
you trust.

## documentation

- [repository guide](llm.md)
- [architecture](spec/architecture.md)
- [stack bridge](spec/stack-bridge.md)
- [wire version 1](spec/wire.md)
- [configuration](spec/config.md)
- [C ABI](spec/abi.md)
- [platforms](spec/platforms.md)
- [acceptance](spec/acceptance.md)
- [operations](spec/operations.md)
- [benchmarks](spec/benchmarks.md)
- [comparison plan](spec/xray-and-sing-vs-snolc.md)

## license

[Unlicense](LICENSE)
