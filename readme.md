<div align="center">

# snolc

modular userspace network stack for linux and android.

<a href="https://count.owenewans.org/owenewans/snolc?theme=moebooru-h&notitle"><img src="https://count.owenewans.org/owenewans/snolc?theme=moebooru-h&notitle" alt="repository views"></a>

`rust` `proxy` `networking`

</div>

## features

- one packet path through smoltcp, yamux, protection and carrier layers
- native adapter, protection, carrier and policy modules behind a C ABI
- strict TOML configuration with explicit resource limits
- library engine shared by the CLI and snolcNG
- TCP and UDP over IPv4 and IPv6

## install

snolc 0.0.1 is under development. Build the development branch with Rust
1.98.1:

```sh
git clone --branch dev https://github.com/owenewans/snolc
cd snolc
cargo build --locked
```

## usage

The release will provide a library-first engine and thin command line client:

```sh
snolc validate snolc.toml
snolc run snolc.toml
```

Native modules run in the process and must come from a trusted source. The
project will publish 0.0.1 after the acceptance suite and Tier 1 tests pass.

## architecture

User traffic follows one route in each direction:

```text
adapter -> smoltcp -> yamux -> protection -> carrier
```

Core owns scheduling, stack bridging, multiplexing, module loading and events.
Policy modules own admission, accounting, rate limits and filtering. The public
compatibility generation is `wire_version = 1`.
