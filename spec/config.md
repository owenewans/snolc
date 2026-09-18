# configuration

snolc uses strict TOML. Runtime rejects unknown fields, duplicate keys, missing
required fields, invalid units, overflow, duplicate instance IDs, cyclic
references, incompatible limits, and unsupported module roles before opening a
listener.

## main file

The main file contains:

- `wire_version`
- package and state paths
- engine command, event, session, flow, memory, I/O, and timeout limits
- stack address family, MTU, socket, packet, UDP, and reassembly limits
- yamux stream, receive window, split size, and close behavior
- logging mode and its complete selected branch
- control socket mode and limits
- tunnel role and module instance references

`config/templates/snolc-server-low-memory.toml` and
`config/templates/snolc-client-low-memory.toml` contain every field selected by
their modes. The runtime parser validates both templates in tests.

`max_streams_per_session` includes one POLICY stream. The low-memory value 17
permits 16 user flows. Validation checks the yamux receive-window minimum for
all streams and includes every configured session in the managed-memory budget.

## module files

A module file contains `wire_version`, unique `instance`, immutable package
identity, role, and strict options. Core parses the common fields and sends the
options table to that module's `validate_config`. Core does not interpret
policy, SSH, Noise, DNS, or adapter fields.

Relative paths resolve against the file that contains them. SDK supplies the
module with that absolute base directory. Runtime does not search the current
directory, home directory, SSH defaults, or package latest version.

An inactive branch uses `mode = "off"`. It does not require fake empty paths or
zero limits. A selected branch requires every field in that branch.

## environment and secrets

Environment input requires an explicit `source = "env"` and variable name.
Missing variables fail startup. TOML input requires `source = "toml"` and its
value. There is no environment-over-TOML precedence rule.

Config dumps redact credentials, private keys, bearer tokens, and secret URI
fields. A publication manifest contains no deployment secret.

## templates

Official module templates live under `config/templates/modules` in the
`snolc-modules` repository. `snolpkg template` copies a signed package template
with `create_new`; it does not
overwrite a user file. Generated files remain normal complete TOML files. A run
does not apply a hidden preset after generation.

Server policy-local uses `snolc-modules/config/templates/modules/policy.toml`. It states
Immediate durability through the module contract and writes cache, database,
queue, quota block, sniff, status, and checkpoint limits.

## validation commands

```sh
cargo run --locked -p snolc-cli -- validate config/templates/snolc-server-low-memory.toml
cargo run --locked -p snolc-cli -- validate config/templates/snolc-client-low-memory.toml
```

These main templates refer to module files and key files. Copy the complete
template tree before validation and create the required keys. A missing file is
an error; the validator does not invent a module or key.

## logging sizes

File limits accept decimal values and suffixes `b`, `kb`, `mb`, `gb`, `kib`,
`mib`, and `gib`. Decimal suffixes use powers of 1000. Binary suffixes use
powers of 1024. Parsing uses checked integer arithmetic and rounds a fractional
result down to bytes. Negative, non-finite, overflow, zero, and a
`max_record_bytes` larger than the file limit fail validation.

## errors

Validation errors include a file and field context. Module errors include the
instance ID. Runtime never falls back to another mode, package, address family,
DNS source, logger, protection, policy, or carrier after a configuration error.
