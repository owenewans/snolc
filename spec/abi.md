# native module ABI

SNOLC modules are target-specific dynamic libraries. Linux uses `.so`, macOS
uses `.dylib`, and Windows uses `.dll`. A module exports:

```c
const SnolModuleDescriptor *snolc_module_entry(void);
```

`include/snolc.h` is the normative C layout. `snolc-abi` contains the matching
Rust `repr(C)` definitions. CI compares sizes and offsets with a C compiler.

## descriptor

The descriptor prefix contains `struct_size`, `wire_version`, `class_mask`, and
zero `reserved`. Core checks this prefix before reading later members or calling
`create`. Descriptor memory stays valid until unload.

Class tables cover adapter, protection, carrier, and policy. Common operations
are `describe`, `validate_config`, `create`, `poll`, `control`, `shutdown`, and
`destroy`. A missing optional operation or unknown control method returns
`STATUS_UNSUPPORTED`. It does not return an empty success response.

Module options arrive as bounded TOML bytes with an absolute base directory.
The module rejects unknown, missing, or incompatible fields during validation.

## values and memory

The ABI passes fixed-width integers, tagged `repr(C)` records, handles, and
borrowed pointer-length pairs. It never passes Rust `Vec`, `String`, futures,
trait objects, or core socket references.

Borrowed memory lives for one call. A module copies data that it keeps. The
allocator that creates memory releases it. Handles encode an index and
generation in `u64`; each call checks owner, type, generation, and lifetime.

Exported functions catch Rust unwind and translate it to instance error. The
release profile uses unwind. Native memory faults, abort, and OOM remain process
failures because modules share the process.

## byte I/O

Byte I/O provides `read`, `write`, `flush`, `shutdown_write`, and `close`.
Results are Progress, Pending, EOF, or Error. A nonempty write cannot report
Progress(0). Pending registers a wake before returning. EOF in one direction
does not close the other direction.

## datagram I/O

`recv_datagram` and `send_datagram` preserve one message. If the receive buffer
is short, the operation returns the needed length without removing the message.
A zero-length datagram is valid and differs from EOF.

SDK `Pump` handles partial writes, bounded pending payload, flush, and
half-close. It reports accepted byte counts to policy and contains no quota or
rate algorithm.

## wake and threading

`WakeHandle` contains context plus wake, retain, and release callbacks. A worker
thread may call wake. It may not call a module or host I/O object. Host timers
and system I/O register through the Host API.

Core does not enter one mutable instance recursively. It queues callbacks that
would reenter that instance. Calls through distinct acyclic I/O wrappers remain
valid.

## lifetime and compatibility

Core retains a loaded library until engine shutdown, module destruction, and
release of module-owned handles and callbacks. A stale handle returns an error.
An incompatible `wire_version`, short descriptor, nonzero reserved field, or
unsupported class fails before instance creation.

Changes to shared wire, ABI layout, or configuration contract require a new
`wire_version`. Package version identifies a release and does not negotiate
compatibility.
