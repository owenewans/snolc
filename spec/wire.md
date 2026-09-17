# wire version 1

All integer fields use big-endian encoding. Parsers read fields, not Rust or C
struct memory. They reject lengths before allocation and reject trailing bytes.

## stream header

Each yamux stream starts with 12 bytes:

```text
offset  size  value
0       4     53 4e 4f 4c, ASCII SNOL
4       4     wire_version, value 1
8       1     kind: 1 POLICY, 2 TCP, 3 UDP
9       3     zero
```

The header stays inside protection and yamux. It never appears as a clear
carrier prefix. The TCP example is:

```text
53 4e 4f 4c 00 00 00 01 02 00 00 00
```

Unknown magic, version, kind, or nonzero reserved bytes produce a protocol
error and reset the stream.

## policy stream

The initiating peer opens one POLICY stream before user flows. It appends:

```text
u16 family_length
family_length bytes of ASCII policy family
```

The family length is 1 through 64. The server answers with the same POLICY
header and family. Core then transfers ownership to policy. A second POLICY
stream, a family mismatch, or a user OPEN before policy admission closes the
session.

policy-local frames its private messages as `u32 length` plus UTF-8 TOML. The
maximum frame is 16,384 bytes. Core does not parse private AUTH, USER, QUOTA, or
status fields.

## flow open

TCP and UDP append `u16 body_length`, then a body no larger than 4,096 bytes:

```text
u8  address_type
... address
u16 port
u16 metadata_length
... opaque metadata
```

Address type 1 carries four IPv4 bytes. Type 2 carries sixteen IPv6 bytes. Type
3 carries `u16 length` and 1 through 253 ASCII A-label bytes. IPv6 zones do not
cross the wire. Port zero is invalid. Metadata is at most 1,024 bytes.

The OPEN response is:

```text
u8  status
u16 reason_length
... UTF-8 reason
```

Reason length is at most 256 bytes. Status values are:

| value | meaning |
| --- | --- |
| 0 | ok |
| 1 | denied |
| 2 | connect failed |
| 3 | unsupported |
| 4 | resource limit |
| 5 | protocol error |
| 6 | internal error |

The adapter reports SOCKS5 or HTTP success after status 0. Reasons contain no
secret or stack trace.

## payload

TCP carries bytes without record headers. yamux FIN represents
`shutdown_write`; reset represents an abnormal flow failure. One direction can
reach EOF while the other remains writable.

UDP carries repeated `u16 payload_length` plus payload records. Length ranges
from 0 through 65,507. The destination stays fixed to the OPEN destination.
The receiver waits for a complete record and never exposes a partial datagram.

## session behavior

One carrier connection contains one protection session and one yamux session.
Wire version 1 lets the client initiate user flows. Carrier loss closes all
flows in that session. A reconnect creates a new session and does not migrate
TCP state.

Implementations bound unfinished OPEN count and read time by engine settings.
Tests feed every split point, joined frames, short fields, oversized fields,
unknown tags, extra bytes, and zero-length UDP. The parser returns an error and
does not panic.
