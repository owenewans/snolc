# stack bridge

`StackBridge` makes smoltcp mandatory for packet and stream adapters. It owns
the interface, socket set, virtual tuple pool, packet queues, reassembly slots,
and generation handles.

## stream port

SOCKS5, HTTP CONNECT, and direct adapters use `StreamPort`. Each TCP flow gets
two smoltcp TCP sockets in an isolated loopback interface. The adapter writes
one socket. The stack emits packets into a bounded in-memory device. The peer
socket receives those packets and exposes payload to policy. Return traffic
uses the same path in reverse.

smoltcp creates SYN, ACK, sequence numbers, windows, retransmission, FIN, and
reset behavior. SNOLC does not implement a second TCP state machine.

The bridge allocates virtual endpoints from ports 1024 through 65535 on
`127.0.0.1` or `::1`. These addresses exist inside the smoltcp interface. They
do not select a remote destination. `FlowMetadata` and the wire OPEN retain the
real destination. A tuple returns to the pool after both sockets leave their
network state and the flow slot generation changes.

UDP StreamPort uses a pair of smoltcp UDP sockets per normalized destination.
The bridge preserves zero-length datagrams and message boundaries. A pending
datagram owns one bounded payload buffer.

## packet port

The Linux and Android TUN adapter sends IP packets to `PacketPort`. The bridge
parses IPv4 and IPv6 with smoltcp, then binds TCP and UDP sockets by full tuple.
Connections with the same destination port retain separate source tuples.

The interface enables AnyIP and installs configured userspace routes through
its own addresses. A new TCP SYN allocates one bounded listening socket for the
destination. A repeated SYN for an existing tuple selects the existing socket.
System routes remain an explicit adapter or platform operation.

PacketPort handles TCP, UDP, and ICMP errors needed for local stack and MTU
behavior. Wire version 1 does not carry arbitrary GRE, ESP, or raw IP payload.

## fragmentation

The base TUN MTU is 1280. IPv4 and IPv6 reassembly uses four fixed slots and
65,536-byte storage per slot. IPv6 extension parsing rejects malformed chains,
overlaps, and jumbograms. A slot expires after `reassembly_timeout_ms`.
Exhaustion drops the new fragmented datagram without growing memory.

UDP payload length ranges from 0 through 65,507 bytes. Each UDP socket allocates
the configured 128 KiB RX and TX buffers plus eight metadata slots in the
low-memory profile. TCP sockets allocate 16 KiB in each direction. Allocation
counts against `max_managed_bytes` when a flow starts.

## scheduling

One bridge tick calls `poll_ingress_single` up to
`max_ingress_packets_per_tick`. It then performs bounded egress and maintenance
work and yields. Policy can stop payload transfer while smoltcp still handles
ACKs and timers.

The in-memory device uses byte and packet limits. A full queue applies
backpressure. It does not drop TCP payload and continue a parallel path. The
acceptance test stalls the device and expects SOCKS5 and HTTP payload progress
to stop.

## errors

- port pool exhaustion returns a flow resource error;
- managed memory exhaustion rejects the new flow;
- malformed packets are dropped and counted;
- invalid or overlapping fragments are dropped;
- unsupported raw protocols get no forwarding flow;
- a stale flow callback fails its generation check;
- adapter shutdown closes its side without forcing peer EOF in the other
  direction.

Packet fixtures cover IPv4, IPv6, equal destination ports, tuple reuse,
fragment completion, fragment timeout, overlap, UDP sizes, and queue stall.
