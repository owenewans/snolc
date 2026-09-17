use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::pin::Pin;
use std::rc::{Rc, Weak};
use std::task::{Context, Poll, Waker};
use std::time::Instant as StdInstant;

use futures::io::{AsyncRead, AsyncWrite};
use smoltcp::iface::{
    Config as InterfaceConfig, Interface, PollIngressSingleResult, SocketHandle, SocketSet,
};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpProtocol, Ipv4Address, Ipv4Packet,
    Ipv6Address, Ipv6Packet, TcpPacket, UdpPacket,
};
use snolc_sdk::{DatagramIo, DatagramRecv, HandleTable, TypedHandle};
use thiserror::Error;

use crate::config::StackConfig;
use crate::wire::Destination;

const FIRST_DYNAMIC_PORT: u16 = 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowMetadata {
    pub destination: Destination,
    pub port: u16,
    pub opaque: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TcpFlowHandle(u64);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UdpFlowHandle(u64);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct PacketTcpTuple {
    source: IpEndpoint,
    destination: IpEndpoint,
}

struct TcpFlow {
    adapter: SocketHandle,
    policy: SocketHandle,
    adapter_port: u16,
    policy_port: u16,
    metadata: FlowMetadata,
    managed_bytes: usize,
}

struct UdpFlow {
    adapter: SocketHandle,
    policy: SocketHandle,
    adapter_port: u16,
    policy_port: u16,
    metadata: FlowMetadata,
    managed_bytes: usize,
}

struct PacketTcpFlow {
    socket: SocketHandle,
    tuple: PacketTcpTuple,
    metadata: FlowMetadata,
    managed_bytes: usize,
    queued: bool,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct PacketUdpTuple {
    source: IpEndpoint,
    destination: IpEndpoint,
}

struct PacketUdpGroup {
    socket: SocketHandle,
    managed_bytes: usize,
    flows: usize,
}

struct PacketUdpFlow {
    tuple: PacketUdpTuple,
    metadata: FlowMetadata,
    incoming: Option<Vec<u8>>,
}

pub struct StackBridge {
    interface: Interface,
    device: BoundedDevice,
    sockets: SocketSet<'static>,
    tcp_flows: HandleTable<TcpFlow>,
    udp_flows: HandleTable<UdpFlow>,
    packet_tcp_flows: HandleTable<PacketTcpFlow>,
    packet_tcp_by_tuple: HashMap<PacketTcpTuple, u64>,
    pending_packet_tcp: VecDeque<u64>,
    packet_udp_groups: HashMap<IpEndpoint, PacketUdpGroup>,
    packet_udp_flows: HandleTable<PacketUdpFlow>,
    packet_udp_by_tuple: HashMap<PacketUdpTuple, u64>,
    pending_packet_udp: VecDeque<u64>,
    ports: PortPool,
    config: StackConfig,
    managed_bytes: usize,
    max_managed_bytes: usize,
    max_ingress_packets_per_tick: usize,
    started: StdInstant,
}

pub struct SharedStackBridge {
    inner: Rc<RefCell<StackBridge>>,
    wakes: RefCell<Vec<Weak<PortWake>>>,
}

pub struct TcpStreamPort {
    bridge: Weak<RefCell<StackBridge>>,
    lease: Rc<TcpFlowLease>,
    side: Side,
    wake: Rc<PortWake>,
    write_shutdown: bool,
}

pub struct UdpDatagramPort {
    bridge: Weak<RefCell<StackBridge>>,
    lease: Rc<UdpFlowLease>,
    side: Side,
    wake: Rc<PortWake>,
}

pub struct PacketPort {
    bridge: Weak<RefCell<StackBridge>>,
    wake: Rc<PortWake>,
    closed: bool,
}

pub struct PacketTcpPort {
    bridge: Weak<RefCell<StackBridge>>,
    lease: Rc<PacketTcpFlowLease>,
    wake: Rc<PortWake>,
    write_shutdown: bool,
}

pub struct PacketUdpPort {
    bridge: Weak<RefCell<StackBridge>>,
    lease: Rc<PacketUdpFlowLease>,
    wake: Rc<PortWake>,
}

struct TcpFlowLease {
    bridge: Weak<RefCell<StackBridge>>,
    handle: TcpFlowHandle,
}

struct UdpFlowLease {
    bridge: Weak<RefCell<StackBridge>>,
    handle: UdpFlowHandle,
}

struct PacketTcpFlowLease {
    bridge: Weak<RefCell<StackBridge>>,
    handle: u64,
}

struct PacketUdpFlowLease {
    bridge: Weak<RefCell<StackBridge>>,
    handle: u64,
}

#[derive(Default)]
struct PortWake {
    waker: RefCell<Option<Waker>>,
}

impl SharedStackBridge {
    pub fn new(
        config: StackConfig,
        max_flows: usize,
        max_managed_bytes: usize,
        max_ingress_packets_per_tick: usize,
    ) -> Result<Self, StackError> {
        Ok(Self {
            inner: Rc::new(RefCell::new(StackBridge::new(
                config,
                max_flows,
                max_managed_bytes,
                max_ingress_packets_per_tick,
            )?)),
            wakes: RefCell::new(Vec::new()),
        })
    }

    pub fn open_tcp(
        &self,
        metadata: FlowMetadata,
    ) -> Result<(TcpStreamPort, TcpStreamPort), StackError> {
        let handle = self.inner.borrow_mut().open_tcp(metadata)?;
        let lease = Rc::new(TcpFlowLease {
            bridge: Rc::downgrade(&self.inner),
            handle,
        });
        let adapter_wake = Rc::new(PortWake::default());
        let policy_wake = Rc::new(PortWake::default());
        self.wakes
            .borrow_mut()
            .extend([Rc::downgrade(&adapter_wake), Rc::downgrade(&policy_wake)]);
        Ok((
            TcpStreamPort {
                bridge: Rc::downgrade(&self.inner),
                lease: Rc::clone(&lease),
                side: Side::Adapter,
                wake: adapter_wake,
                write_shutdown: false,
            },
            TcpStreamPort {
                bridge: Rc::downgrade(&self.inner),
                lease,
                side: Side::Policy,
                wake: policy_wake,
                write_shutdown: false,
            },
        ))
    }

    pub fn open_udp(
        &self,
        metadata: FlowMetadata,
    ) -> Result<(UdpDatagramPort, UdpDatagramPort), StackError> {
        let handle = self.inner.borrow_mut().open_udp(metadata)?;
        let lease = Rc::new(UdpFlowLease {
            bridge: Rc::downgrade(&self.inner),
            handle,
        });
        let adapter_wake = Rc::new(PortWake::default());
        let policy_wake = Rc::new(PortWake::default());
        self.wakes
            .borrow_mut()
            .extend([Rc::downgrade(&adapter_wake), Rc::downgrade(&policy_wake)]);
        Ok((
            UdpDatagramPort {
                bridge: Rc::downgrade(&self.inner),
                lease: Rc::clone(&lease),
                side: Side::Adapter,
                wake: adapter_wake,
            },
            UdpDatagramPort {
                bridge: Rc::downgrade(&self.inner),
                lease,
                side: Side::Policy,
                wake: policy_wake,
            },
        ))
    }

    pub fn packet_port(&self) -> PacketPort {
        let wake = Rc::new(PortWake::default());
        self.wakes.borrow_mut().push(Rc::downgrade(&wake));
        PacketPort {
            bridge: Rc::downgrade(&self.inner),
            wake,
            closed: false,
        }
    }

    pub fn accept_packet_tcp(&self) -> Result<Option<(FlowMetadata, PacketTcpPort)>, StackError> {
        let Some(handle) = self.inner.borrow_mut().pending_packet_tcp.pop_front() else {
            return Ok(None);
        };
        let metadata = self.inner.borrow().packet_tcp_metadata(handle)?.clone();
        let lease = Rc::new(PacketTcpFlowLease {
            bridge: Rc::downgrade(&self.inner),
            handle,
        });
        let wake = Rc::new(PortWake::default());
        self.wakes.borrow_mut().push(Rc::downgrade(&wake));
        Ok(Some((
            metadata,
            PacketTcpPort {
                bridge: Rc::downgrade(&self.inner),
                lease,
                wake,
                write_shutdown: false,
            },
        )))
    }

    pub fn accept_packet_udp(&self) -> Result<Option<(FlowMetadata, PacketUdpPort)>, StackError> {
        let Some(handle) = self.inner.borrow_mut().pending_packet_udp.pop_front() else {
            return Ok(None);
        };
        let metadata = self.inner.borrow().packet_udp_metadata(handle)?.clone();
        let lease = Rc::new(PacketUdpFlowLease {
            bridge: Rc::downgrade(&self.inner),
            handle,
        });
        let wake = Rc::new(PortWake::default());
        self.wakes.borrow_mut().push(Rc::downgrade(&wake));
        Ok(Some((
            metadata,
            PacketUdpPort {
                bridge: Rc::downgrade(&self.inner),
                lease,
                wake,
            },
        )))
    }

    pub fn poll(&self) {
        self.inner.borrow_mut().poll();
        self.wakes.borrow_mut().retain(|wake| {
            let Some(wake) = wake.upgrade() else {
                return false;
            };
            if let Some(waker) = wake.waker.borrow_mut().take() {
                waker.wake();
            }
            true
        });
    }

    pub fn managed_bytes(&self) -> usize {
        self.inner.borrow().managed_bytes()
    }
}

impl PacketPort {
    fn pending<T>(&self, context: &Context<'_>) -> Poll<io::Result<T>> {
        *self.wake.waker.borrow_mut() = Some(context.waker().clone());
        Poll::Pending
    }

    fn bridge(&self) -> io::Result<Rc<RefCell<StackBridge>>> {
        self.bridge
            .upgrade()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "stack is stopped"))
    }
}

impl PacketTcpPort {
    fn pending<T>(&self, context: &Context<'_>) -> Poll<io::Result<T>> {
        *self.wake.waker.borrow_mut() = Some(context.waker().clone());
        Poll::Pending
    }

    fn bridge(&self) -> io::Result<Rc<RefCell<StackBridge>>> {
        self.bridge
            .upgrade()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "stack is stopped"))
    }
}

impl AsyncRead for PacketTcpPort {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if output.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let bridge = match self.bridge() {
            Ok(bridge) => bridge,
            Err(error) => return Poll::Ready(Err(error)),
        };
        let mut bridge = bridge.borrow_mut();
        let socket = match bridge.packet_tcp_socket(self.lease.handle) {
            Ok(socket) => socket,
            Err(error) => return Poll::Ready(Err(stack_io_error(error))),
        };
        if socket.can_recv() {
            return Poll::Ready(
                socket
                    .recv_slice(output)
                    .map_err(|error| io::Error::other(error.to_string())),
            );
        }
        if !socket.may_recv() {
            return Poll::Ready(Ok(0));
        }
        drop(bridge);
        self.pending(context)
    }
}

impl AsyncWrite for PacketTcpPort {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_shutdown {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "packet TCP write side is closed",
            )));
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let bridge = match self.bridge() {
            Ok(bridge) => bridge,
            Err(error) => return Poll::Ready(Err(error)),
        };
        let mut bridge = bridge.borrow_mut();
        let socket = match bridge.packet_tcp_socket(self.lease.handle) {
            Ok(socket) => socket,
            Err(error) => return Poll::Ready(Err(stack_io_error(error))),
        };
        if socket.can_send() {
            return Poll::Ready(
                socket
                    .send_slice(input)
                    .map_err(|error| io::Error::other(error.to_string())),
            );
        }
        if !socket.may_send() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "packet TCP socket is closed",
            )));
        }
        drop(bridge);
        self.pending(context)
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.write_shutdown {
            let bridge = match self.bridge() {
                Ok(bridge) => bridge,
                Err(error) => return Poll::Ready(Err(error)),
            };
            let result = bridge
                .borrow_mut()
                .packet_tcp_socket(self.lease.handle)
                .map(|socket| socket.close())
                .map_err(stack_io_error);
            if let Err(error) = result {
                return Poll::Ready(Err(error));
            }
            self.write_shutdown = true;
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for PacketTcpFlowLease {
    fn drop(&mut self) {
        if let Some(bridge) = self.bridge.upgrade() {
            let _ = bridge.borrow_mut().close_packet_tcp(self.handle);
        }
    }
}

impl PacketUdpPort {
    fn pending<T>(&self, context: &Context<'_>) -> Poll<io::Result<T>> {
        *self.wake.waker.borrow_mut() = Some(context.waker().clone());
        Poll::Pending
    }

    fn bridge(&self) -> io::Result<Rc<RefCell<StackBridge>>> {
        self.bridge
            .upgrade()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "stack is stopped"))
    }
}

impl DatagramIo for PacketUdpPort {
    fn poll_recv_datagram(
        &mut self,
        context: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<DatagramRecv>> {
        let bridge = match self.bridge() {
            Ok(bridge) => bridge,
            Err(error) => return Poll::Ready(Err(error)),
        };
        let mut bridge = bridge.borrow_mut();
        let flow = match bridge
            .packet_udp_flows
            .get_mut(TypedHandle::from_raw(self.lease.handle))
        {
            Ok(flow) => flow,
            Err(_) => return Poll::Ready(Ok(DatagramRecv::Closed)),
        };
        let Some(packet) = flow.incoming.as_ref() else {
            drop(bridge);
            return self.pending(context);
        };
        if output.len() < packet.len() {
            return Poll::Ready(Ok(DatagramRecv::BufferTooSmall(packet.len())));
        }
        let packet = flow.incoming.take().expect("checked above");
        bridge.release(packet.len());
        output[..packet.len()].copy_from_slice(&packet);
        Poll::Ready(Ok(DatagramRecv::Datagram(packet.len())))
    }

    fn poll_send_datagram(
        &mut self,
        context: &mut Context<'_>,
        datagram: &[u8],
    ) -> Poll<io::Result<()>> {
        if datagram.len() > self.bridge()?.borrow().config.max_udp_payload_bytes {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP payload exceeds stack limit",
            )));
        }
        let bridge = match self.bridge() {
            Ok(bridge) => bridge,
            Err(error) => return Poll::Ready(Err(error)),
        };
        let mut bridge = bridge.borrow_mut();
        let tuple = match bridge
            .packet_udp_flows
            .get(TypedHandle::from_raw(self.lease.handle))
        {
            Ok(flow) => flow.tuple,
            Err(_) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "packet UDP flow is closed",
                )));
            }
        };
        let socket_handle = match bridge.packet_udp_groups.get(&tuple.destination) {
            Some(group) => group.socket,
            None => return Poll::Ready(Err(io::Error::other("packet UDP socket is missing"))),
        };
        match bridge
            .sockets
            .get_mut::<udp::Socket>(socket_handle)
            .send_slice(datagram, tuple.source)
        {
            Ok(()) => Poll::Ready(Ok(())),
            Err(udp::SendError::BufferFull) => {
                drop(bridge);
                self.pending(context)
            }
            Err(_) => Poll::Ready(Err(io::Error::other("packet UDP send failed"))),
        }
    }

    fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for PacketUdpFlowLease {
    fn drop(&mut self) {
        if let Some(bridge) = self.bridge.upgrade() {
            let _ = bridge.borrow_mut().close_packet_udp(self.handle);
        }
    }
}

impl DatagramIo for PacketPort {
    fn poll_recv_datagram(
        &mut self,
        context: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<DatagramRecv>> {
        if self.closed {
            return Poll::Ready(Ok(DatagramRecv::Closed));
        }
        let bridge = match self.bridge() {
            Ok(bridge) => bridge,
            Err(error) => return Poll::Ready(Err(error)),
        };
        let mut bridge = bridge.borrow_mut();
        let Some(required) = bridge.device.egress.front().map(Vec::len) else {
            drop(bridge);
            return self.pending(context);
        };
        if output.len() < required {
            return Poll::Ready(Ok(DatagramRecv::BufferTooSmall(required)));
        }
        let packet = bridge.device.egress.pop_front().expect("front checked");
        bridge.device.bytes -= packet.len();
        output[..packet.len()].copy_from_slice(&packet);
        Poll::Ready(Ok(DatagramRecv::Datagram(packet.len())))
    }

    fn poll_send_datagram(
        &mut self,
        context: &mut Context<'_>,
        packet: &[u8],
    ) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "packet port is closed",
            )));
        }
        if packet.is_empty() || packet.len() > u16::MAX as usize || !valid_ip_packet(packet) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet port input is invalid",
            )));
        }
        let bridge = match self.bridge() {
            Ok(bridge) => bridge,
            Err(error) => return Poll::Ready(Err(error)),
        };
        let mut bridge = bridge.borrow_mut();
        if bridge.device.bytes.saturating_add(packet.len()) > bridge.device.byte_limit {
            drop(bridge);
            return self.pending(context);
        }
        bridge.device.bytes += packet.len();
        bridge.device.ingress.push_back(QueuedPacket {
            bytes: packet.to_vec(),
            external: true,
        });
        Poll::Ready(Ok(()))
    }

    fn close(&mut self) -> io::Result<()> {
        self.closed = true;
        Ok(())
    }
}

impl TcpStreamPort {
    pub fn metadata(&self) -> Result<FlowMetadata, StackError> {
        let bridge = self.bridge.upgrade().ok_or(StackError::Stopped)?;
        Ok(bridge.borrow().tcp_metadata(self.lease.handle)?.clone())
    }

    fn pending<T>(&self, context: &Context<'_>) -> Poll<io::Result<T>> {
        *self.wake.waker.borrow_mut() = Some(context.waker().clone());
        Poll::Pending
    }

    fn bridge(&self) -> io::Result<Rc<RefCell<StackBridge>>> {
        self.bridge
            .upgrade()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "stack is stopped"))
    }
}

impl AsyncRead for TcpStreamPort {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if output.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let bridge = match self.bridge() {
            Ok(bridge) => bridge,
            Err(error) => return Poll::Ready(Err(error)),
        };
        let mut bridge = bridge.borrow_mut();
        let socket = match bridge.tcp_socket(self.lease.handle, self.side) {
            Ok(socket) => socket,
            Err(error) => return Poll::Ready(Err(stack_io_error(error))),
        };
        if socket.can_recv() {
            return Poll::Ready(
                socket
                    .recv_slice(output)
                    .map_err(|error| io::Error::other(error.to_string())),
            );
        }
        if !socket.may_recv() {
            return Poll::Ready(Ok(0));
        }
        drop(bridge);
        self.pending(context)
    }
}

impl AsyncWrite for TcpStreamPort {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_shutdown {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stack stream write side is closed",
            )));
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let bridge = match self.bridge() {
            Ok(bridge) => bridge,
            Err(error) => return Poll::Ready(Err(error)),
        };
        let mut bridge = bridge.borrow_mut();
        let socket = match bridge.tcp_socket(self.lease.handle, self.side) {
            Ok(socket) => socket,
            Err(error) => return Poll::Ready(Err(stack_io_error(error))),
        };
        if socket.can_send() {
            return Poll::Ready(
                socket
                    .send_slice(input)
                    .map_err(|error| io::Error::other(error.to_string())),
            );
        }
        if !socket.may_send() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stack stream is closed",
            )));
        }
        drop(bridge);
        self.pending(context)
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_shutdown {
            return Poll::Ready(Ok(()));
        }
        let bridge = match self.bridge() {
            Ok(bridge) => bridge,
            Err(error) => return Poll::Ready(Err(error)),
        };
        let result = bridge
            .borrow_mut()
            .tcp_shutdown_write(self.lease.handle, self.side)
            .map_err(stack_io_error);
        if result.is_ok() {
            self.write_shutdown = true;
        }
        Poll::Ready(result)
    }
}

impl Drop for TcpFlowLease {
    fn drop(&mut self) {
        if let Some(bridge) = self.bridge.upgrade() {
            let _ = bridge.borrow_mut().close_tcp(self.handle);
        }
    }
}

impl UdpDatagramPort {
    pub fn metadata(&self) -> Result<FlowMetadata, StackError> {
        let bridge = self.bridge.upgrade().ok_or(StackError::Stopped)?;
        Ok(bridge.borrow().udp_metadata(self.lease.handle)?.clone())
    }

    fn pending<T>(&self, context: &Context<'_>) -> Poll<io::Result<T>> {
        *self.wake.waker.borrow_mut() = Some(context.waker().clone());
        Poll::Pending
    }

    fn bridge(&self) -> io::Result<Rc<RefCell<StackBridge>>> {
        self.bridge
            .upgrade()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "stack is stopped"))
    }
}

impl DatagramIo for UdpDatagramPort {
    fn poll_recv_datagram(
        &mut self,
        context: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<DatagramRecv>> {
        let bridge = match self.bridge() {
            Ok(bridge) => bridge,
            Err(error) => return Poll::Ready(Err(error)),
        };
        let result = {
            let mut bridge = bridge.borrow_mut();
            match self.side {
                Side::Adapter => bridge.udp_recv_adapter(self.lease.handle, output),
                Side::Policy => bridge.udp_recv_policy(self.lease.handle, output),
            }
        };
        match result {
            Ok(DatagramRead::Empty) => self.pending(context),
            Ok(DatagramRead::Datagram(length)) => Poll::Ready(Ok(DatagramRecv::Datagram(length))),
            Ok(DatagramRead::BufferTooSmall(required)) => {
                Poll::Ready(Ok(DatagramRecv::BufferTooSmall(required)))
            }
            Err(error) => Poll::Ready(Err(stack_io_error(error))),
        }
    }

    fn poll_send_datagram(
        &mut self,
        context: &mut Context<'_>,
        datagram: &[u8],
    ) -> Poll<io::Result<()>> {
        if datagram.len() > crate::wire::MAX_UDP_PAYLOAD {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP payload exceeds wire limit",
            )));
        }
        let bridge = match self.bridge() {
            Ok(bridge) => bridge,
            Err(error) => return Poll::Ready(Err(error)),
        };
        let result = {
            let mut bridge = bridge.borrow_mut();
            match self.side {
                Side::Adapter => bridge.udp_send_adapter(self.lease.handle, datagram),
                Side::Policy => bridge.udp_send_policy(self.lease.handle, datagram),
            }
        };
        match result {
            Ok(()) => Poll::Ready(Ok(())),
            Err(StackError::Udp) => self.pending(context),
            Err(error) => Poll::Ready(Err(stack_io_error(error))),
        }
    }

    fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for UdpFlowLease {
    fn drop(&mut self) {
        if let Some(bridge) = self.bridge.upgrade() {
            let _ = bridge.borrow_mut().close_udp(self.handle);
        }
    }
}

fn stack_io_error(error: StackError) -> io::Error {
    io::Error::other(error.to_string())
}

impl StackBridge {
    pub fn new(
        config: StackConfig,
        max_flows: usize,
        max_managed_bytes: usize,
        max_ingress_packets_per_tick: usize,
    ) -> Result<Self, StackError> {
        let mut device = BoundedDevice::new(config.mtu, config.packet_queue_bytes);
        let interface_config = InterfaceConfig::new(HardwareAddress::Ip);
        let mut interface = Interface::new(interface_config, &mut device, Instant::from_millis(0));
        interface.update_ip_addrs(|addresses| {
            if config.ipv4 {
                addresses
                    .push(IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8))
                    .unwrap();
            }
            if config.ipv6 {
                addresses
                    .push(IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 128))
                    .unwrap();
            }
        });
        interface.set_any_ip(true);
        if config.ipv4 {
            interface
                .routes_mut()
                .add_default_ipv4_route(Ipv4Address::new(127, 0, 0, 1))
                .map_err(|_| StackError::Resource)?;
        }
        if config.ipv6 {
            interface
                .routes_mut()
                .add_default_ipv6_route(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1))
                .map_err(|_| StackError::Resource)?;
        }
        Ok(Self {
            interface,
            device,
            sockets: SocketSet::new(Vec::new()),
            tcp_flows: HandleTable::new(1, max_flows),
            udp_flows: HandleTable::new(2, max_flows),
            packet_tcp_flows: HandleTable::new(3, max_flows),
            packet_tcp_by_tuple: HashMap::new(),
            pending_packet_tcp: VecDeque::new(),
            packet_udp_groups: HashMap::new(),
            packet_udp_flows: HandleTable::new(4, max_flows),
            packet_udp_by_tuple: HashMap::new(),
            pending_packet_udp: VecDeque::new(),
            ports: PortPool::new(),
            config,
            managed_bytes: 0,
            max_managed_bytes,
            max_ingress_packets_per_tick,
            started: StdInstant::now(),
        })
    }

    pub fn open_tcp(&mut self, metadata: FlowMetadata) -> Result<TcpFlowHandle, StackError> {
        validate_metadata(&metadata)?;
        let managed_bytes = self
            .config
            .tcp_socket_rx_bytes
            .checked_add(self.config.tcp_socket_tx_bytes)
            .and_then(|one| one.checked_mul(2))
            .ok_or(StackError::Resource)?;
        self.reserve(managed_bytes)?;
        let adapter_port = match self.ports.allocate() {
            Ok(port) => port,
            Err(error) => {
                self.release(managed_bytes);
                return Err(error);
            }
        };
        let policy_port = match self.ports.allocate() {
            Ok(port) => port,
            Err(error) => {
                self.ports.release(adapter_port)?;
                self.release(managed_bytes);
                return Err(error);
            }
        };
        let policy = self.sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; self.config.tcp_socket_rx_bytes]),
            tcp::SocketBuffer::new(vec![0; self.config.tcp_socket_tx_bytes]),
        ));
        let adapter = self.sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; self.config.tcp_socket_rx_bytes]),
            tcp::SocketBuffer::new(vec![0; self.config.tcp_socket_tx_bytes]),
        ));
        if let Err(error) = self
            .sockets
            .get_mut::<tcp::Socket>(policy)
            .listen(policy_port)
        {
            self.cleanup_tcp_sockets(adapter, policy, adapter_port, policy_port, managed_bytes);
            return Err(StackError::Tcp(error.to_string()));
        }
        let endpoint = IpEndpoint::new(IpAddress::v4(127, 0, 0, 1), policy_port);
        let connect = {
            let context = self.interface.context();
            self.sockets
                .get_mut::<tcp::Socket>(adapter)
                .connect(context, endpoint, adapter_port)
        };
        if let Err(error) = connect {
            self.cleanup_tcp_sockets(adapter, policy, adapter_port, policy_port, managed_bytes);
            return Err(StackError::Tcp(error.to_string()));
        }
        let flow = TcpFlow {
            adapter,
            policy,
            adapter_port,
            policy_port,
            metadata,
            managed_bytes,
        };
        let handle = match self.tcp_flows.insert(flow) {
            Ok(handle) => handle,
            Err(_) => {
                self.cleanup_tcp_sockets(adapter, policy, adapter_port, policy_port, managed_bytes);
                return Err(StackError::FlowLimit);
            }
        };
        for _ in 0..8 {
            self.poll();
        }
        Ok(TcpFlowHandle(handle.raw()))
    }

    pub fn open_udp(&mut self, metadata: FlowMetadata) -> Result<UdpFlowHandle, StackError> {
        validate_metadata(&metadata)?;
        let managed_bytes = self
            .config
            .udp_socket_rx_bytes
            .checked_add(self.config.udp_socket_tx_bytes)
            .and_then(|one| one.checked_mul(2))
            .ok_or(StackError::Resource)?;
        self.reserve(managed_bytes)?;
        let adapter_port = match self.ports.allocate() {
            Ok(port) => port,
            Err(error) => {
                self.release(managed_bytes);
                return Err(error);
            }
        };
        let policy_port = match self.ports.allocate() {
            Ok(port) => port,
            Err(error) => {
                self.ports.release(adapter_port)?;
                self.release(managed_bytes);
                return Err(error);
            }
        };
        let adapter = self.sockets.add(new_udp_socket(&self.config));
        let policy = self.sockets.add(new_udp_socket(&self.config));
        if self
            .sockets
            .get_mut::<udp::Socket>(adapter)
            .bind(adapter_port)
            .is_err()
            || self
                .sockets
                .get_mut::<udp::Socket>(policy)
                .bind(policy_port)
                .is_err()
        {
            self.cleanup_udp_sockets(adapter, policy, adapter_port, policy_port, managed_bytes);
            return Err(StackError::Udp);
        }
        let flow = UdpFlow {
            adapter,
            policy,
            adapter_port,
            policy_port,
            metadata,
            managed_bytes,
        };
        let handle = match self.udp_flows.insert(flow) {
            Ok(handle) => handle,
            Err(_) => {
                self.cleanup_udp_sockets(adapter, policy, adapter_port, policy_port, managed_bytes);
                return Err(StackError::FlowLimit);
            }
        };
        Ok(UdpFlowHandle(handle.raw()))
    }

    pub fn tcp_send_adapter(
        &mut self,
        handle: TcpFlowHandle,
        data: &[u8],
    ) -> Result<usize, StackError> {
        let socket = self.tcp_socket(handle, Side::Adapter)?;
        socket
            .send_slice(data)
            .map_err(|error| StackError::Tcp(error.to_string()))
    }

    pub fn tcp_send_policy(
        &mut self,
        handle: TcpFlowHandle,
        data: &[u8],
    ) -> Result<usize, StackError> {
        let socket = self.tcp_socket(handle, Side::Policy)?;
        socket
            .send_slice(data)
            .map_err(|error| StackError::Tcp(error.to_string()))
    }

    pub fn tcp_recv_adapter(
        &mut self,
        handle: TcpFlowHandle,
        output: &mut [u8],
    ) -> Result<usize, StackError> {
        let socket = self.tcp_socket(handle, Side::Adapter)?;
        socket
            .recv_slice(output)
            .map_err(|error| StackError::Tcp(error.to_string()))
    }

    pub fn tcp_recv_policy(
        &mut self,
        handle: TcpFlowHandle,
        output: &mut [u8],
    ) -> Result<usize, StackError> {
        let socket = self.tcp_socket(handle, Side::Policy)?;
        socket
            .recv_slice(output)
            .map_err(|error| StackError::Tcp(error.to_string()))
    }

    pub fn tcp_shutdown_write(
        &mut self,
        handle: TcpFlowHandle,
        side: Side,
    ) -> Result<(), StackError> {
        self.tcp_socket(handle, side)?.close();
        Ok(())
    }

    pub fn tcp_metadata(&self, handle: TcpFlowHandle) -> Result<&FlowMetadata, StackError> {
        Ok(&self
            .tcp_flows
            .get(TypedHandle::from_raw(handle.0))
            .map_err(|_| StackError::Stale)?
            .metadata)
    }

    pub fn close_tcp(&mut self, handle: TcpFlowHandle) -> Result<(), StackError> {
        let flow = self
            .tcp_flows
            .remove(TypedHandle::from_raw(handle.0))
            .map_err(|_| StackError::Stale)?;
        self.sockets.remove(flow.adapter);
        self.sockets.remove(flow.policy);
        self.ports.release(flow.adapter_port)?;
        self.ports.release(flow.policy_port)?;
        self.release(flow.managed_bytes);
        Ok(())
    }

    pub fn udp_send_adapter(
        &mut self,
        handle: UdpFlowHandle,
        data: &[u8],
    ) -> Result<(), StackError> {
        let endpoint = self.udp_endpoint(handle, Side::Policy)?;
        self.udp_socket(handle, Side::Adapter)?
            .send_slice(data, endpoint)
            .map_err(|_| StackError::Udp)
    }

    pub fn udp_send_policy(
        &mut self,
        handle: UdpFlowHandle,
        data: &[u8],
    ) -> Result<(), StackError> {
        let endpoint = self.udp_endpoint(handle, Side::Adapter)?;
        self.udp_socket(handle, Side::Policy)?
            .send_slice(data, endpoint)
            .map_err(|_| StackError::Udp)
    }

    pub fn udp_recv_adapter(
        &mut self,
        handle: UdpFlowHandle,
        output: &mut [u8],
    ) -> Result<DatagramRead, StackError> {
        recv_udp(self.udp_socket(handle, Side::Adapter)?, output)
    }

    pub fn udp_recv_policy(
        &mut self,
        handle: UdpFlowHandle,
        output: &mut [u8],
    ) -> Result<DatagramRead, StackError> {
        recv_udp(self.udp_socket(handle, Side::Policy)?, output)
    }

    pub fn udp_metadata(&self, handle: UdpFlowHandle) -> Result<&FlowMetadata, StackError> {
        Ok(&self
            .udp_flows
            .get(TypedHandle::from_raw(handle.0))
            .map_err(|_| StackError::Stale)?
            .metadata)
    }

    pub fn close_udp(&mut self, handle: UdpFlowHandle) -> Result<(), StackError> {
        let flow = self
            .udp_flows
            .remove(TypedHandle::from_raw(handle.0))
            .map_err(|_| StackError::Stale)?;
        self.sockets.remove(flow.adapter);
        self.sockets.remove(flow.policy);
        self.ports.release(flow.adapter_port)?;
        self.ports.release(flow.policy_port)?;
        self.release(flow.managed_bytes);
        Ok(())
    }

    pub fn poll(&mut self) {
        let now = self.now();
        self.interface.poll_maintenance(now);
        for _ in 0..self.max_ingress_packets_per_tick {
            if self.prepare_packet_tcp().is_err()
                && let Some(packet) = self.device.ingress.pop_front()
            {
                self.device.bytes -= packet.bytes.len();
            }
            if let Err(_error) = self.prepare_packet_udp() {
                if let Some(packet) = self.device.ingress.pop_front() {
                    self.device.bytes -= packet.bytes.len();
                }
                continue;
            }
            if matches!(
                self.interface
                    .poll_ingress_single(now, &mut self.device, &mut self.sockets),
                PollIngressSingleResult::None
            ) {
                break;
            }
        }
        self.queue_established_packet_tcp();
        self.drain_packet_udp();
        let _ = self
            .interface
            .poll_egress(now, &mut self.device, &mut self.sockets);
    }

    pub fn stop_device(&mut self) {
        self.device.stopped = true;
    }

    pub fn start_device(&mut self) {
        self.device.stopped = false;
    }

    pub fn queued_packet_bytes(&self) -> usize {
        self.device.bytes
    }

    pub fn managed_bytes(&self) -> usize {
        self.managed_bytes
    }

    fn tcp_socket(
        &mut self,
        handle: TcpFlowHandle,
        side: Side,
    ) -> Result<&mut tcp::Socket<'static>, StackError> {
        let flow = self
            .tcp_flows
            .get(TypedHandle::from_raw(handle.0))
            .map_err(|_| StackError::Stale)?;
        let socket = match side {
            Side::Adapter => flow.adapter,
            Side::Policy => flow.policy,
        };
        Ok(self.sockets.get_mut(socket))
    }

    fn packet_tcp_socket(&mut self, handle: u64) -> Result<&mut tcp::Socket<'static>, StackError> {
        let flow = self
            .packet_tcp_flows
            .get(TypedHandle::from_raw(handle))
            .map_err(|_| StackError::Stale)?;
        Ok(self.sockets.get_mut(flow.socket))
    }

    fn packet_tcp_metadata(&self, handle: u64) -> Result<&FlowMetadata, StackError> {
        Ok(&self
            .packet_tcp_flows
            .get(TypedHandle::from_raw(handle))
            .map_err(|_| StackError::Stale)?
            .metadata)
    }

    fn prepare_packet_tcp(&mut self) -> Result<(), StackError> {
        let Some(packet) = self.device.ingress.front() else {
            return Ok(());
        };
        if !packet.external {
            return Ok(());
        }
        let Some(tuple) = tcp_syn_tuple(&packet.bytes) else {
            return Ok(());
        };
        if self.packet_tcp_by_tuple.contains_key(&tuple) {
            return Ok(());
        }
        let managed_bytes = self
            .config
            .tcp_socket_rx_bytes
            .checked_add(self.config.tcp_socket_tx_bytes)
            .ok_or(StackError::Resource)?;
        self.reserve(managed_bytes)?;
        let socket = self.sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; self.config.tcp_socket_rx_bytes]),
            tcp::SocketBuffer::new(vec![0; self.config.tcp_socket_tx_bytes]),
        ));
        if let Err(error) = self
            .sockets
            .get_mut::<tcp::Socket>(socket)
            .listen(tuple.destination)
        {
            self.sockets.remove(socket);
            self.release(managed_bytes);
            return Err(StackError::Tcp(error.to_string()));
        }
        let destination = match tuple.destination.addr {
            IpAddress::Ipv4(address) => Destination::Ipv4(address),
            IpAddress::Ipv6(address) => Destination::Ipv6(address),
        };
        let flow = PacketTcpFlow {
            socket,
            tuple,
            metadata: FlowMetadata {
                destination,
                port: tuple.destination.port,
                opaque: Vec::new(),
            },
            managed_bytes,
            queued: false,
        };
        let handle = match self.packet_tcp_flows.insert(flow) {
            Ok(handle) => handle.raw(),
            Err(_) => {
                self.sockets.remove(socket);
                self.release(managed_bytes);
                return Err(StackError::FlowLimit);
            }
        };
        self.packet_tcp_by_tuple.insert(tuple, handle);
        Ok(())
    }

    fn queue_established_packet_tcp(&mut self) {
        let handles: Vec<u64> = self.packet_tcp_by_tuple.values().copied().collect();
        for handle in handles {
            let Ok(flow) = self.packet_tcp_flows.get_mut(TypedHandle::from_raw(handle)) else {
                continue;
            };
            if flow.queued {
                continue;
            }
            if self.sockets.get::<tcp::Socket>(flow.socket).state() == tcp::State::Established {
                flow.queued = true;
                self.pending_packet_tcp.push_back(handle);
            }
        }
    }

    fn close_packet_tcp(&mut self, handle: u64) -> Result<(), StackError> {
        let flow = self
            .packet_tcp_flows
            .remove(TypedHandle::from_raw(handle))
            .map_err(|_| StackError::Stale)?;
        self.packet_tcp_by_tuple.remove(&flow.tuple);
        self.pending_packet_tcp.retain(|pending| *pending != handle);
        self.sockets.remove(flow.socket);
        self.release(flow.managed_bytes);
        Ok(())
    }

    fn packet_udp_metadata(&self, handle: u64) -> Result<&FlowMetadata, StackError> {
        Ok(&self
            .packet_udp_flows
            .get(TypedHandle::from_raw(handle))
            .map_err(|_| StackError::Stale)?
            .metadata)
    }

    fn prepare_packet_udp(&mut self) -> Result<(), StackError> {
        let Some(packet) = self.device.ingress.front() else {
            return Ok(());
        };
        if !packet.external {
            return Ok(());
        }
        let Some(tuple) = udp_tuple(&packet.bytes) else {
            return Ok(());
        };
        if self.packet_udp_groups.contains_key(&tuple.destination) {
            return Ok(());
        }
        let managed_bytes = self
            .config
            .udp_socket_rx_bytes
            .checked_add(self.config.udp_socket_tx_bytes)
            .ok_or(StackError::Resource)?;
        self.reserve(managed_bytes)?;
        let socket = self.sockets.add(new_udp_socket(&self.config));
        if self
            .sockets
            .get_mut::<udp::Socket>(socket)
            .bind(tuple.destination)
            .is_err()
        {
            self.sockets.remove(socket);
            self.release(managed_bytes);
            return Err(StackError::Udp);
        }
        self.packet_udp_groups.insert(
            tuple.destination,
            PacketUdpGroup {
                socket,
                managed_bytes,
                flows: 0,
            },
        );
        Ok(())
    }

    fn drain_packet_udp(&mut self) {
        let destinations: Vec<IpEndpoint> = self.packet_udp_groups.keys().copied().collect();
        for destination in destinations {
            while let Some(socket) = self
                .packet_udp_groups
                .get(&destination)
                .map(|group| group.socket)
            {
                let next = {
                    let socket = self.sockets.get_mut::<udp::Socket>(socket);
                    let Ok((payload, metadata)) = socket.peek() else {
                        break;
                    };
                    (payload.to_vec(), metadata.endpoint)
                };
                let tuple = PacketUdpTuple {
                    source: next.1,
                    destination,
                };
                if let Some(handle) = self.packet_udp_by_tuple.get(&tuple).copied()
                    && self
                        .packet_udp_flows
                        .get(TypedHandle::from_raw(handle))
                        .ok()
                        .and_then(|flow| flow.incoming.as_ref())
                        .is_some()
                {
                    break;
                }
                if self.reserve(next.0.len()).is_err() {
                    break;
                }
                let payload = {
                    let socket = self.sockets.get_mut::<udp::Socket>(socket);
                    match socket.recv() {
                        Ok((payload, _)) => payload.to_vec(),
                        Err(_) => {
                            self.release(next.0.len());
                            break;
                        }
                    }
                };
                if let Some(handle) = self.packet_udp_by_tuple.get(&tuple).copied() {
                    if let Ok(flow) = self.packet_udp_flows.get_mut(TypedHandle::from_raw(handle)) {
                        flow.incoming = Some(payload);
                    } else {
                        self.release(payload.len());
                    }
                    continue;
                }
                let destination_value = match destination.addr {
                    IpAddress::Ipv4(address) => Destination::Ipv4(address),
                    IpAddress::Ipv6(address) => Destination::Ipv6(address),
                };
                let flow = PacketUdpFlow {
                    tuple,
                    metadata: FlowMetadata {
                        destination: destination_value,
                        port: destination.port,
                        opaque: Vec::new(),
                    },
                    incoming: Some(payload),
                };
                let handle = match self.packet_udp_flows.insert(flow) {
                    Ok(handle) => handle.raw(),
                    Err(_) => {
                        self.release(next.0.len());
                        break;
                    }
                };
                self.packet_udp_by_tuple.insert(tuple, handle);
                if let Some(group) = self.packet_udp_groups.get_mut(&destination) {
                    group.flows += 1;
                }
                self.pending_packet_udp.push_back(handle);
            }
        }
    }

    fn close_packet_udp(&mut self, handle: u64) -> Result<(), StackError> {
        let flow = self
            .packet_udp_flows
            .remove(TypedHandle::from_raw(handle))
            .map_err(|_| StackError::Stale)?;
        if let Some(packet) = flow.incoming {
            self.release(packet.len());
        }
        self.packet_udp_by_tuple.remove(&flow.tuple);
        self.pending_packet_udp.retain(|pending| *pending != handle);
        let mut remove_group = None;
        if let Some(group) = self.packet_udp_groups.get_mut(&flow.tuple.destination) {
            group.flows = group.flows.saturating_sub(1);
            if group.flows == 0 {
                remove_group = Some((group.socket, group.managed_bytes));
            }
        }
        if let Some((socket, managed_bytes)) = remove_group {
            self.packet_udp_groups.remove(&flow.tuple.destination);
            self.sockets.remove(socket);
            self.release(managed_bytes);
        }
        Ok(())
    }

    fn udp_socket(
        &mut self,
        handle: UdpFlowHandle,
        side: Side,
    ) -> Result<&mut udp::Socket<'static>, StackError> {
        let flow = self
            .udp_flows
            .get(TypedHandle::from_raw(handle.0))
            .map_err(|_| StackError::Stale)?;
        let socket = match side {
            Side::Adapter => flow.adapter,
            Side::Policy => flow.policy,
        };
        Ok(self.sockets.get_mut(socket))
    }

    fn udp_endpoint(&self, handle: UdpFlowHandle, side: Side) -> Result<IpEndpoint, StackError> {
        let flow = self
            .udp_flows
            .get(TypedHandle::from_raw(handle.0))
            .map_err(|_| StackError::Stale)?;
        let port = match side {
            Side::Adapter => flow.adapter_port,
            Side::Policy => flow.policy_port,
        };
        Ok(IpEndpoint::new(IpAddress::v4(127, 0, 0, 1), port))
    }

    fn reserve(&mut self, bytes: usize) -> Result<(), StackError> {
        let next = self
            .managed_bytes
            .checked_add(bytes)
            .ok_or(StackError::Resource)?;
        if next > self.max_managed_bytes {
            return Err(StackError::Resource);
        }
        self.managed_bytes = next;
        Ok(())
    }

    fn release(&mut self, bytes: usize) {
        self.managed_bytes -= bytes;
    }

    fn now(&self) -> Instant {
        let millis = i64::try_from(self.started.elapsed().as_millis()).unwrap_or(i64::MAX);
        Instant::from_millis(millis)
    }

    fn cleanup_tcp_sockets(
        &mut self,
        adapter: SocketHandle,
        policy: SocketHandle,
        adapter_port: u16,
        policy_port: u16,
        bytes: usize,
    ) {
        self.sockets.remove(adapter);
        self.sockets.remove(policy);
        let _ = self.ports.release(adapter_port);
        let _ = self.ports.release(policy_port);
        self.release(bytes);
    }

    fn cleanup_udp_sockets(
        &mut self,
        adapter: SocketHandle,
        policy: SocketHandle,
        adapter_port: u16,
        policy_port: u16,
        bytes: usize,
    ) {
        self.sockets.remove(adapter);
        self.sockets.remove(policy);
        let _ = self.ports.release(adapter_port);
        let _ = self.ports.release(policy_port);
        self.release(bytes);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Side {
    Adapter,
    Policy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatagramRead {
    Empty,
    Datagram(usize),
    BufferTooSmall(usize),
}

fn recv_udp(
    socket: &mut udp::Socket<'static>,
    output: &mut [u8],
) -> Result<DatagramRead, StackError> {
    let length = match socket.peek() {
        Ok((payload, _)) => payload.len(),
        Err(udp::RecvError::Exhausted) => return Ok(DatagramRead::Empty),
        Err(_) => return Err(StackError::Udp),
    };
    if output.len() < length {
        return Ok(DatagramRead::BufferTooSmall(length));
    }
    let (length, _) = socket.recv_slice(output).map_err(|_| StackError::Udp)?;
    Ok(DatagramRead::Datagram(length))
}

fn new_udp_socket(config: &StackConfig) -> udp::Socket<'static> {
    udp::Socket::new(
        udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; config.udp_metadata_slots],
            vec![0; config.udp_socket_rx_bytes],
        ),
        udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; config.udp_metadata_slots],
            vec![0; config.udp_socket_tx_bytes],
        ),
    )
}

fn validate_metadata(metadata: &FlowMetadata) -> Result<(), StackError> {
    if metadata.port == 0 || metadata.opaque.len() > crate::wire::MAX_METADATA {
        return Err(StackError::Metadata);
    }
    Ok(())
}

struct PortPool {
    available: VecDeque<u16>,
    allocated: Vec<bool>,
}

impl PortPool {
    fn new() -> Self {
        Self {
            available: (FIRST_DYNAMIC_PORT..=u16::MAX).collect(),
            allocated: vec![false; usize::from(u16::MAX) + 1],
        }
    }

    fn allocate(&mut self) -> Result<u16, StackError> {
        let port = self.available.pop_front().ok_or(StackError::PortLimit)?;
        self.allocated[usize::from(port)] = true;
        Ok(port)
    }

    fn release(&mut self, port: u16) -> Result<(), StackError> {
        if port < FIRST_DYNAMIC_PORT || !self.allocated[usize::from(port)] {
            return Err(StackError::Stale);
        }
        self.allocated[usize::from(port)] = false;
        self.available.push_back(port);
        Ok(())
    }
}

struct BoundedDevice {
    ingress: VecDeque<QueuedPacket>,
    egress: VecDeque<Vec<u8>>,
    bytes: usize,
    byte_limit: usize,
    mtu: usize,
    stopped: bool,
    dropped: usize,
}

struct QueuedPacket {
    bytes: Vec<u8>,
    external: bool,
}

impl BoundedDevice {
    fn new(mtu: usize, byte_limit: usize) -> Self {
        Self {
            ingress: VecDeque::new(),
            egress: VecDeque::new(),
            bytes: 0,
            byte_limit,
            mtu,
            stopped: false,
            dropped: 0,
        }
    }
}

struct BoundedRxToken {
    packet: Vec<u8>,
}

struct BoundedTxToken<'a> {
    ingress: &'a mut VecDeque<QueuedPacket>,
    egress: &'a mut VecDeque<Vec<u8>>,
    bytes: &'a mut usize,
    byte_limit: usize,
    dropped: &'a mut usize,
}

impl Device for BoundedDevice {
    type RxToken<'a> = BoundedRxToken;
    type TxToken<'a> = BoundedTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.stopped {
            return None;
        }
        let packet = self.ingress.pop_front()?;
        self.bytes -= packet.bytes.len();
        Some((
            BoundedRxToken {
                packet: packet.bytes,
            },
            BoundedTxToken {
                ingress: &mut self.ingress,
                egress: &mut self.egress,
                bytes: &mut self.bytes,
                byte_limit: self.byte_limit,
                dropped: &mut self.dropped,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        if self.stopped {
            return None;
        }
        Some(BoundedTxToken {
            ingress: &mut self.ingress,
            egress: &mut self.egress,
            bytes: &mut self.bytes,
            byte_limit: self.byte_limit,
            dropped: &mut self.dropped,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities.checksum = ChecksumCapabilities::ignored();
        capabilities
    }
}

impl RxToken for BoundedRxToken {
    fn consume<R, F>(self, function: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        function(&self.packet)
    }
}

impl TxToken for BoundedTxToken<'_> {
    fn consume<R, F>(self, length: usize, function: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; length];
        let result = function(&mut packet);
        if self.bytes.saturating_add(length) <= self.byte_limit {
            *self.bytes += length;
            if virtual_loopback_destination(&packet) {
                self.ingress.push_back(QueuedPacket {
                    bytes: packet,
                    external: false,
                });
            } else {
                self.egress.push_back(packet);
            }
        } else {
            *self.dropped += 1;
        }
        result
    }
}

fn valid_ip_packet(packet: &[u8]) -> bool {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => packet.len() >= 20,
        Some(6) => packet.len() >= 40,
        _ => false,
    }
}

fn tcp_syn_tuple(packet: &[u8]) -> Option<PacketTcpTuple> {
    let (source, destination, payload) = match packet.first().map(|byte| byte >> 4)? {
        4 => {
            let packet = Ipv4Packet::new_checked(packet).ok()?;
            if packet.next_header() != IpProtocol::Tcp {
                return None;
            }
            (
                IpAddress::Ipv4(packet.src_addr()),
                IpAddress::Ipv4(packet.dst_addr()),
                packet.payload(),
            )
        }
        6 => {
            let packet = Ipv6Packet::new_checked(packet).ok()?;
            if packet.next_header() != IpProtocol::Tcp {
                return None;
            }
            (
                IpAddress::Ipv6(packet.src_addr()),
                IpAddress::Ipv6(packet.dst_addr()),
                packet.payload(),
            )
        }
        _ => return None,
    };
    let tcp = TcpPacket::new_checked(payload).ok()?;
    if !tcp.syn() || tcp.ack() || tcp.src_port() == 0 || tcp.dst_port() == 0 {
        return None;
    }
    Some(PacketTcpTuple {
        source: IpEndpoint::new(source, tcp.src_port()),
        destination: IpEndpoint::new(destination, tcp.dst_port()),
    })
}

fn udp_tuple(packet: &[u8]) -> Option<PacketUdpTuple> {
    let (source, destination, payload) = match packet.first().map(|byte| byte >> 4)? {
        4 => {
            let packet = Ipv4Packet::new_checked(packet).ok()?;
            if packet.next_header() != IpProtocol::Udp || packet.frag_offset() != 0 {
                return None;
            }
            (
                IpAddress::Ipv4(packet.src_addr()),
                IpAddress::Ipv4(packet.dst_addr()),
                packet.payload(),
            )
        }
        6 => {
            let packet = Ipv6Packet::new_checked(packet).ok()?;
            if packet.next_header() != IpProtocol::Udp {
                return None;
            }
            (
                IpAddress::Ipv6(packet.src_addr()),
                IpAddress::Ipv6(packet.dst_addr()),
                packet.payload(),
            )
        }
        _ => return None,
    };
    if payload.len() < 8 {
        return None;
    }
    let udp = UdpPacket::new_unchecked(payload);
    if udp.src_port() == 0 || udp.dst_port() == 0 {
        return None;
    }
    Some(PacketUdpTuple {
        source: IpEndpoint::new(source, udp.src_port()),
        destination: IpEndpoint::new(destination, udp.dst_port()),
    })
}

fn virtual_loopback_destination(packet: &[u8]) -> bool {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => packet.get(16).is_some_and(|first| *first == 127),
        Some(6) => packet.get(24..40) == Some(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        _ => false,
    }
}

#[derive(Debug, Error)]
pub enum StackError {
    #[error("stack resource budget is exhausted")]
    Resource,
    #[error("flow limit is exhausted")]
    FlowLimit,
    #[error("virtual port pool is exhausted")]
    PortLimit,
    #[error("flow handle is stale")]
    Stale,
    #[error("flow metadata is invalid")]
    Metadata,
    #[error("TCP operation failed: {0}")]
    Tcp(String),
    #[error("UDP operation failed")]
    Udp,
    #[error("stack is stopped")]
    Stopped,
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::task::{Context, Poll, Waker};

    use super::*;
    use crate::config::Config;
    use futures::io::{AsyncRead, AsyncWrite};

    fn bridge() -> StackBridge {
        let text = include_str!("../../../config/templates/snolc-server-low-memory.toml");
        let config = Config::parse(text, Path::new("/etc/snolc")).unwrap();
        StackBridge::new(
            config.stack,
            16,
            8 * 1024 * 1024,
            config.engine.max_ingress_packets_per_tick,
        )
        .unwrap()
    }

    fn shared_bridge() -> SharedStackBridge {
        let text = include_str!("../../../config/templates/snolc-server-low-memory.toml");
        let config = Config::parse(text, Path::new("/etc/snolc")).unwrap();
        SharedStackBridge::new(
            config.stack,
            16,
            8 * 1024 * 1024,
            config.engine.max_ingress_packets_per_tick,
        )
        .unwrap()
    }

    fn metadata() -> FlowMetadata {
        FlowMetadata {
            destination: Destination::Domain("example.com".into()),
            port: 443,
            opaque: Vec::new(),
        }
    }

    #[test]
    fn stopped_device_stops_tcp_exchange() {
        let mut bridge = bridge();
        let flow = bridge.open_tcp(metadata()).unwrap();
        bridge.stop_device();
        assert_eq!(bridge.tcp_send_adapter(flow, b"blocked").unwrap(), 7);
        for _ in 0..16 {
            bridge.poll();
        }
        let mut output = [0; 16];
        assert_eq!(bridge.tcp_recv_policy(flow, &mut output).unwrap(), 0);
        bridge.start_device();
        for _ in 0..16 {
            bridge.poll();
        }
        assert_eq!(bridge.tcp_recv_policy(flow, &mut output).unwrap(), 7);
        assert_eq!(&output[..7], b"blocked");
    }

    #[test]
    fn udp_keeps_empty_and_maximum_datagrams() {
        let mut bridge = bridge();
        let flow = bridge.open_udp(metadata()).unwrap();
        for payload in [Vec::new(), vec![1], vec![7; crate::wire::MAX_UDP_PAYLOAD]] {
            bridge.udp_send_adapter(flow, &payload).unwrap();
            for _ in 0..128 {
                bridge.poll();
            }
            let mut output = vec![0; crate::wire::MAX_UDP_PAYLOAD];
            assert_eq!(
                bridge.udp_recv_policy(flow, &mut output).unwrap(),
                DatagramRead::Datagram(payload.len())
            );
            assert_eq!(&output[..payload.len()], payload);
        }
    }

    #[test]
    fn small_udp_buffer_does_not_consume_datagram() {
        let mut bridge = bridge();
        let flow = bridge.open_udp(metadata()).unwrap();
        bridge.udp_send_adapter(flow, b"four").unwrap();
        for _ in 0..4 {
            bridge.poll();
        }
        assert_eq!(
            bridge.udp_recv_policy(flow, &mut [0; 3]).unwrap(),
            DatagramRead::BufferTooSmall(4)
        );
        let mut output = [0; 4];
        assert_eq!(
            bridge.udp_recv_policy(flow, &mut output).unwrap(),
            DatagramRead::Datagram(4)
        );
        assert_eq!(&output, b"four");
    }

    #[test]
    fn stale_handle_cannot_reach_reused_flow() {
        let mut bridge = bridge();
        let first = bridge.open_tcp(metadata()).unwrap();
        bridge.close_tcp(first).unwrap();
        let second = bridge.open_tcp(metadata()).unwrap();
        assert_ne!(first, second);
        assert!(matches!(bridge.tcp_metadata(first), Err(StackError::Stale)));
    }

    #[test]
    fn bounded_device_routes_loopback_and_external_packets_separately() {
        let mut device = BoundedDevice::new(1280, 4096);
        let mut external = vec![0; 20];
        external[0] = 0x45;
        external[16..20].copy_from_slice(&[203, 0, 113, 1]);
        device
            .transmit(Instant::from_millis(0))
            .unwrap()
            .consume(external.len(), |packet| packet.copy_from_slice(&external));
        assert_eq!(device.egress.pop_front(), Some(external));
        let mut loopback = vec![0; 20];
        loopback[0] = 0x45;
        loopback[16..20].copy_from_slice(&[127, 0, 0, 1]);
        device
            .transmit(Instant::from_millis(0))
            .unwrap()
            .consume(loopback.len(), |packet| packet.copy_from_slice(&loopback));
        assert_eq!(
            device.ingress.pop_front().map(|packet| packet.bytes),
            Some(loopback)
        );
    }

    #[test]
    fn packet_port_preserves_packet_boundaries_and_required_length() {
        let bridge = shared_bridge();
        let mut port = bridge.packet_port();
        let mut context = Context::from_waker(Waker::noop());
        let mut packet = vec![0; 20];
        packet[0] = 0x45;
        packet[16..20].copy_from_slice(&[203, 0, 113, 1]);
        assert!(matches!(
            port.poll_send_datagram(&mut context, &packet),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(
            bridge
                .inner
                .borrow()
                .device
                .ingress
                .front()
                .map(|queued| &queued.bytes),
            Some(&packet)
        );
        {
            let mut inner = bridge.inner.borrow_mut();
            inner.device.egress.push_back(packet.clone());
            inner.device.bytes += packet.len();
        }
        assert!(matches!(
            port.poll_recv_datagram(&mut context, &mut [0; 19]),
            Poll::Ready(Ok(DatagramRecv::BufferTooSmall(20)))
        ));
        let mut output = [0; 20];
        assert!(matches!(
            port.poll_recv_datagram(&mut context, &mut output),
            Poll::Ready(Ok(DatagramRecv::Datagram(20)))
        ));
        assert_eq!(output.as_slice(), packet);
    }

    #[test]
    fn packet_tcp_listener_uses_full_tuple_and_exposes_smoltcp_stream() {
        let server = shared_bridge();
        let mut client_device = BoundedDevice::new(1280, 262_144);
        let mut client_interface = Interface::new(
            InterfaceConfig::new(HardwareAddress::Ip),
            &mut client_device,
            Instant::from_millis(0),
        );
        client_interface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(IpAddress::v4(10, 0, 0, 2), 24))
                .unwrap();
        });
        client_interface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(10, 0, 0, 1))
            .unwrap();
        let mut client_sockets = SocketSet::new(Vec::new());
        let first = client_sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 4096]),
            tcp::SocketBuffer::new(vec![0; 4096]),
        ));
        let second = client_sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 4096]),
            tcp::SocketBuffer::new(vec![0; 4096]),
        ));
        let destination = IpEndpoint::new(IpAddress::v4(203, 0, 113, 9), 443);
        {
            let context = client_interface.context();
            client_sockets
                .get_mut::<tcp::Socket>(first)
                .connect(context, destination, 40_001)
                .unwrap();
        }
        {
            let context = client_interface.context();
            client_sockets
                .get_mut::<tcp::Socket>(second)
                .connect(context, destination, 40_002)
                .unwrap();
        }
        for tick in 0..128 {
            poll_fixture_client(
                &mut client_interface,
                &mut client_device,
                &mut client_sockets,
                tick,
            );
            move_egress_to_ingress(&mut client_device, &mut server.inner.borrow_mut().device);
            server.poll();
            move_egress_to_ingress(&mut server.inner.borrow_mut().device, &mut client_device);
            if client_sockets.get::<tcp::Socket>(first).state() == tcp::State::Established
                && client_sockets.get::<tcp::Socket>(second).state() == tcp::State::Established
            {
                break;
            }
        }
        assert_eq!(
            client_sockets.get::<tcp::Socket>(first).state(),
            tcp::State::Established
        );
        assert_eq!(
            client_sockets.get::<tcp::Socket>(second).state(),
            tcp::State::Established
        );
        let (first_metadata, mut first_server) = server.accept_packet_tcp().unwrap().unwrap();
        let (second_metadata, mut second_server) = server.accept_packet_tcp().unwrap().unwrap();
        assert_eq!(
            first_metadata.destination,
            Destination::Ipv4("203.0.113.9".parse().unwrap())
        );
        assert_eq!(second_metadata.port, 443);

        client_sockets
            .get_mut::<tcp::Socket>(first)
            .send_slice(b"first-tuple")
            .unwrap();
        client_sockets
            .get_mut::<tcp::Socket>(second)
            .send_slice(b"secondtuple")
            .unwrap();
        let mut first_output = [0; 11];
        let mut second_output = [0; 11];
        let mut first_read = false;
        let mut second_read = false;
        let mut context = Context::from_waker(Waker::noop());
        for tick in 128..256 {
            poll_fixture_client(
                &mut client_interface,
                &mut client_device,
                &mut client_sockets,
                tick,
            );
            move_egress_to_ingress(&mut client_device, &mut server.inner.borrow_mut().device);
            server.poll();
            move_egress_to_ingress(&mut server.inner.borrow_mut().device, &mut client_device);
            if !first_read {
                first_read = matches!(
                    Pin::new(&mut first_server).poll_read(&mut context, &mut first_output),
                    Poll::Ready(Ok(11))
                );
            }
            if !second_read {
                second_read = matches!(
                    Pin::new(&mut second_server).poll_read(&mut context, &mut second_output),
                    Poll::Ready(Ok(11))
                );
            }
            if first_read && second_read {
                break;
            }
        }
        let mut outputs = [first_output, second_output];
        outputs.sort();
        assert_eq!(outputs, [*b"first-tuple", *b"secondtuple"]);
    }

    #[test]
    fn packet_udp_demuxes_full_tuple_and_preserves_datagrams() {
        let server = shared_bridge();
        let mut client_device = BoundedDevice::new(1280, 262_144);
        let mut client_interface = Interface::new(
            InterfaceConfig::new(HardwareAddress::Ip),
            &mut client_device,
            Instant::from_millis(0),
        );
        client_interface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(IpAddress::v4(10, 0, 0, 2), 24))
                .unwrap();
        });
        client_interface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(10, 0, 0, 1))
            .unwrap();
        let mut client_sockets = SocketSet::new(Vec::new());
        let first = client_sockets.add(fixture_udp_socket());
        let second = client_sockets.add(fixture_udp_socket());
        client_sockets
            .get_mut::<udp::Socket>(first)
            .bind(40_001)
            .unwrap();
        client_sockets
            .get_mut::<udp::Socket>(second)
            .bind(40_002)
            .unwrap();
        let destination = IpEndpoint::new(IpAddress::v4(203, 0, 113, 9), 53);
        client_sockets
            .get_mut::<udp::Socket>(first)
            .send_slice(b"first", destination)
            .unwrap();
        client_sockets
            .get_mut::<udp::Socket>(second)
            .send_slice(b"second", destination)
            .unwrap();
        for tick in 0..32 {
            poll_fixture_client(
                &mut client_interface,
                &mut client_device,
                &mut client_sockets,
                tick,
            );
            move_egress_to_ingress(&mut client_device, &mut server.inner.borrow_mut().device);
            server.poll();
            if server.inner.borrow().pending_packet_udp.len() == 2 {
                break;
            }
        }
        let (first_metadata, mut first_server) = server.accept_packet_udp().unwrap().unwrap();
        let (second_metadata, mut second_server) = server.accept_packet_udp().unwrap().unwrap();
        assert_eq!(
            first_metadata.destination,
            Destination::Ipv4("203.0.113.9".parse().unwrap())
        );
        assert_eq!(second_metadata.port, 53);
        let mut context = Context::from_waker(Waker::noop());
        let mut first_payload = [0; 6];
        let mut second_payload = [0; 6];
        let first_length = match first_server.poll_recv_datagram(&mut context, &mut first_payload) {
            Poll::Ready(Ok(DatagramRecv::Datagram(length))) => length,
            result => panic!("unexpected first UDP result: {result:?}"),
        };
        let second_length =
            match second_server.poll_recv_datagram(&mut context, &mut second_payload) {
                Poll::Ready(Ok(DatagramRecv::Datagram(length))) => length,
                result => panic!("unexpected second UDP result: {result:?}"),
            };
        let mut payloads = [
            first_payload[..first_length].to_vec(),
            second_payload[..second_length].to_vec(),
        ];
        payloads.sort();
        assert_eq!(payloads, [b"first".to_vec(), b"second".to_vec()]);

        assert!(matches!(
            first_server.poll_send_datagram(&mut context, b"reply"),
            Poll::Ready(Ok(()))
        ));
        for tick in 32..64 {
            server.poll();
            move_egress_to_ingress(&mut server.inner.borrow_mut().device, &mut client_device);
            poll_fixture_client(
                &mut client_interface,
                &mut client_device,
                &mut client_sockets,
                tick,
            );
            if client_sockets.get::<udp::Socket>(first).can_recv()
                || client_sockets.get::<udp::Socket>(second).can_recv()
            {
                break;
            }
        }
        let mut response = [0; 5];
        let sockets = [&first, &second];
        let received = sockets.into_iter().find_map(|handle| {
            let socket = client_sockets.get_mut::<udp::Socket>(*handle);
            socket
                .can_recv()
                .then(|| socket.recv_slice(&mut response).unwrap().0)
        });
        assert_eq!(received, Some(5));
        assert_eq!(&response, b"reply");
    }

    fn fixture_udp_socket() -> udp::Socket<'static> {
        udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 4096]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 4096]),
        )
    }

    fn poll_fixture_client(
        interface: &mut Interface,
        device: &mut BoundedDevice,
        sockets: &mut SocketSet<'static>,
        tick: i64,
    ) {
        let now = Instant::from_millis(tick);
        interface.poll_maintenance(now);
        for _ in 0..32 {
            if matches!(
                interface.poll_ingress_single(now, device, sockets),
                PollIngressSingleResult::None
            ) {
                break;
            }
        }
        let _ = interface.poll_egress(now, device, sockets);
    }

    fn move_egress_to_ingress(source: &mut BoundedDevice, destination: &mut BoundedDevice) {
        while let Some(packet) = source.egress.pop_front() {
            source.bytes -= packet.len();
            destination.bytes += packet.len();
            destination.ingress.push_back(QueuedPacket {
                bytes: packet,
                external: true,
            });
        }
    }

    #[test]
    fn async_ports_exchange_and_release_the_same_flow() {
        let bridge = shared_bridge();
        let (mut adapter, mut policy) = bridge.open_tcp(metadata()).unwrap();
        let allocated = bridge.managed_bytes();
        assert!(allocated > 0);
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(
            Pin::new(&mut adapter).poll_write(&mut context, b"through-stack"),
            Poll::Ready(Ok(13))
        ));
        let mut output = [0; 13];
        for _ in 0..16 {
            bridge.poll();
            if let Poll::Ready(Ok(13)) = Pin::new(&mut policy).poll_read(&mut context, &mut output)
            {
                break;
            }
        }
        assert_eq!(&output, b"through-stack");
        assert_eq!(adapter.metadata().unwrap(), metadata());
        drop(adapter);
        assert_eq!(bridge.managed_bytes(), allocated);
        drop(policy);
        assert_eq!(bridge.managed_bytes(), 0);
    }

    #[test]
    fn async_udp_ports_preserve_atomic_datagrams_and_release_flow() {
        let bridge = shared_bridge();
        let (mut adapter, mut policy) = bridge.open_udp(metadata()).unwrap();
        let allocated = bridge.managed_bytes();
        let mut context = Context::from_waker(Waker::noop());
        for payload in [Vec::new(), vec![1], vec![7; crate::wire::MAX_UDP_PAYLOAD]] {
            assert!(matches!(
                adapter.poll_send_datagram(&mut context, &payload),
                Poll::Ready(Ok(()))
            ));
            let mut output = vec![0; crate::wire::MAX_UDP_PAYLOAD];
            let mut received = None;
            for _ in 0..128 {
                bridge.poll();
                if let Poll::Ready(Ok(DatagramRecv::Datagram(length))) =
                    policy.poll_recv_datagram(&mut context, &mut output)
                {
                    received = Some(length);
                    break;
                }
            }
            assert_eq!(received, Some(payload.len()));
            assert_eq!(&output[..payload.len()], payload);
        }
        assert_eq!(adapter.metadata().unwrap(), metadata());
        drop(adapter);
        assert_eq!(bridge.managed_bytes(), allocated);
        drop(policy);
        assert_eq!(bridge.managed_bytes(), 0);
    }
}
