use std::cell::RefCell;
use std::collections::VecDeque;
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
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
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

pub struct StackBridge {
    interface: Interface,
    device: BoundedDevice,
    sockets: SocketSet<'static>,
    tcp_flows: HandleTable<TcpFlow>,
    udp_flows: HandleTable<UdpFlow>,
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

struct TcpFlowLease {
    bridge: Weak<RefCell<StackBridge>>,
    handle: TcpFlowHandle,
}

struct UdpFlowLease {
    bridge: Weak<RefCell<StackBridge>>,
    handle: UdpFlowHandle,
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
            Ok(DatagramRead::Datagram(length)) => {
                Poll::Ready(Ok(DatagramRecv::Datagram(length)))
            }
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
        Ok(Self {
            interface,
            device,
            sockets: SocketSet::new(Vec::new()),
            tcp_flows: HandleTable::new(1, max_flows),
            udp_flows: HandleTable::new(2, max_flows),
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
            if matches!(
                self.interface
                    .poll_ingress_single(now, &mut self.device, &mut self.sockets),
                PollIngressSingleResult::None
            ) {
                break;
            }
        }
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
    queue: VecDeque<Vec<u8>>,
    bytes: usize,
    byte_limit: usize,
    mtu: usize,
    stopped: bool,
    dropped: usize,
}

impl BoundedDevice {
    fn new(mtu: usize, byte_limit: usize) -> Self {
        Self {
            queue: VecDeque::new(),
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
    queue: &'a mut VecDeque<Vec<u8>>,
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
        let packet = self.queue.pop_front()?;
        self.bytes -= packet.len();
        Some((
            BoundedRxToken { packet },
            BoundedTxToken {
                queue: &mut self.queue,
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
            queue: &mut self.queue,
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
            self.queue.push_back(packet);
        } else {
            *self.dropped += 1;
        }
        result
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
