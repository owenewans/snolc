#![cfg(target_os = "linux")]

use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use russh::keys::ssh_key::LineEnding;
use russh::keys::{Algorithm, PrivateKey};
use sha2::{Digest, Sha256};
use smoltcp::iface::{Config as InterfaceConfig, Interface, PollIngressSingleResult, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};
use snolc::config::Config;
use snolc::loader::LoadedModule;
use snolc::module_config::ModuleConfig;
use snolc::{Engine, Event, Host, Lifecycle, PlatformEvent};
use snow::{Builder, params::NoiseParams};

struct QuietHost;

impl Host for QuietHost {
    fn engine_event(&self, _event: &Event) {}
}

#[test]
fn official_module_templates_pass_native_validation() {
    let root = std::env::temp_dir().join(format!(
        "snolc-module-templates-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    let ssh_private = root.join("ssh-private");
    let ssh_public = root.join("ssh-public");
    let private = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    fs::write(
        &ssh_private,
        private.to_openssh(LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();
    fs::write(&ssh_public, private.public_key().to_openssh().unwrap()).unwrap();
    let noise_private = root.join("noise-private");
    let noise_public = root.join("noise-public");
    fs::write(&noise_private, [7; 32]).unwrap();
    fs::write(&noise_public, [9; 32]).unwrap();
    let templates = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/templates/modules");
    for (file, library) in [
        ("direct.toml", "adapter_direct"),
        ("socks5.toml", "adapter_socks5"),
        ("http-connect.toml", "adapter_http_connect"),
        ("tun-linux.toml", "adapter_tun"),
        ("tun-android.toml", "adapter_tun"),
        ("protection-dummy.toml", "protection_dummy"),
        ("noise.toml", "protection_noise"),
        ("noise-client.toml", "protection_noise"),
        ("tcp.toml", "carrier_tcp"),
        ("tcp-client.toml", "carrier_tcp"),
        ("ssh.toml", "carrier_ssh"),
        ("ssh-client.toml", "carrier_ssh"),
        ("policy-dummy.toml", "policy_dummy"),
        ("policy.toml", "policy_local"),
        ("policy-client.toml", "policy_local"),
    ] {
        let path = templates.join(file);
        let input = fs::read_to_string(&path).unwrap();
        let mut config = ModuleConfig::parse(&input, &path).unwrap();
        match file {
            "noise.toml" => {
                config.options.insert(
                    "private_key_file".into(),
                    noise_private.to_string_lossy().into_owned().into(),
                );
            }
            "noise-client.toml" => {
                config.options.insert(
                    "server_public_key_file".into(),
                    noise_public.to_string_lossy().into_owned().into(),
                );
            }
            "ssh.toml" => {
                config.options.insert(
                    "host_key".into(),
                    ssh_private.to_string_lossy().into_owned().into(),
                );
                config.options["auth"].as_table_mut().unwrap().insert(
                    "public_key".into(),
                    ssh_public.to_string_lossy().into_owned().into(),
                );
            }
            "ssh-client.toml" => {
                config.options.insert(
                    "server_host_key".into(),
                    ssh_public.to_string_lossy().into_owned().into(),
                );
                config.options["auth"].as_table_mut().unwrap().insert(
                    "private_key".into(),
                    ssh_private.to_string_lossy().into_owned().into(),
                );
            }
            "policy-client.toml" => {
                config.options["client"]["credential"] = toml::Value::Table(
                    [
                        ("source".into(), "toml".into()),
                        ("value".into(), "00".repeat(32).into()),
                    ]
                    .into_iter()
                    .collect(),
                );
            }
            _ => {}
        }
        LoadedModule::load(
            format!("template-{file}"),
            &module_library(library),
            config.options_toml().unwrap(),
            &config.base_directory,
            &path,
        )
        .unwrap_or_else(|error| panic!("{file}: {error}"));
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn native_tcp_dummy_path_establishes_policy_session() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    drop(listener);

    let server = build_side(
        "server-dummy",
        "server",
        endpoint,
        true,
        ("protection_dummy", b""),
        ("policy_dummy", b"pump_buffer_bytes = 4096\n"),
    );
    let client = build_side(
        "client-dummy",
        "client",
        endpoint,
        false,
        ("protection_dummy", b""),
        ("policy_dummy", b"pump_buffer_bytes = 4096\n"),
    );
    run_pair(server, client);
}

#[test]
fn platform_network_change_reconnects_and_vpn_revoke_stops() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    drop(listener);
    let server = build_side(
        "server-platform",
        "server",
        endpoint,
        true,
        ("protection_dummy", b""),
        ("policy_dummy", b"pump_buffer_bytes = 4096\n"),
    );
    let client = build_side(
        "client-platform",
        "client",
        endpoint,
        false,
        ("protection_dummy", b""),
        ("policy_dummy", b"pump_buffer_bytes = 4096\n"),
    );
    let (server_engine, server_handle) = Engine::build(server, QuietHost).unwrap();
    let (client_engine, client_handle) = Engine::build(client, QuietHost).unwrap();
    let mut events = client_handle.subscribe().unwrap();
    let server_thread = thread::spawn(move || server_engine.run());
    wait_running(&server_handle);
    let client_thread = thread::spawn(move || client_engine.run());
    wait_sessions(&server_handle, &client_handle);

    let mut established = 0;
    while let Ok(event) = events.try_recv() {
        if matches!(
            event,
            Event::Tunnel {
                state: "established",
                ..
            }
        ) {
            established += 1;
        }
    }
    assert_eq!(established, 1);
    client_handle
        .platform_event(PlatformEvent::NetworkChanged)
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut network_event = false;
    while established < 2 {
        while let Ok(event) = events.try_recv() {
            network_event |= matches!(event, Event::Platform(PlatformEvent::NetworkChanged));
            if matches!(
                event,
                Event::Tunnel {
                    state: "established",
                    ..
                }
            ) {
                established += 1;
            }
        }
        assert!(Instant::now() < deadline, "network reconnect timed out");
        thread::sleep(Duration::from_millis(10));
    }
    assert!(network_event);
    assert_eq!(client_handle.snapshot().sessions, 1);

    client_handle
        .platform_event(PlatformEvent::VpnPermissionRevoked)
        .unwrap();
    client_thread.join().unwrap().unwrap();
    assert_eq!(client_handle.snapshot().lifecycle, Lifecycle::Stopped);
    server_handle.shutdown().unwrap();
    server_thread.join().unwrap().unwrap();
}

#[test]
fn native_ssh_carrier_establishes_policy_session() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    drop(listener);
    let directory = std::env::temp_dir().join(format!(
        "snolc-native-ssh-{}-{}",
        std::process::id(),
        endpoint.port()
    ));
    fs::create_dir_all(&directory).unwrap();
    let private_path = directory.join("host");
    let public_path = directory.join("host.pub");
    let private = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    fs::write(
        &private_path,
        private.to_openssh(LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();
    fs::write(&public_path, private.public_key().to_openssh().unwrap()).unwrap();
    let server_carrier = format!(
        "mode = \"listen\"\nendpoint_ip = \"{endpoint}\"\nusername = \"snolc\"\nhost_key = \"{}\"\nmax_connections = 2\nqueue_chunks = 8\nchunk_bytes = 16384\ninactivity_timeout_ms = 15000\n\n[auth]\nmode = \"password\"\npassword = \"secret\"\n",
        private_path.display()
    );
    let client_carrier = format!(
        "mode = \"connect\"\nendpoint_ip = \"{endpoint}\"\nusername = \"snolc\"\nserver_host_key = \"{}\"\nmax_connections = 2\nqueue_chunks = 8\nchunk_bytes = 16384\ninactivity_timeout_ms = 15000\n\n[auth]\nmode = \"password\"\npassword = \"secret\"\n",
        public_path.display()
    );
    let server = build_side_with_carrier(
        "server-ssh",
        "server",
        ("carrier_ssh", server_carrier.as_bytes()),
        ("protection_dummy", b""),
        ("policy_dummy", b"pump_buffer_bytes = 4096\n"),
    );
    let client = build_side_with_carrier(
        "client-ssh",
        "client",
        ("carrier_ssh", client_carrier.as_bytes()),
        ("protection_dummy", b""),
        ("policy_dummy", b"pump_buffer_bytes = 4096\n"),
    );
    run_pair(server, client);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn native_tun_tcp_path_uses_packet_port_and_smoltcp() {
    let carrier_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let carrier_endpoint = carrier_listener.local_addr().unwrap();
    drop(carrier_listener);
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_endpoint = echo.local_addr().unwrap();
    let echo_thread = thread::spawn(move || {
        let (mut stream, _) = echo.accept().unwrap();
        let mut input = [0; 4];
        stream.read_exact(&mut input).unwrap();
        assert_eq!(&input, b"ping");
        stream.write_all(b"pong").unwrap();
    });
    let (module_tun, client_tun) = UnixDatagram::pair().unwrap();
    client_tun.set_nonblocking(true).unwrap();
    let adapter_options = format!(
        "mode = \"android-fd\"\nfd = {}\nmtu = 1280\npacket_queue_bytes = 262144\n",
        module_tun.as_raw_fd()
    );
    let server = build_side(
        "server-tun",
        "server",
        carrier_endpoint,
        true,
        ("protection_dummy", b""),
        ("policy_dummy", b"pump_buffer_bytes = 4096\n"),
    );
    let client = build_side_with_adapter(
        "client-tun",
        "client",
        carrier_endpoint,
        false,
        ("adapter_tun", adapter_options.as_bytes()),
        ("protection_dummy", b""),
        ("policy_dummy", b"pump_buffer_bytes = 4096\n"),
    );
    let (server_engine, server_handle) = Engine::build(server, QuietHost).unwrap();
    let (client_engine, client_handle) = Engine::build(client, QuietHost).unwrap();
    let server_thread = thread::spawn(move || server_engine.run());
    wait_running(&server_handle);
    let client_thread = thread::spawn(move || client_engine.run());
    wait_sessions(&server_handle, &client_handle);
    drop(module_tun);

    let mut device = TunFixtureDevice {
        socket: client_tun,
        mtu: 1280,
    };
    let mut interface = Interface::new(
        InterfaceConfig::new(HardwareAddress::Ip),
        &mut device,
        SmolInstant::from_millis(0),
    );
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::v4(10, 0, 0, 2), 24))
            .unwrap();
    });
    interface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(10, 0, 0, 1))
        .unwrap();
    let mut sockets = SocketSet::new(Vec::new());
    let socket = sockets.add(tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 16_384]),
        tcp::SocketBuffer::new(vec![0; 16_384]),
    ));
    let std::net::IpAddr::V4(echo_ip) = echo_endpoint.ip() else {
        panic!("fixture endpoint must use IPv4");
    };
    let [a, b, c, d] = echo_ip.octets();
    {
        let context = interface.context();
        sockets
            .get_mut::<tcp::Socket>(socket)
            .connect(
                context,
                IpEndpoint::new(
                    IpAddress::Ipv4(Ipv4Address::new(a, b, c, d)),
                    echo_endpoint.port(),
                ),
                40_001,
            )
            .unwrap();
    }
    let started = Instant::now();
    let deadline = started + Duration::from_secs(5);
    let mut sent = false;
    let mut output = [0; 4];
    loop {
        let now = SmolInstant::from_millis(started.elapsed().as_millis() as i64);
        interface.poll_maintenance(now);
        for _ in 0..32 {
            if matches!(
                interface.poll_ingress_single(now, &mut device, &mut sockets),
                PollIngressSingleResult::None
            ) {
                break;
            }
        }
        let _ = interface.poll_egress(now, &mut device, &mut sockets);
        let socket = sockets.get_mut::<tcp::Socket>(socket);
        if socket.state() == tcp::State::Established && !sent && socket.can_send() {
            assert_eq!(socket.send_slice(b"ping").unwrap(), 4);
            sent = true;
        }
        if socket.can_recv() && socket.recv_slice(&mut output).unwrap() == 4 {
            break;
        }
        assert!(Instant::now() < deadline, "TUN TCP exchange timed out");
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(&output, b"pong");
    client_handle.shutdown().unwrap();
    server_handle.shutdown().unwrap();
    client_thread.join().unwrap().unwrap();
    server_thread.join().unwrap().unwrap();
    echo_thread.join().unwrap();
}

#[test]
fn native_tun_udp_path_preserves_datagrams() {
    let carrier_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let carrier_endpoint = carrier_listener.local_addr().unwrap();
    drop(carrier_listener);
    let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
    let echo_endpoint = echo.local_addr().unwrap();
    let echo_thread = thread::spawn(move || {
        let mut input = vec![0; 65_507];
        for expected in [0, 1, 65_507] {
            let (length, peer) = echo.recv_from(&mut input).unwrap();
            assert_eq!(length, expected);
            assert!(input[..length].iter().all(|byte| *byte == expected as u8));
            echo.send_to(&input[..length], peer).unwrap();
        }
    });
    let (module_tun, client_tun) = UnixDatagram::pair().unwrap();
    client_tun.set_nonblocking(true).unwrap();
    let adapter_options = format!(
        "mode = \"android-fd\"\nfd = {}\nmtu = 1280\npacket_queue_bytes = 262144\n",
        module_tun.as_raw_fd()
    );
    let server = build_side(
        "server-tun-udp",
        "server",
        carrier_endpoint,
        true,
        ("protection_dummy", b""),
        ("policy_dummy", b"pump_buffer_bytes = 65507\n"),
    );
    let client = build_side_with_adapter(
        "client-tun-udp",
        "client",
        carrier_endpoint,
        false,
        ("adapter_tun", adapter_options.as_bytes()),
        ("protection_dummy", b""),
        ("policy_dummy", b"pump_buffer_bytes = 65507\n"),
    );
    let (server_engine, server_handle) = Engine::build(server, QuietHost).unwrap();
    let (client_engine, client_handle) = Engine::build(client, QuietHost).unwrap();
    let server_thread = thread::spawn(move || server_engine.run());
    wait_running(&server_handle);
    let client_thread = thread::spawn(move || client_engine.run());
    wait_sessions(&server_handle, &client_handle);
    drop(module_tun);

    let mut device = TunFixtureDevice {
        socket: client_tun,
        mtu: 1280,
    };
    let mut interface = Interface::new(
        InterfaceConfig::new(HardwareAddress::Ip),
        &mut device,
        SmolInstant::from_millis(0),
    );
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::v4(10, 0, 0, 2), 24))
            .unwrap();
    });
    interface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(10, 0, 0, 1))
        .unwrap();
    let mut sockets = SocketSet::new(Vec::new());
    let socket = sockets.add(tun_fixture_udp_socket());
    sockets
        .get_mut::<smoltcp::socket::udp::Socket>(socket)
        .bind(40_001)
        .unwrap();
    let std::net::IpAddr::V4(echo_ip) = echo_endpoint.ip() else {
        panic!("fixture endpoint must use IPv4");
    };
    let [a, b, c, d] = echo_ip.octets();
    let destination = IpEndpoint::new(
        IpAddress::Ipv4(Ipv4Address::new(a, b, c, d)),
        echo_endpoint.port(),
    );
    let started = Instant::now();
    for length in [0, 1, 65_507] {
        let payload = vec![length as u8; length];
        sockets
            .get_mut::<smoltcp::socket::udp::Socket>(socket)
            .send_slice(&payload, destination)
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut output = vec![0; 65_507];
        loop {
            let now = SmolInstant::from_millis(started.elapsed().as_millis() as i64);
            interface.poll_maintenance(now);
            for _ in 0..32 {
                if matches!(
                    interface.poll_ingress_single(now, &mut device, &mut sockets),
                    PollIngressSingleResult::None
                ) {
                    break;
                }
            }
            let _ = interface.poll_egress(now, &mut device, &mut sockets);
            let socket = sockets.get_mut::<smoltcp::socket::udp::Socket>(socket);
            if socket.can_recv() {
                let (received, peer) = socket.recv_slice(&mut output).unwrap();
                assert_eq!(received, length);
                assert_eq!(peer.endpoint, destination);
                assert_eq!(&output[..received], payload);
                break;
            }
            assert!(Instant::now() < deadline, "TUN UDP exchange timed out");
            thread::sleep(Duration::from_millis(1));
        }
    }
    client_handle.shutdown().unwrap();
    server_handle.shutdown().unwrap();
    client_thread.join().unwrap().unwrap();
    server_thread.join().unwrap().unwrap();
    echo_thread.join().unwrap();
}

fn tun_fixture_udp_socket() -> smoltcp::socket::udp::Socket<'static> {
    smoltcp::socket::udp::Socket::new(
        smoltcp::socket::udp::PacketBuffer::new(
            vec![smoltcp::socket::udp::PacketMetadata::EMPTY; 8],
            vec![0; 131_072],
        ),
        smoltcp::socket::udp::PacketBuffer::new(
            vec![smoltcp::socket::udp::PacketMetadata::EMPTY; 8],
            vec![0; 131_072],
        ),
    )
}

struct TunFixtureDevice {
    socket: UnixDatagram,
    mtu: usize,
}

struct TunFixtureRx(Vec<u8>);

struct TunFixtureTx<'a>(&'a UnixDatagram);

impl Device for TunFixtureDevice {
    type RxToken<'a> = TunFixtureRx;
    type TxToken<'a> = TunFixtureTx<'a>;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let mut packet = vec![0; self.mtu];
        match self.socket.recv(&mut packet) {
            Ok(length) => {
                packet.truncate(length);
                Some((TunFixtureRx(packet), TunFixtureTx(&self.socket)))
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => None,
            Err(error) => panic!("TUN fixture receive failed: {error}"),
        }
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TunFixtureTx(&self.socket))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities.checksum = ChecksumCapabilities::ignored();
        capabilities
    }
}

impl RxToken for TunFixtureRx {
    fn consume<R, F>(self, function: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        function(&self.0)
    }
}

impl TxToken for TunFixtureTx<'_> {
    fn consume<R, F>(self, length: usize, function: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; length];
        let result = function(&mut packet);
        assert_eq!(self.0.send(&packet).unwrap(), packet.len());
        result
    }
}

#[test]
fn native_tcp_noise_path_establishes_authenticated_policy_session() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    drop(listener);
    let params: NoiseParams = "Noise_NK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
    let keypair = Builder::new(params).generate_keypair().unwrap();
    let directory = std::env::temp_dir().join(format!(
        "snolc-native-noise-{}-{}",
        std::process::id(),
        endpoint.port()
    ));
    fs::create_dir_all(&directory).unwrap();
    let private = directory.join("server.key");
    let public = directory.join("server.pub");
    fs::write(&private, keypair.private).unwrap();
    fs::write(&public, keypair.public).unwrap();
    let server_options = format!(
        "mode = \"server\"\nprivate_key_file = \"{}\"\n",
        private.display()
    );
    let client_options = format!(
        "mode = \"client\"\nserver_public_key_file = \"{}\"\n",
        public.display()
    );
    let server = build_side(
        "server-noise",
        "server",
        endpoint,
        true,
        ("protection_noise", server_options.as_bytes()),
        ("policy_dummy", b"pump_buffer_bytes = 4096\n"),
    );
    let client = build_side(
        "client-noise",
        "client",
        endpoint,
        false,
        ("protection_noise", client_options.as_bytes()),
        ("policy_dummy", b"pump_buffer_bytes = 4096\n"),
    );
    run_pair(server, client);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn native_noise_policy_local_opens_private_storage_and_session() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    drop(listener);
    let params: NoiseParams = "Noise_NK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
    let keypair = Builder::new(params).generate_keypair().unwrap();
    let directory = std::env::temp_dir().join(format!(
        "snolc-native-local-{}-{}",
        std::process::id(),
        endpoint.port()
    ));
    fs::create_dir_all(&directory).unwrap();
    let private = directory.join("server.key");
    let public = directory.join("server.pub");
    fs::write(&private, keypair.private).unwrap();
    fs::write(&public, keypair.public).unwrap();
    let server_protection = format!(
        "mode = \"server\"\nprivate_key_file = \"{}\"\n",
        private.display()
    );
    let client_protection = format!(
        "mode = \"client\"\nserver_public_key_file = \"{}\"\n",
        public.display()
    );
    let credential = "ab".repeat(32);
    let credential_digest = format!("{:x}", Sha256::digest(hex_bytes(&credential)));
    let server_policy = policy_local_options(&directory.join("server-state/policy.redb"), None);
    let client_policy = policy_local_options(
        &directory.join("client-state/policy.redb"),
        Some(&credential),
    );
    let server = build_side(
        "server-local",
        "server",
        endpoint,
        true,
        ("protection_noise", server_protection.as_bytes()),
        ("policy_local", server_policy.as_bytes()),
    );
    let client = build_side(
        "client-local",
        "client",
        endpoint,
        false,
        ("protection_noise", client_protection.as_bytes()),
        ("policy_local", client_policy.as_bytes()),
    );
    run_authenticated_pair(server, client, &credential_digest);
    assert!(directory.join("server-state/policy.redb").is_file());
    assert!(directory.join("client-state/policy.redb").is_file());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn native_socks_tcp_payload_crosses_stack_mux_and_direct_adapter() {
    let carrier_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let carrier_endpoint = carrier_listener.local_addr().unwrap();
    drop(carrier_listener);
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let target_endpoint = target.local_addr().unwrap();
    let target_thread = thread::spawn(move || {
        let (mut stream, _) = target.accept().unwrap();
        let mut input = [0; 13];
        stream.read_exact(&mut input).unwrap();
        assert_eq!(&input, b"stack-payload");
        stream.write_all(b"direct-reply").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });
    let socks_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let socks_endpoint = socks_listener.local_addr().unwrap();
    drop(socks_listener);
    let policy = ("policy_dummy", b"pump_buffer_bytes = 4096\n".as_slice());
    let server = build_side(
        "server-flow",
        "server",
        carrier_endpoint,
        true,
        ("protection_dummy", b""),
        policy,
    );
    let socks_options = format!(
        "listen = \"{socks_endpoint}\"\nmax_connections = 4\nmax_udp_associations = 2\nmax_request_bytes = 1024\nreject_fragments = true\n"
    );
    let client = build_side_with_adapter(
        "client-flow",
        "client",
        carrier_endpoint,
        false,
        ("adapter_socks5", socks_options.as_bytes()),
        ("protection_dummy", b""),
        policy,
    );
    let (server_engine, server_handle) = Engine::build(server, QuietHost).unwrap();
    let (client_engine, client_handle) = Engine::build(client, QuietHost).unwrap();
    let server_thread = thread::spawn(move || server_engine.run());
    wait_running(&server_handle);
    let client_thread = thread::spawn(move || client_engine.run());
    wait_sessions(&server_handle, &client_handle);

    let mut socks = TcpStream::connect(socks_endpoint).unwrap();
    socks
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socks.write_all(&[5, 1, 0]).unwrap();
    let mut greeting = [0; 2];
    socks.read_exact(&mut greeting).unwrap();
    assert_eq!(greeting, [5, 0]);
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&[127, 0, 0, 1]);
    request.extend_from_slice(&target_endpoint.port().to_be_bytes());
    request.extend_from_slice(b"stack-payload");
    socks.write_all(&request).unwrap();
    let mut response = [0; 10];
    socks.read_exact(&mut response).unwrap();
    assert_eq!(response[1], 0);
    let mut reply = [0; 12];
    socks.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"direct-reply");

    let deadline = Instant::now() + Duration::from_secs(5);
    while (client_handle.snapshot().flows != 1 || server_handle.snapshot().flows != 1)
        && Instant::now() < deadline
    {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(client_handle.snapshot().flows, 1);
    assert_eq!(server_handle.snapshot().flows, 1);
    socks.shutdown(Shutdown::Both).unwrap();
    while client_handle.snapshot().flows != 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(client_handle.snapshot().flows, 0);
    target_thread.join().unwrap();
    client_handle.shutdown().unwrap();
    server_handle.shutdown().unwrap();
    client_thread.join().unwrap().unwrap();
    server_thread.join().unwrap().unwrap();
}

#[test]
fn native_http_connect_preserves_early_payload() {
    let carrier_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let carrier_endpoint = carrier_listener.local_addr().unwrap();
    drop(carrier_listener);
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let target_endpoint = target.local_addr().unwrap();
    let target_thread = thread::spawn(move || {
        let (mut stream, _) = target.accept().unwrap();
        let mut input = [0; 10];
        stream.read_exact(&mut input).unwrap();
        assert_eq!(&input, b"http-early");
        stream.write_all(b"http-reply").unwrap();
    });
    let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_endpoint = proxy_listener.local_addr().unwrap();
    drop(proxy_listener);
    let policy = ("policy_dummy", b"pump_buffer_bytes = 4096\n".as_slice());
    let server = build_side(
        "server-http",
        "server",
        carrier_endpoint,
        true,
        ("protection_dummy", b""),
        policy,
    );
    let options =
        format!("listen = \"{proxy_endpoint}\"\nmax_connections = 4\nmax_header_bytes = 4096\n");
    let client = build_side_with_adapter(
        "client-http",
        "client",
        carrier_endpoint,
        false,
        ("adapter_http_connect", options.as_bytes()),
        ("protection_dummy", b""),
        policy,
    );
    let (server_engine, server_handle) = Engine::build(server, QuietHost).unwrap();
    let (client_engine, client_handle) = Engine::build(client, QuietHost).unwrap();
    let server_thread = thread::spawn(move || server_engine.run());
    wait_running(&server_handle);
    let client_thread = thread::spawn(move || client_engine.run());
    wait_sessions(&server_handle, &client_handle);

    let mut proxy = TcpStream::connect(proxy_endpoint).unwrap();
    proxy
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    proxy
        .write_all(
            format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: ignored\r\n\r\nhttp-early",
                target_endpoint.port()
            )
            .as_bytes(),
        )
        .unwrap();
    let mut response = Vec::new();
    while !response.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        proxy.read_exact(&mut byte).unwrap();
        response.push(byte[0]);
        assert!(response.len() < 4096);
    }
    assert!(response.starts_with(b"HTTP/1.1 200 "));
    let mut reply = [0; 10];
    proxy.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"http-reply");
    proxy.shutdown(Shutdown::Both).unwrap();
    target_thread.join().unwrap();
    client_handle.shutdown().unwrap();
    server_handle.shutdown().unwrap();
    client_thread.join().unwrap().unwrap();
    server_thread.join().unwrap().unwrap();
}

#[test]
fn native_socks_udp_preserves_datagram_boundaries() {
    let carrier_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let carrier_endpoint = carrier_listener.local_addr().unwrap();
    drop(carrier_listener);
    let target = UdpSocket::bind("127.0.0.1:0").unwrap();
    let target_endpoint = target.local_addr().unwrap();
    target
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let payloads = [Vec::new(), vec![1], b"udp-through-stack".to_vec()];
    let expected = payloads.clone();
    let target_thread = thread::spawn(move || {
        let mut buffer = [0; 65_507];
        for payload in expected {
            let (length, source) = target.recv_from(&mut buffer).unwrap();
            assert_eq!(&buffer[..length], payload);
            target.send_to(&buffer[..length], source).unwrap();
        }
    });
    let socks_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let socks_endpoint = socks_listener.local_addr().unwrap();
    drop(socks_listener);
    let policy = ("policy_dummy", b"pump_buffer_bytes = 4096\n".as_slice());
    let server = build_side(
        "server-udp",
        "server",
        carrier_endpoint,
        true,
        ("protection_dummy", b""),
        policy,
    );
    let socks_options = format!(
        "listen = \"{socks_endpoint}\"\nmax_connections = 8\nmax_udp_associations = 2\nmax_request_bytes = 1024\nreject_fragments = true\n"
    );
    let client = build_side_with_adapter(
        "client-udp",
        "client",
        carrier_endpoint,
        false,
        ("adapter_socks5", socks_options.as_bytes()),
        ("protection_dummy", b""),
        policy,
    );
    let (server_engine, server_handle) = Engine::build(server, QuietHost).unwrap();
    let (client_engine, client_handle) = Engine::build(client, QuietHost).unwrap();
    let server_thread = thread::spawn(move || server_engine.run());
    wait_running(&server_handle);
    let client_thread = thread::spawn(move || client_engine.run());
    wait_sessions(&server_handle, &client_handle);

    let mut control = TcpStream::connect(socks_endpoint).unwrap();
    control
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    control.write_all(&[5, 1, 0]).unwrap();
    let mut greeting = [0; 2];
    control.read_exact(&mut greeting).unwrap();
    assert_eq!(greeting, [5, 0]);
    control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
    let mut response = [0; 10];
    control.read_exact(&mut response).unwrap();
    assert_eq!(response[..4], [5, 0, 0, 1]);
    let relay = std::net::SocketAddrV4::new(
        std::net::Ipv4Addr::new(response[4], response[5], response[6], response[7]),
        u16::from_be_bytes([response[8], response[9]]),
    );
    let client_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    client_udp
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    for payload in payloads {
        let mut packet = vec![0, 0, 0, 1, 127, 0, 0, 1];
        packet.extend_from_slice(&target_endpoint.port().to_be_bytes());
        packet.extend_from_slice(&payload);
        client_udp.send_to(&packet, relay).unwrap();
        let mut reply = [0; 65_535];
        let (length, _) = client_udp.recv_from(&mut reply).unwrap();
        assert!(length >= 10);
        assert_eq!(&reply[..8], &packet[..8]);
        assert_eq!(&reply[8..10], &target_endpoint.port().to_be_bytes());
        assert_eq!(&reply[10..length], payload);
    }
    target_thread.join().unwrap();
    drop(control);
    client_handle.shutdown().unwrap();
    server_handle.shutdown().unwrap();
    client_thread.join().unwrap().unwrap();
    server_thread.join().unwrap().unwrap();
}

#[test]
fn native_unix_control_dispatches_on_engine_thread() {
    let carrier_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let carrier_endpoint = carrier_listener.local_addr().unwrap();
    drop(carrier_listener);
    let root = std::env::temp_dir().join(format!(
        "snolc-native-control-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let socket = root.join("snolc.sock");
    let validated = build_side_with_control(
        "control",
        carrier_endpoint,
        &socket,
        ("protection_dummy", b""),
        ("policy_dummy", b"pump_buffer_bytes = 4096\n"),
    );
    let (engine, handle) = Engine::build(validated, QuietHost).unwrap();
    let thread = thread::spawn(move || engine.run());
    wait_running(&handle);
    let error =
        snolc::control::request(&socket, "policy-control", b"unsupported", 1024).unwrap_err();
    assert!(matches!(error, snolc::control::ControlError::Remote(_)));
    handle.shutdown().unwrap();
    thread.join().unwrap().unwrap();
    assert!(!socket.exists());
    std::fs::remove_dir(root).unwrap();
}

#[test]
fn native_policy_local_debits_before_forwarding_payload() {
    let carrier_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let carrier_endpoint = carrier_listener.local_addr().unwrap();
    drop(carrier_listener);
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let target_endpoint = target.local_addr().unwrap();
    let (release_target, target_release) = std::sync::mpsc::sync_channel(1);
    let target_thread = thread::spawn(move || {
        let (mut stream, _) = target.accept().unwrap();
        let mut input = [0; 12];
        stream.read_exact(&mut input).unwrap();
        assert_eq!(&input, b"quota-upload");
        stream.write_all(b"quota-down").unwrap();
        target_release.recv().unwrap();
    });
    let socks_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let socks_endpoint = socks_listener.local_addr().unwrap();
    drop(socks_listener);
    let directory = std::env::temp_dir().join(format!(
        "snolc-native-metered-{}-{}",
        std::process::id(),
        carrier_endpoint.port()
    ));
    fs::create_dir_all(&directory).unwrap();
    let params: NoiseParams = "Noise_NK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
    let keypair = Builder::new(params).generate_keypair().unwrap();
    let private = directory.join("server.key");
    let public = directory.join("server.pub");
    fs::write(&private, keypair.private).unwrap();
    fs::write(&public, keypair.public).unwrap();
    let server_protection = format!(
        "mode = \"server\"\nprivate_key_file = \"{}\"\n",
        private.display()
    );
    let client_protection = format!(
        "mode = \"client\"\nserver_public_key_file = \"{}\"\n",
        public.display()
    );
    let credential = "cd".repeat(32);
    let credential_digest = format!("{:x}", Sha256::digest(hex_bytes(&credential)));
    let server_policy = policy_local_options(&directory.join("server-state/policy.redb"), None);
    let client_policy = policy_local_options(
        &directory.join("client-state/policy.redb"),
        Some(&credential),
    );
    let server = build_side_with_adapter(
        "server-metered",
        "server",
        carrier_endpoint,
        true,
        (
            "adapter_direct",
            b"dns_mode = \"system\"\nmax_pending_opens = 8\nmax_resolved_addresses = 16\nresolve_timeout_ms = 1000\nconnect_timeout_ms = 1000\n",
        ),
        ("protection_noise", server_protection.as_bytes()),
        ("policy_local", server_policy.as_bytes()),
    );
    let socks_options = format!(
        "listen = \"{socks_endpoint}\"\nmax_connections = 4\nmax_udp_associations = 2\nmax_request_bytes = 1024\nreject_fragments = true\n"
    );
    let client = build_side_with_adapter(
        "client-metered",
        "client",
        carrier_endpoint,
        false,
        ("adapter_socks5", socks_options.as_bytes()),
        ("protection_noise", client_protection.as_bytes()),
        ("policy_local", client_policy.as_bytes()),
    );
    let (server_engine, server_handle) = Engine::build(server, QuietHost).unwrap();
    let (client_engine, client_handle) = Engine::build(client, QuietHost).unwrap();
    let server_thread = thread::spawn(move || server_engine.run());
    wait_running(&server_handle);
    let user_id = provision_user(&server_handle, "policy-server-metered", &credential_digest);
    let client_thread = thread::spawn(move || client_engine.run());
    wait_sessions(&server_handle, &client_handle);
    wait_user_session(&server_handle, "policy-server-metered", &user_id);
    wait_any_policy_session(&client_handle, "policy-client-metered");

    let mut socks = TcpStream::connect(socks_endpoint).unwrap();
    socks
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socks.write_all(&[5, 1, 0]).unwrap();
    let mut greeting = [0; 2];
    socks.read_exact(&mut greeting).unwrap();
    assert_eq!(greeting, [5, 0]);
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&target_endpoint.port().to_be_bytes());
    request.extend_from_slice(b"quota-upload");
    socks.write_all(&request).unwrap();
    let mut response = [0; 10];
    socks.read_exact(&mut response).unwrap_or_else(|error| {
        panic!(
            "CONNECT response failed: {error}; server={:?}; client={:?}",
            server_handle.snapshot(),
            client_handle.snapshot()
        )
    });
    assert_eq!(response[1], 0);
    let mut reply = [0; 10];
    socks.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"quota-down");

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let request = format!("method = \"usage.get\"\nuser_id = \"{user_id}\"\n");
        let response = futures::executor::block_on(
            server_handle.control("policy-server-metered", request.into_bytes()),
        )
        .unwrap();
        let usage: toml::Value = toml::from_str(std::str::from_utf8(&response).unwrap()).unwrap();
        if usage["upload_bytes"].as_integer() == Some(12)
            && usage["download_bytes"].as_integer() == Some(10)
        {
            assert_eq!(usage["used_bytes"].as_integer(), Some(1_048_576));
            break;
        }
        assert!(Instant::now() < deadline, "quota accounting timed out");
        thread::sleep(Duration::from_millis(10));
    }
    let rules = r#"terminal = "allow"
[[entries]]
action = "deny"
direction = "both"
protocol = "any"
unavailable = "deny"
cidr = "127.0.0.0/8"
[[entries]]
action = "deny"
direction = "both"
protocol = "any"
unavailable = "deny"
cidr = "::1/128"
"#;
    let rules_request = toml::to_string(&toml::Table::from_iter([
        ("method".into(), toml::Value::String("rules.replace".into())),
        (
            "client_id".into(),
            toml::Value::String("native-test".into()),
        ),
        ("seq".into(), toml::Value::Integer(3)),
        ("profile".into(), toml::Value::String("default".into())),
        ("apply".into(), toml::Value::String("active".into())),
        ("rules_toml".into(), toml::Value::String(rules.into())),
    ]))
    .unwrap();
    futures::executor::block_on(
        server_handle.control("policy-server-metered", rules_request.into_bytes()),
    )
    .unwrap();
    release_target.send(()).unwrap();
    target_thread.join().unwrap();
    socks.shutdown(Shutdown::Both).unwrap();
    while (client_handle.snapshot().flows != 0 || server_handle.snapshot().flows != 0)
        && Instant::now() < deadline
    {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(client_handle.snapshot().flows, 0);
    assert_eq!(server_handle.snapshot().flows, 0);

    let denied_target = TcpListener::bind("127.0.0.1:0").unwrap();
    denied_target.set_nonblocking(true).unwrap();
    let denied_endpoint = denied_target.local_addr().unwrap();
    let mut denied = TcpStream::connect(socks_endpoint).unwrap();
    denied
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    denied.write_all(&[5, 1, 0]).unwrap();
    denied.read_exact(&mut greeting).unwrap();
    let domain = b"localhost";
    let mut request = vec![5, 1, 0, 3, domain.len() as u8];
    request.extend_from_slice(domain);
    request.extend_from_slice(&denied_endpoint.port().to_be_bytes());
    denied.write_all(&request).unwrap();
    denied.read_exact(&mut response).unwrap();
    assert_ne!(response[1], 0);
    assert!(matches!(
        denied_target.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));

    let revoke = format!(
        "method = \"credential.revoke\"\nclient_id = \"native-test\"\nseq = 4\ncredential_sha256 = \"{credential_digest}\"\n"
    );
    futures::executor::block_on(
        server_handle.control("policy-server-metered", revoke.into_bytes()),
    )
    .unwrap();
    loop {
        let request = format!("method = \"usage.get\"\nuser_id = \"{user_id}\"\n");
        let response = futures::executor::block_on(
            server_handle.control("policy-server-metered", request.into_bytes()),
        )
        .unwrap();
        let usage: toml::Value = toml::from_str(std::str::from_utf8(&response).unwrap()).unwrap();
        if usage["used_bytes"].as_integer() == Some(22) {
            break;
        }
        assert!(Instant::now() < deadline, "quota refund timed out");
        thread::sleep(Duration::from_millis(10));
    }
    client_handle.shutdown().unwrap();
    server_handle.shutdown().unwrap();
    client_thread.join().unwrap().unwrap();
    server_thread.join().unwrap().unwrap();
    fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "60-minute release resource gate"]
fn release_resource_profile() {
    const FLOWS_PER_USER: usize = 8;
    const TOTAL_FLOWS: usize = FLOWS_PER_USER * 2;
    const MIB: u64 = 1024 * 1024;

    let duration = std::env::var("SNOLC_LONG_RUN_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(3600);
    let stored_users = std::env::var("SNOLC_STORED_USERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(10_000);
    let ceiling = std::env::var("SNOLC_RESOURCE_CEILING").as_deref() == Ok("1");
    assert!(duration > 0 && stored_users >= 2);

    let carrier_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let carrier_endpoint = carrier_listener.local_addr().unwrap();
    drop(carrier_listener);
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    target.set_nonblocking(true).unwrap();
    let target_endpoint = target.local_addr().unwrap();
    let socks_a = free_tcp_endpoint();
    let socks_b = free_tcp_endpoint();
    let directory = std::env::temp_dir().join(format!(
        "snolc-resource-{}-{}",
        std::process::id(),
        carrier_endpoint.port()
    ));
    fs::create_dir_all(&directory).unwrap();

    let params: NoiseParams = "Noise_NK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
    let keypair = Builder::new(params).generate_keypair().unwrap();
    let private = directory.join("server.key");
    let public = directory.join("server.pub");
    fs::write(&private, keypair.private).unwrap();
    fs::write(&public, keypair.public).unwrap();
    let server_protection = format!(
        "mode = \"server\"\nprivate_key_file = \"{}\"\n",
        private.display()
    );
    let client_protection = format!(
        "mode = \"client\"\nserver_public_key_file = \"{}\"\n",
        public.display()
    );
    let credential_a = "31".repeat(32);
    let credential_b = "72".repeat(32);
    let digest_a = format!("{:x}", Sha256::digest(hex_bytes(&credential_a)));
    let digest_b = format!("{:x}", Sha256::digest(hex_bytes(&credential_b)));
    let server_policy = policy_local_options(&directory.join("server/policy.redb"), None);
    let server_carrier = format!(
        "mode = \"listen\"\nendpoint_ip = \"{carrier_endpoint}\"\nmax_connections = 2\nnodelay = true\n"
    );
    let server = build_side_with_modules_and_tunnels(
        "server-resource",
        "server",
        (
            "adapter_direct",
            b"dns_mode = \"reject-domains\"\nmax_pending_opens = 8\nmax_resolved_addresses = 16\nresolve_timeout_ms = 1000\nconnect_timeout_ms = 1000\n",
        ),
        ("carrier_tcp", server_carrier.as_bytes()),
        ("protection_noise", server_protection.as_bytes()),
        ("policy_local", server_policy.as_bytes()),
        None,
        2,
    );
    let (server_engine, server_handle) = Engine::build(server, QuietHost).unwrap();
    let server_thread = thread::spawn(move || server_engine.run());
    wait_running(&server_handle);
    let users = provision_resource_users(
        &server_handle,
        "policy-server-resource",
        stored_users,
        [&digest_a, &digest_b],
        ceiling,
    );
    let idle_rss = process_rss_bytes();
    assert!(idle_rss <= 32 * MIB, "idle RSS is {idle_rss} bytes");
    let target_thread = thread::spawn(move || run_echo_target(target, TOTAL_FLOWS));

    let client_policy_a =
        policy_local_options(&directory.join("client-a/policy.redb"), Some(&credential_a));
    let client_policy_b =
        policy_local_options(&directory.join("client-b/policy.redb"), Some(&credential_b));
    let client_a = build_resource_client(
        "client-resource-a",
        carrier_endpoint,
        socks_a,
        &client_protection,
        &client_policy_a,
    );
    let client_b = build_resource_client(
        "client-resource-b",
        carrier_endpoint,
        socks_b,
        &client_protection,
        &client_policy_b,
    );
    let (client_a_engine, client_a_handle) = Engine::build(client_a, QuietHost).unwrap();
    let (client_b_engine, client_b_handle) = Engine::build(client_b, QuietHost).unwrap();
    let client_a_thread = thread::spawn(move || client_a_engine.run());
    let client_b_thread = thread::spawn(move || client_b_engine.run());
    wait_session_count(&server_handle, 2);
    wait_session_count(&client_a_handle, 1);
    wait_session_count(&client_b_handle, 1);
    wait_user_session(&server_handle, "policy-server-resource", &users[0]);
    wait_user_session(&server_handle, "policy-server-resource", &users[1]);
    wait_any_policy_session(&client_a_handle, "policy-client-resource-a");
    wait_any_policy_session(&client_b_handle, "policy-client-resource-b");

    let mut streams = Vec::with_capacity(TOTAL_FLOWS);
    for (endpoint, client) in [(socks_a, &client_a_handle), (socks_b, &client_b_handle)] {
        for index in 0..FLOWS_PER_USER {
            streams.push(open_socks_flow(
                endpoint,
                target_endpoint,
                index,
                &server_handle,
                client,
            ));
        }
    }
    wait_flow_count(&server_handle, TOTAL_FLOWS);
    wait_flow_count(&client_a_handle, FLOWS_PER_USER);
    wait_flow_count(&client_b_handle, FLOWS_PER_USER);

    let stop_sample = Arc::new(AtomicBool::new(false));
    let steady_rss = Arc::new(AtomicU64::new(process_rss_bytes()));
    let sample_thread = {
        let stop = stop_sample.clone();
        let maximum = steady_rss.clone();
        thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                maximum.fetch_max(process_rss_bytes(), Ordering::AcqRel);
                thread::sleep(Duration::from_millis(100));
            }
        })
    };
    let transferred = Arc::new(AtomicU64::new(0));
    let deadline = Instant::now() + Duration::from_secs(duration);
    let mut workers = Vec::with_capacity(TOTAL_FLOWS);
    for (index, stream) in streams.into_iter().enumerate() {
        let transferred = transferred.clone();
        workers.push(thread::spawn(move || {
            run_resource_flow(stream, deadline, index as u8, &transferred, ceiling)
        }));
    }
    for worker in workers {
        worker.join().unwrap();
    }
    stop_sample.store(true, Ordering::Release);
    sample_thread.join().unwrap();
    target_thread.join().unwrap();

    let bytes = transferred.load(Ordering::Acquire);
    let bits_per_second = bytes.saturating_mul(8) / duration;
    let steady_rss = steady_rss.load(Ordering::Acquire);
    let peak_rss = process_peak_rss_bytes();
    println!(
        "snolc_resource ceiling={ceiling} duration_seconds={duration} stored_users={stored_users} flows={TOTAL_FLOWS} transferred_bytes={bytes} bits_per_second={bits_per_second} idle_rss_bytes={idle_rss} steady_rss_bytes={steady_rss} peak_rss_bytes={peak_rss}"
    );
    assert!(steady_rss <= 64 * MIB, "steady RSS is {steady_rss} bytes");
    assert!(peak_rss <= 96 * MIB, "peak RSS is {peak_rss} bytes");
    if !ceiling {
        assert!(
            (950_000..=1_050_000).contains(&bits_per_second),
            "aggregate payload rate is {bits_per_second} bit/s"
        );
    }

    client_a_handle.shutdown().unwrap();
    client_b_handle.shutdown().unwrap();
    server_handle.shutdown().unwrap();
    client_a_thread.join().unwrap().unwrap();
    client_b_thread.join().unwrap().unwrap();
    server_thread.join().unwrap().unwrap();
    fs::remove_dir_all(directory).unwrap();
}

fn free_tcp_endpoint() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    drop(listener);
    endpoint
}

fn build_resource_client(
    identity: &str,
    carrier: std::net::SocketAddr,
    socks: std::net::SocketAddr,
    protection: &str,
    policy: &str,
) -> snolc::ValidatedConfig {
    let adapter = format!(
        "listen = \"{socks}\"\nmax_connections = 16\nmax_udp_associations = 4\nmax_request_bytes = 1024\nreject_fragments = true\n"
    );
    build_side_with_adapter(
        identity,
        "client",
        carrier,
        false,
        ("adapter_socks5", adapter.as_bytes()),
        ("protection_noise", protection.as_bytes()),
        ("policy_local", policy.as_bytes()),
    )
}

fn provision_resource_users(
    handle: &snolc::EngineHandle,
    instance: &str,
    count: usize,
    credentials: [&str; 2],
    ceiling: bool,
) -> Vec<String> {
    let mut user_ids = Vec::with_capacity(2);
    for index in 0..count {
        let seq = index + 1;
        let combined_rate = if ceiling {
            "mode = \"unlimited\"".to_owned()
        } else {
            "mode = \"limited\"\nbytes_per_second = 62500".to_owned()
        };
        let quota = if ceiling {
            "mode = \"unlimited\"".to_owned()
        } else {
            "mode = \"limited\"\nbytes = 1073741824".to_owned()
        };
        let request = format!(
            r#"method = "user.create"
client_id = "resource-gate"
seq = {seq}

[user]
status = "enabled"
burst_bytes = 65507
weight = 1
group = "default"
rule_profile = "default"

[user.expiration]
mode = "unlimited"
[user.weekly_access]
mode = "unlimited"
[user.quota]
{quota}
[user.upload_rate]
mode = "unlimited"
[user.download_rate]
mode = "unlimited"
[user.combined_rate]
{combined_rate}
[user.max_sessions]
mode = "limited"
count = 1
[user.max_flows]
mode = "limited"
count = 8
"#
        );
        let response =
            futures::executor::block_on(handle.control(instance, request.into_bytes())).unwrap();
        if index < 2 {
            let response: toml::Value =
                toml::from_str(std::str::from_utf8(&response).unwrap()).unwrap();
            user_ids.push(response["user_id"].as_str().unwrap().to_owned());
        }
    }
    for (offset, (user_id, credential)) in user_ids.iter().zip(credentials).enumerate() {
        let seq = count + offset + 1;
        let request = format!(
            "method = \"credential.add\"\nclient_id = \"resource-gate\"\nseq = {seq}\nuser_id = \"{user_id}\"\ncredential_sha256 = \"{credential}\"\n"
        );
        futures::executor::block_on(handle.control(instance, request.into_bytes())).unwrap();
    }
    user_ids
}

fn open_socks_flow(
    socks: std::net::SocketAddr,
    target: std::net::SocketAddr,
    index: usize,
    server: &snolc::EngineHandle,
    client: &snolc::EngineHandle,
) -> TcpStream {
    let mut stream = TcpStream::connect(socks).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    stream.write_all(&[5, 1, 0]).unwrap();
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).unwrap();
    assert_eq!(greeting, [5, 0]);
    let std::net::IpAddr::V4(address) = target.ip() else {
        panic!("resource target must use IPv4")
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&address.octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).unwrap();
    let mut response = [0; 10];
    stream.read_exact(&mut response).unwrap_or_else(|error| {
        panic!(
            "SOCKS flow {socks} index {index} failed: {error}; server={:?}; client={:?}",
            server.snapshot(),
            client.snapshot()
        )
    });
    assert_eq!(response[1], 0);
    stream
}

fn run_echo_target(listener: TcpListener, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut workers = Vec::with_capacity(count);
    while workers.len() < count {
        match listener.accept() {
            Ok((mut stream, _)) => workers.push(thread::spawn(move || {
                let mut buffer = [0; 16_384];
                loop {
                    match stream.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(length) => stream.write_all(&buffer[..length]).unwrap(),
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(error) => panic!("echo read failed: {error}"),
                    }
                }
            })),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "flow accept timed out");
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("flow accept failed: {error}"),
        }
    }
    for worker in workers {
        worker.join().unwrap();
    }
}

fn run_resource_flow(
    mut stream: TcpStream,
    deadline: Instant,
    byte: u8,
    transferred: &AtomicU64,
    ceiling: bool,
) {
    let size = if ceiling { 16_384 } else { 3906 };
    let payload = vec![byte; size];
    let mut reply = vec![0; size];
    let mut next = Instant::now();
    while Instant::now() < deadline {
        stream.write_all(&payload).unwrap();
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(reply, payload);
        transferred.fetch_add((payload.len() + reply.len()) as u64, Ordering::AcqRel);
        if !ceiling {
            next += Duration::from_secs(1);
            if let Some(delay) = next.checked_duration_since(Instant::now()) {
                thread::sleep(delay);
            }
        }
    }
    stream.shutdown(Shutdown::Both).unwrap();
}

fn wait_session_count(handle: &snolc::EngineHandle, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while handle.snapshot().sessions != count && Instant::now() < deadline {
        assert_ne!(handle.snapshot().lifecycle, Lifecycle::Failed);
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(handle.snapshot().sessions, count);
}

fn wait_flow_count(handle: &snolc::EngineHandle, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while handle.snapshot().flows != count && Instant::now() < deadline {
        assert_ne!(handle.snapshot().lifecycle, Lifecycle::Failed);
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(handle.snapshot().flows, count);
}

fn process_rss_bytes() -> u64 {
    process_status_kib("VmRSS:") * 1024
}

fn process_peak_rss_bytes() -> u64 {
    process_status_kib("VmHWM:") * 1024
}

fn process_status_kib(field: &str) -> u64 {
    fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| {
            line.strip_prefix(field)
                .and_then(|value| value.split_whitespace().next())
                .and_then(|value| value.parse::<u64>().ok())
        })
        .unwrap()
}

fn run_pair(server: snolc::ValidatedConfig, client: snolc::ValidatedConfig) {
    let (server_engine, server_handle) = Engine::build(server, QuietHost).unwrap();
    let (client_engine, client_handle) = Engine::build(client, QuietHost).unwrap();

    let server_thread = thread::spawn(move || server_engine.run());
    thread::sleep(Duration::from_millis(50));
    let client_thread = thread::spawn(move || client_engine.run());

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline
        && (server_handle.snapshot().sessions != 1 || client_handle.snapshot().sessions != 1)
    {
        assert_ne!(server_handle.snapshot().lifecycle, Lifecycle::Failed);
        assert_ne!(client_handle.snapshot().lifecycle, Lifecycle::Failed);
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(server_handle.snapshot().sessions, 1);
    assert_eq!(client_handle.snapshot().sessions, 1);

    client_handle.shutdown().unwrap();
    server_handle.shutdown().unwrap();
    client_thread.join().unwrap().unwrap();
    server_thread.join().unwrap().unwrap();
}

fn run_authenticated_pair(
    server: snolc::ValidatedConfig,
    client: snolc::ValidatedConfig,
    credential_digest: &str,
) {
    let (server_engine, server_handle) = Engine::build(server, QuietHost).unwrap();
    let (client_engine, client_handle) = Engine::build(client, QuietHost).unwrap();
    let server_thread = thread::spawn(move || server_engine.run());
    wait_running(&server_handle);
    let user_id = provision_user(&server_handle, "policy-server-local", credential_digest);

    let client_thread = thread::spawn(move || client_engine.run());
    wait_sessions(&server_handle, &client_handle);
    wait_user_session(&server_handle, "policy-server-local", &user_id);
    client_handle.shutdown().unwrap();
    server_handle.shutdown().unwrap();
    client_thread.join().unwrap().unwrap();
    server_thread.join().unwrap().unwrap();
}

fn provision_user(
    server_handle: &snolc::EngineHandle,
    policy_instance: &str,
    credential_digest: &str,
) -> String {
    let create = br#"
method = "user.create"
client_id = "native-test"
seq = 1

[user]
status = "enabled"
burst_bytes = 65507
weight = 1
group = "default"
rule_profile = "default"

[user.expiration]
mode = "unlimited"
[user.weekly_access]
mode = "unlimited"
[user.quota]
mode = "limited"
bytes = 1048576
[user.upload_rate]
mode = "unlimited"
[user.download_rate]
mode = "unlimited"
[user.combined_rate]
mode = "unlimited"
[user.max_sessions]
mode = "limited"
count = 2
[user.max_flows]
mode = "limited"
count = 16
"#;
    let response =
        futures::executor::block_on(server_handle.control(policy_instance, create.to_vec()))
            .unwrap();
    let response: toml::Value = toml::from_str(std::str::from_utf8(&response).unwrap()).unwrap();
    let user_id = response["user_id"].as_str().unwrap();
    let add = format!(
        "method = \"credential.add\"\nclient_id = \"native-test\"\nseq = 2\nuser_id = \"{user_id}\"\ncredential_sha256 = \"{credential_digest}\"\n"
    );
    futures::executor::block_on(server_handle.control(policy_instance, add.into_bytes())).unwrap();
    user_id.to_owned()
}

fn wait_user_session(server_handle: &snolc::EngineHandle, policy_instance: &str, user_id: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let request = format!("method = \"sessions.list\"\nuser_id = \"{user_id}\"\n");
        let response = futures::executor::block_on(
            server_handle.control(policy_instance, request.into_bytes()),
        )
        .unwrap();
        let response: toml::Value =
            toml::from_str(std::str::from_utf8(&response).unwrap()).unwrap();
        if response["sessions"]
            .as_array()
            .is_some_and(|sessions| sessions.len() == 1)
        {
            break;
        }
        assert!(Instant::now() < deadline, "policy authentication timed out");
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_any_policy_session(handle: &snolc::EngineHandle, policy_instance: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let response = futures::executor::block_on(
            handle.control(policy_instance, b"method = \"sessions.list\"\n".to_vec()),
        )
        .unwrap();
        let response: toml::Value =
            toml::from_str(std::str::from_utf8(&response).unwrap()).unwrap();
        if response["sessions"]
            .as_array()
            .is_some_and(|sessions| sessions.len() == 1)
        {
            break;
        }
        assert!(Instant::now() < deadline, "client authentication timed out");
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_running(handle: &snolc::EngineHandle) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && handle.snapshot().lifecycle != Lifecycle::Running {
        assert_ne!(handle.snapshot().lifecycle, Lifecycle::Failed);
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(handle.snapshot().lifecycle, Lifecycle::Running);
}

fn wait_sessions(server: &snolc::EngineHandle, client: &snolc::EngineHandle) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline
        && (server.snapshot().sessions != 1 || client.snapshot().sessions != 1)
    {
        assert_ne!(server.snapshot().lifecycle, Lifecycle::Failed);
        assert_ne!(client.snapshot().lifecycle, Lifecycle::Failed);
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(server.snapshot().sessions, 1);
    assert_eq!(client.snapshot().sessions, 1);
}

fn build_side(
    identity: &str,
    role: &str,
    endpoint: std::net::SocketAddr,
    listen: bool,
    protection: (&str, &[u8]),
    policy: (&str, &[u8]),
) -> snolc::ValidatedConfig {
    build_side_with_adapter(
        identity,
        role,
        endpoint,
        listen,
        (
            "adapter_direct",
            b"dns_mode = \"reject-domains\"\nmax_pending_opens = 8\nmax_resolved_addresses = 16\nresolve_timeout_ms = 1000\nconnect_timeout_ms = 1000\n",
        ),
        protection,
        policy,
    )
}

fn build_side_with_adapter(
    identity: &str,
    role: &str,
    endpoint: std::net::SocketAddr,
    listen: bool,
    adapter: (&str, &[u8]),
    protection: (&str, &[u8]),
    policy: (&str, &[u8]),
) -> snolc::ValidatedConfig {
    build_side_with_adapter_and_control(
        identity, role, endpoint, listen, adapter, protection, policy, None,
    )
}

fn build_side_with_control(
    identity: &str,
    endpoint: std::net::SocketAddr,
    socket: &Path,
    protection: (&str, &[u8]),
    policy: (&str, &[u8]),
) -> snolc::ValidatedConfig {
    build_side_with_adapter_and_control(
        identity,
        "server",
        endpoint,
        true,
        (
            "adapter_direct",
            b"dns_mode = \"reject-domains\"\nmax_pending_opens = 8\nmax_resolved_addresses = 16\nresolve_timeout_ms = 1000\nconnect_timeout_ms = 1000\n",
        ),
        protection,
        policy,
        Some(socket),
    )
}

#[allow(clippy::too_many_arguments)]
fn build_side_with_adapter_and_control(
    identity: &str,
    role: &str,
    endpoint: std::net::SocketAddr,
    listen: bool,
    adapter: (&str, &[u8]),
    protection: (&str, &[u8]),
    policy: (&str, &[u8]),
    control: Option<&Path>,
) -> snolc::ValidatedConfig {
    let carrier_mode = if listen { "listen" } else { "connect" };
    let carrier = format!(
        "mode = \"{carrier_mode}\"\nendpoint_ip = \"{endpoint}\"\nmax_connections = 2\nnodelay = true\n"
    );
    build_side_with_modules(
        identity,
        role,
        adapter,
        ("carrier_tcp", carrier.as_bytes()),
        protection,
        policy,
        control,
    )
}

fn build_side_with_carrier(
    identity: &str,
    role: &str,
    carrier: (&str, &[u8]),
    protection: (&str, &[u8]),
    policy: (&str, &[u8]),
) -> snolc::ValidatedConfig {
    build_side_with_modules(
        identity,
        role,
        (
            "adapter_direct",
            b"dns_mode = \"reject-domains\"\nmax_pending_opens = 8\nmax_resolved_addresses = 16\nresolve_timeout_ms = 1000\nconnect_timeout_ms = 1000\n",
        ),
        carrier,
        protection,
        policy,
        None,
    )
}

fn build_side_with_modules(
    identity: &str,
    role: &str,
    adapter: (&str, &[u8]),
    carrier: (&str, &[u8]),
    protection: (&str, &[u8]),
    policy: (&str, &[u8]),
    control: Option<&Path>,
) -> snolc::ValidatedConfig {
    build_side_with_modules_and_tunnels(
        identity, role, adapter, carrier, protection, policy, control, 1,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_side_with_modules_and_tunnels(
    identity: &str,
    role: &str,
    adapter: (&str, &[u8]),
    carrier: (&str, &[u8]),
    protection: (&str, &[u8]),
    policy: (&str, &[u8]),
    control: Option<&Path>,
    tunnel_count: usize,
) -> snolc::ValidatedConfig {
    let root = PathBuf::from(format!("/tmp/snolc-native-session-{identity}"));
    let adapter_config = root.join("adapter.toml");
    let protection_config = root.join("protection.toml");
    let carrier_config = root.join("carrier.toml");
    let policy_config = root.join("policy.toml");
    let mut config = Config::parse(
        &main_config(
            role,
            &adapter_config,
            &protection_config,
            &carrier_config,
            &policy_config,
        ),
        Path::new("/"),
    )
    .unwrap();
    if let Some(path) = control {
        config.control = snolc::config::ControlConfig::Unix {
            path: path.to_path_buf(),
            max_request_bytes: 65_536,
            max_connections: 4,
        };
    }
    while config.tunnels.len() < tunnel_count {
        let mut tunnel = config.tunnels[0].clone();
        tunnel.name = format!("main-{}", config.tunnels.len() + 1);
        config.tunnels.push(tunnel);
    }
    let modules = vec![
        load(
            &format!("adapter-{identity}"),
            adapter.0,
            adapter.1,
            &adapter_config,
        ),
        load(
            &format!("protection-{identity}"),
            protection.0,
            protection.1,
            &protection_config,
        ),
        load(
            &format!("carrier-{identity}"),
            carrier.0,
            carrier.1,
            &carrier_config,
        ),
        load(
            &format!("policy-{identity}"),
            policy.0,
            policy.1,
            &policy_config,
        ),
    ];
    Engine::validate(config, modules).unwrap()
}

fn policy_local_options(path: &Path, credential: Option<&str>) -> String {
    let template = include_str!("../../../config/templates/modules/policy.toml");
    let mut template: toml::Value = toml::from_str(template).unwrap();
    template["options"]["storage"]["path"] =
        toml::Value::String(path.to_string_lossy().into_owned());
    if let Some(credential) = credential {
        let client: toml::Value = toml::from_str(&format!(
            "[client.credential]\nsource = \"toml\"\nvalue = \"{credential}\"\n"
        ))
        .unwrap();
        template["options"]
            .as_table_mut()
            .unwrap()
            .insert("client".into(), client["client"].clone());
    }
    toml::to_string(&template["options"]).unwrap()
}

fn hex_bytes(input: &str) -> Vec<u8> {
    let (pairs, remainder) = input.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).unwrap();
            let low = (pair[1] as char).to_digit(16).unwrap();
            ((high << 4) | low) as u8
        })
        .collect()
}

fn load(instance: &str, library: &str, options: &[u8], source: &Path) -> LoadedModule {
    LoadedModule::load(
        instance.to_owned(),
        &module_library(library),
        options.to_vec(),
        Path::new("/tmp"),
        source,
    )
    .unwrap()
}

fn module_library(name: &str) -> PathBuf {
    std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join(format!("libsnolc_{name}.so"))
}

fn main_config(
    role: &str,
    adapter: &Path,
    protection: &Path,
    carrier: &Path,
    policy: &Path,
) -> String {
    format!(
        r#"wire_version = 1

[paths]
packages = "/tmp/packages"
state = "/tmp/state"

[engine]
max_sessions = 2
max_flows = 32
max_pending_sessions = 2
max_pending_opens = 8
max_managed_bytes = 33554432
max_commands = 64
max_events = 256
max_io_chunk = 16384
max_ingress_packets_per_tick = 32
connect_timeout_ms = 2000
handshake_timeout_ms = 2000
shutdown_timeout_ms = 2000

[stack]
ipv4 = true
ipv6 = true
mtu = 1280
tcp_socket_rx_bytes = 16384
tcp_socket_tx_bytes = 16384
udp_socket_rx_bytes = 131072
udp_socket_tx_bytes = 131072
udp_metadata_slots = 8
packet_queue_bytes = 262144
max_udp_payload_bytes = 65507
reassembly_slots = 4
reassembly_timeout_ms = 15000

[yamux]
max_streams_per_session = 17
receive_window_bytes = 4456448
split_send_size = 16384
read_after_close = true

[logging]
mode = "off"

[control]
mode = "off"

[[tunnels]]
name = "main"
role = "{role}"
adapters = ["{}"]
protection = "{}"
carrier = "{}"
policy = "{}"
"#,
        adapter.display(),
        protection.display(),
        carrier.display(),
        policy.display()
    )
}
