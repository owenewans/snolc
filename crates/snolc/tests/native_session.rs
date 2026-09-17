#![cfg(target_os = "linux")]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use snolc::config::Config;
use snolc::loader::LoadedModule;
use snolc::{Engine, Event, Host, Lifecycle};

struct QuietHost;

impl Host for QuietHost {
    fn engine_event(&self, _event: &Event) {}
}

#[test]
fn native_tcp_dummy_path_establishes_policy_session() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    drop(listener);

    let server = build_side("server", endpoint, true);
    let client = build_side("client", endpoint, false);
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

fn build_side(role: &str, endpoint: std::net::SocketAddr, listen: bool) -> snolc::ValidatedConfig {
    let root = PathBuf::from(format!("/tmp/snolc-native-session-{role}"));
    let adapter_config = root.join("adapter.toml");
    let protection_config = root.join("protection.toml");
    let carrier_config = root.join("carrier.toml");
    let policy_config = root.join("policy.toml");
    let config = Config::parse(
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
    let carrier_mode = if listen { "listen" } else { "connect" };
    let modules = vec![
        load(
            &format!("adapter-{role}"),
            "adapter_direct",
            b"dns_mode = \"reject-domains\"\nmax_pending_opens = 8\nresolve_timeout_ms = 1000\nconnect_timeout_ms = 1000\n",
            &adapter_config,
        ),
        load(
            &format!("protection-{role}"),
            "protection_dummy",
            b"",
            &protection_config,
        ),
        load(
            &format!("carrier-{role}"),
            "carrier_tcp",
            format!(
                "mode = \"{carrier_mode}\"\nendpoint_ip = \"{endpoint}\"\nmax_connections = 2\nnodelay = true\n"
            )
            .as_bytes(),
            &carrier_config,
        ),
        load(
            &format!("policy-{role}"),
            "policy_dummy",
            b"pump_buffer_bytes = 4096\n",
            &policy_config,
        ),
    ];
    Engine::validate(config, modules).unwrap()
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
