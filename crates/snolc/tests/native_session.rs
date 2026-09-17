#![cfg(target_os = "linux")]

use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use snolc::config::Config;
use snolc::loader::LoadedModule;
use snolc::{Engine, Event, Host, Lifecycle};
use snow::{Builder, params::NoiseParams};

struct QuietHost;

impl Host for QuietHost {
    fn engine_event(&self, _event: &Event) {}
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
        futures::executor::block_on(server_handle.control("policy-server-local", create.to_vec()))
            .unwrap();
    let response: toml::Value = toml::from_str(std::str::from_utf8(&response).unwrap()).unwrap();
    let user_id = response["user_id"].as_str().unwrap();
    let add = format!(
        "method = \"credential.add\"\nclient_id = \"native-test\"\nseq = 2\nuser_id = \"{user_id}\"\ncredential_sha256 = \"{credential_digest}\"\n"
    );
    futures::executor::block_on(server_handle.control("policy-server-local", add.into_bytes()))
        .unwrap();

    let client_thread = thread::spawn(move || client_engine.run());
    wait_sessions(&server_handle, &client_handle);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let request = format!("method = \"sessions.list\"\nuser_id = \"{user_id}\"\n");
        let response = futures::executor::block_on(
            server_handle.control("policy-server-local", request.into_bytes()),
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
    client_handle.shutdown().unwrap();
    server_handle.shutdown().unwrap();
    client_thread.join().unwrap().unwrap();
    server_thread.join().unwrap().unwrap();
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
    let root = PathBuf::from(format!("/tmp/snolc-native-session-{identity}"));
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
            &format!("adapter-{identity}"),
            "adapter_direct",
            b"dns_mode = \"reject-domains\"\nmax_pending_opens = 8\nresolve_timeout_ms = 1000\nconnect_timeout_ms = 1000\n",
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
            "carrier_tcp",
            format!(
                "mode = \"{carrier_mode}\"\nendpoint_ip = \"{endpoint}\"\nmax_connections = 2\nnodelay = true\n"
            )
            .as_bytes(),
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
    let template = include_str!("../../../config/templates/policy-local-server.toml");
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
