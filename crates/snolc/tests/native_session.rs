#![cfg(target_os = "linux")]

use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
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
    let server = build_side(
        "server-metered",
        "server",
        carrier_endpoint,
        true,
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
    let revoke = format!(
        "method = \"credential.revoke\"\nclient_id = \"native-test\"\nseq = 3\ncredential_sha256 = \"{credential_digest}\"\n"
    );
    futures::executor::block_on(
        server_handle.control("policy-server-metered", revoke.into_bytes()),
    )
    .unwrap();
    release_target.send(()).unwrap();
    target_thread.join().unwrap();
    while (client_handle.snapshot().flows != 0 || server_handle.snapshot().flows != 0)
        && Instant::now() < deadline
    {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(client_handle.snapshot().flows, 0);
    assert_eq!(server_handle.snapshot().flows, 0);
    socks.shutdown(Shutdown::Both).unwrap();
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
            b"dns_mode = \"reject-domains\"\nmax_pending_opens = 8\nresolve_timeout_ms = 1000\nconnect_timeout_ms = 1000\n",
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
