#![cfg(unix)]

use std::collections::HashMap;
use std::mem::{offset_of, size_of};
use std::path::PathBuf;
use std::process::Command;

use snolc_abi::*;

#[test]
fn c_header_matches_rust_layout() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let output = std::env::temp_dir().join(format!("snolc-header-layout-{}", std::process::id()));
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let compiled = Command::new(compiler)
        .arg("-std=c11")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg(manifest.join("tests/header_layout.c"))
        .arg("-I")
        .arg(manifest.join("../../include"))
        .arg("-o")
        .arg(&output)
        .status()
        .expect("C compiler must run");
    assert!(compiled.success());
    let measured = Command::new(&output)
        .output()
        .expect("layout probe must run");
    let _ = std::fs::remove_file(&output);
    assert!(measured.status.success());
    let measured = String::from_utf8(measured.stdout).unwrap();
    let measured: HashMap<_, _> = measured
        .lines()
        .map(|line| {
            let mut fields = line.split_ascii_whitespace();
            let name = fields.next().unwrap();
            let values = fields
                .map(|value| value.parse::<usize>().unwrap())
                .collect::<Vec<_>>();
            (name, values)
        })
        .collect();

    assert_layout::<SnolBytes>(
        &measured,
        "SnolBytes",
        &[
            offset_of!(SnolBytes, pointer),
            offset_of!(SnolBytes, length),
        ],
    );
    assert_layout::<SnolBytesMut>(
        &measured,
        "SnolBytesMut",
        &[
            offset_of!(SnolBytesMut, pointer),
            offset_of!(SnolBytesMut, length),
        ],
    );
    assert_layout::<SnolIoResult>(
        &measured,
        "SnolIoResult",
        &[
            offset_of!(SnolIoResult, tag),
            offset_of!(SnolIoResult, code),
            offset_of!(SnolIoResult, count),
        ],
    );
    assert_layout::<SnolWakeHandle>(
        &measured,
        "SnolWakeHandle",
        &[
            offset_of!(SnolWakeHandle, context),
            offset_of!(SnolWakeHandle, wake),
            offset_of!(SnolWakeHandle, retain),
            offset_of!(SnolWakeHandle, release),
        ],
    );
    assert_layout::<SnolFlowMetadataV1>(
        &measured,
        "SnolFlowMetadataV1",
        &[
            offset_of!(SnolFlowMetadataV1, struct_size),
            offset_of!(SnolFlowMetadataV1, kind),
            offset_of!(SnolFlowMetadataV1, address_type),
            offset_of!(SnolFlowMetadataV1, reserved),
            offset_of!(SnolFlowMetadataV1, address),
            offset_of!(SnolFlowMetadataV1, port),
            offset_of!(SnolFlowMetadataV1, reserved2),
            offset_of!(SnolFlowMetadataV1, metadata),
        ],
    );
    assert_layout::<SnolByteIoV1>(
        &measured,
        "SnolByteIoV1",
        &[
            offset_of!(SnolByteIoV1, struct_size),
            offset_of!(SnolByteIoV1, reserved),
            offset_of!(SnolByteIoV1, read),
            offset_of!(SnolByteIoV1, write),
            offset_of!(SnolByteIoV1, flush),
            offset_of!(SnolByteIoV1, shutdown_write),
            offset_of!(SnolByteIoV1, close),
        ],
    );
    assert_layout::<SnolDatagramIoV1>(
        &measured,
        "SnolDatagramIoV1",
        &[
            offset_of!(SnolDatagramIoV1, struct_size),
            offset_of!(SnolDatagramIoV1, reserved),
            offset_of!(SnolDatagramIoV1, recv_datagram),
            offset_of!(SnolDatagramIoV1, send_datagram),
            offset_of!(SnolDatagramIoV1, close),
        ],
    );
    assert_layout::<SnolAdapterApiV1>(
        &measured,
        "SnolAdapterApiV1",
        &[
            offset_of!(SnolAdapterApiV1, struct_size),
            offset_of!(SnolAdapterApiV1, reserved),
            offset_of!(SnolAdapterApiV1, open),
            offset_of!(SnolAdapterApiV1, accept),
            offset_of!(SnolAdapterApiV1, attach),
            offset_of!(SnolAdapterApiV1, complete),
            offset_of!(SnolAdapterApiV1, close_flow),
            offset_of!(SnolAdapterApiV1, attach_datagram),
            offset_of!(SnolAdapterApiV1, attach_packet_port),
        ],
    );
    assert_layout::<SnolProtectionApiV1>(
        &measured,
        "SnolProtectionApiV1",
        &[
            offset_of!(SnolProtectionApiV1, struct_size),
            offset_of!(SnolProtectionApiV1, reserved),
            offset_of!(SnolProtectionApiV1, wrap),
        ],
    );
    assert_layout::<SnolCarrierApiV1>(
        &measured,
        "SnolCarrierApiV1",
        &[
            offset_of!(SnolCarrierApiV1, struct_size),
            offset_of!(SnolCarrierApiV1, reserved),
            offset_of!(SnolCarrierApiV1, connect),
            offset_of!(SnolCarrierApiV1, accept),
        ],
    );
    assert_layout::<SnolPolicyApiV1>(
        &measured,
        "SnolPolicyApiV1",
        &[
            offset_of!(SnolPolicyApiV1, struct_size),
            offset_of!(SnolPolicyApiV1, reserved),
            offset_of!(SnolPolicyApiV1, attach_session),
            offset_of!(SnolPolicyApiV1, admit_flow),
            offset_of!(SnolPolicyApiV1, attach_flow),
            offset_of!(SnolPolicyApiV1, attach_datagram_flow),
        ],
    );
    assert_layout::<SnolHostApiV1>(
        &measured,
        "SnolHostApiV1",
        &[
            offset_of!(SnolHostApiV1, struct_size),
            offset_of!(SnolHostApiV1, reserved),
            offset_of!(SnolHostApiV1, context),
            offset_of!(SnolHostApiV1, now_monotonic_nanos),
            offset_of!(SnolHostApiV1, set_timer),
            offset_of!(SnolHostApiV1, emit_event),
            offset_of!(SnolHostApiV1, context_get),
            offset_of!(SnolHostApiV1, context_set),
            offset_of!(SnolHostApiV1, protect_socket),
        ],
    );
    assert_layout::<SnolModuleDescriptor>(
        &measured,
        "SnolModuleDescriptor",
        &[
            offset_of!(SnolModuleDescriptor, struct_size),
            offset_of!(SnolModuleDescriptor, wire_version),
            offset_of!(SnolModuleDescriptor, class_mask),
            offset_of!(SnolModuleDescriptor, reserved),
            offset_of!(SnolModuleDescriptor, name),
            offset_of!(SnolModuleDescriptor, describe),
            offset_of!(SnolModuleDescriptor, validate_config),
            offset_of!(SnolModuleDescriptor, create),
            offset_of!(SnolModuleDescriptor, poll),
            offset_of!(SnolModuleDescriptor, control),
            offset_of!(SnolModuleDescriptor, shutdown),
            offset_of!(SnolModuleDescriptor, destroy),
            offset_of!(SnolModuleDescriptor, byte_io),
            offset_of!(SnolModuleDescriptor, datagram_io),
            offset_of!(SnolModuleDescriptor, adapter),
            offset_of!(SnolModuleDescriptor, protection),
            offset_of!(SnolModuleDescriptor, carrier),
            offset_of!(SnolModuleDescriptor, policy),
        ],
    );
}

fn assert_layout<T>(measured: &HashMap<&str, Vec<usize>>, name: &str, offsets: &[usize]) {
    let mut expected = Vec::with_capacity(offsets.len() + 1);
    expected.push(size_of::<T>());
    expected.extend_from_slice(offsets);
    assert_eq!(measured.get(name), Some(&expected), "{name}");
}
