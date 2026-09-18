#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = snolc::wire::parse_header(data);
    let _ = snolc::wire::parse_policy(data);
    let _ = snolc::wire::parse_open(data);
    let _ = snolc::wire::parse_open_response(data);
    let _ = snolc::wire::parse_udp(data);
});
