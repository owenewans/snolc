#![no_main]

use libfuzzer_sys::fuzz_target;
use snolc_policy_local::FrameDecoder;

fuzz_target!(|data: &[u8]| {
    let mut decoder = FrameDecoder::new(16_384).unwrap();
    let split = data.first().map_or(0, |byte| usize::from(*byte) % (data.len() + 1));
    let _ = decoder.push(&data[..split]);
    let _ = decoder.push(&data[split..]);
});
