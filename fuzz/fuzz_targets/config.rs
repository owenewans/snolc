#![no_main]

use std::path::Path;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        let _ = snolc::config::Config::parse(input, Path::new("/tmp/snolc-fuzz"));
    }
});
