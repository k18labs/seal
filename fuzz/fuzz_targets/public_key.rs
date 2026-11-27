#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| { let _ = seal::signature::validate_public_key_bytes(data); });
