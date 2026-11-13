#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| gimmecores_node::fuzzing::text(data));
