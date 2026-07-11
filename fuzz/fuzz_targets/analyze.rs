#![no_main]

use analysis_core::{analyze, AnalysisOptions};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if !data.is_empty() {
        let _ = analyze("fuzz-input.bin", data, &AnalysisOptions::default());
    }
});

