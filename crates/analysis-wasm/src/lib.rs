use analysis_core::{AnalysisOptions, MAX_INPUT_BYTES};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn analyze_sample(name: &str, bytes: &[u8], options_json: &str) -> Result<String, JsValue> {
    let options = if options_json.trim().is_empty() {
        AnalysisOptions::default()
    } else {
        serde_json::from_str(options_json)
            .map_err(|error| JsValue::from_str(&format!("invalid analysis options: {error}")))?
    };
    let report = analysis_core::analyze(name, bytes, &options)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    serde_json::to_string(&report)
        .map_err(|error| JsValue::from_str(&format!("failed to serialize report: {error}")))
}

#[wasm_bindgen]
pub fn max_input_bytes() -> usize {
    MAX_INPUT_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_returns_versioned_json() {
        let json = analyze_sample("fixture.bin", b"fixture data", "{}").unwrap();
        assert!(json.contains("\"schema_version\":1"));
    }
}
