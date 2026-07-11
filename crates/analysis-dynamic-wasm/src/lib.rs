use analysis_dynamic::DynamicOptions;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn analyze_dynamic_sample(
    name: &str,
    bytes: &[u8],
    options_json: &str,
) -> Result<String, JsValue> {
    let options = if options_json.trim().is_empty() {
        DynamicOptions::default()
    } else {
        serde_json::from_str(options_json)
            .map_err(|error| JsValue::from_str(&format!("invalid dynamic options: {error}")))?
    };
    let report = analysis_dynamic::analyze_dynamic(name, bytes, &options)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    serde_json::to_string(&report)
        .map_err(|error| JsValue::from_str(&format!("failed to serialize dynamic report: {error}")))
}
