use analysis_dynamic::DynamicOptions;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct DynamicSession {
    inner: analysis_dynamic::DynamicAnalysis,
}

#[wasm_bindgen]
impl DynamicSession {
    pub fn report_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.inner.report).map_err(|error| {
            JsValue::from_str(&format!("failed to serialize dynamic report: {error}"))
        })
    }

    pub fn artifact_bytes(&self, id: &str) -> Result<Vec<u8>, JsValue> {
        self.inner
            .artifact_bytes(id)
            .map(ToOwned::to_owned)
            .ok_or_else(|| JsValue::from_str("artifact not found"))
    }
}

#[wasm_bindgen]
pub fn analyze_dynamic_session(
    name: &str,
    bytes: &[u8],
    options_json: &str,
) -> Result<DynamicSession, JsValue> {
    let options = parse_options(options_json)?;
    let inner = analysis_dynamic::analyze_dynamic_with_artifacts(name, bytes, &options)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    Ok(DynamicSession { inner })
}

#[wasm_bindgen]
pub fn analyze_dynamic_sample(
    name: &str,
    bytes: &[u8],
    options_json: &str,
) -> Result<String, JsValue> {
    let session = analyze_dynamic_session(name, bytes, options_json)?;
    session.report_json()
}

fn parse_options(options_json: &str) -> Result<DynamicOptions, JsValue> {
    let options = if options_json.trim().is_empty() {
        DynamicOptions::default()
    } else {
        serde_json::from_str(options_json)
            .map_err(|error| JsValue::from_str(&format!("invalid dynamic options: {error}")))?
    };
    Ok(options)
}
