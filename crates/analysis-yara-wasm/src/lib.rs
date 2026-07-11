use analysis_yara::{CompiledYaraRules as CoreRules, YaraScanOptions};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct CompiledYaraRules {
    inner: CoreRules,
}

#[wasm_bindgen]
impl CompiledYaraRules {
    pub fn summary_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(self.inner.summary()).map_err(|error| {
            JsValue::from_str(&format!("failed to serialize YARA summary: {error}"))
        })
    }

    pub fn scan(&self, name: &str, bytes: &[u8], options_json: &str) -> Result<String, JsValue> {
        let options = if options_json.trim().is_empty() {
            YaraScanOptions::default()
        } else {
            serde_json::from_str(options_json)
                .map_err(|error| JsValue::from_str(&format!("invalid YARA options: {error}")))?
        };
        let report = self
            .inner
            .scan(name, bytes, &options)
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
        serde_json::to_string(&report).map_err(|error| {
            JsValue::from_str(&format!("failed to serialize YARA report: {error}"))
        })
    }
}

#[wasm_bindgen]
pub fn compile_yara_rules(
    pack_name: &str,
    source_name: &str,
    namespace: &str,
    source: &str,
) -> Result<CompiledYaraRules, JsValue> {
    let inner = CoreRules::compile(pack_name, source_name, namespace, source).map_err(|error| {
        let json = serde_json::to_string(&error).unwrap_or(error.message);
        JsValue::from_str(&json)
    })?;
    Ok(CompiledYaraRules { inner })
}
