use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const YARA_SCHEMA_VERSION: u32 = 1;
pub const MAX_RULE_SOURCE_BYTES: usize = 1024 * 1024;
pub const MAX_RULES: usize = 10_000;
pub const MAX_DIAGNOSTICS: usize = 100;
pub const MAX_MATCHING_RULES: usize = 5_000;
pub const MAX_REPORTED_MATCHES: usize = 10_000;
pub const MAX_MATCHES_PER_PATTERN: usize = 100;
pub const MAX_SAMPLE_BYTES: usize = 128 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraCompileSummary {
    pub schema_version: u32,
    pub engine_version: String,
    pub pack_name: String,
    pub source_name: String,
    pub namespace: String,
    pub source_sha256: String,
    pub rule_count: usize,
    pub warnings: Vec<YaraDiagnostic>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraCompileFailure {
    pub message: String,
    pub errors: Vec<YaraDiagnostic>,
    pub warnings: Vec<YaraDiagnostic>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraDiagnostic {
    pub level: String,
    pub message: String,
    pub details: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraScanOptions {
    #[serde(default = "default_max_matches_per_pattern")]
    pub max_matches_per_pattern: usize,
    #[serde(default = "default_max_reported_matches")]
    pub max_reported_matches: usize,
}

const fn default_max_matches_per_pattern() -> usize {
    MAX_MATCHES_PER_PATTERN
}

const fn default_max_reported_matches() -> usize {
    MAX_REPORTED_MATCHES
}

impl Default for YaraScanOptions {
    fn default() -> Self {
        Self {
            max_matches_per_pattern: default_max_matches_per_pattern(),
            max_reported_matches: default_max_reported_matches(),
        }
    }
}

impl YaraScanOptions {
    pub fn bounded(mut self) -> Self {
        self.max_matches_per_pattern = self
            .max_matches_per_pattern
            .clamp(1, MAX_MATCHES_PER_PATTERN);
        self.max_reported_matches = self.max_reported_matches.clamp(1, MAX_REPORTED_MATCHES);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraReport {
    pub schema_version: u32,
    pub engine_version: String,
    pub sample_name: String,
    pub sample_sha256: String,
    pub pack: YaraPackSummary,
    pub elapsed_ms: f64,
    pub matches: Vec<YaraRuleMatch>,
    pub stats: YaraStats,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraPackSummary {
    pub name: String,
    pub namespace: String,
    pub source_name: String,
    pub source_sha256: String,
    pub rule_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRuleMatch {
    pub identifier: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub metadata: Vec<YaraMetadata>,
    pub severity: String,
    pub patterns: Vec<YaraPatternMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMetadata {
    pub identifier: String,
    pub value: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraPatternMatch {
    pub identifier: String,
    pub kind: String,
    pub occurrences: Vec<YaraOccurrence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraOccurrence {
    pub offset: u64,
    pub length: u64,
    pub xor_key: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraStats {
    pub rules_scanned: usize,
    pub matching_rules: usize,
    pub matched_patterns: usize,
    pub reported_occurrences: usize,
}
