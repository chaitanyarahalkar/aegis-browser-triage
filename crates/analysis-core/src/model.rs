use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_INPUT_BYTES: usize = 128 * 1024 * 1024;
pub const MAX_SECTIONS: usize = 4_096;
pub const MAX_COLLECTION_ITEMS: usize = 50_000;
pub const MAX_STRINGS: usize = 50_000;
pub const MAX_STRING_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_STRING_LENGTH: usize = 4 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisOptions {
    #[serde(default = "default_min_string_length")]
    pub min_string_length: usize,
    #[serde(default = "default_max_strings")]
    pub max_strings: usize,
}

const fn default_min_string_length() -> usize {
    4
}

const fn default_max_strings() -> usize {
    MAX_STRINGS
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            min_string_length: default_min_string_length(),
            max_strings: default_max_strings(),
        }
    }
}

impl AnalysisOptions {
    pub fn bounded(mut self) -> Self {
        self.min_string_length = self.min_string_length.clamp(4, 128);
        self.max_strings = self.max_strings.clamp(1, MAX_STRINGS);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub schema_version: u32,
    pub engine_version: String,
    pub sample: SampleSummary,
    pub format: FormatReport,
    pub sections: Vec<SectionRecord>,
    pub imports: Vec<SymbolRecord>,
    pub exports: Vec<SymbolRecord>,
    pub strings: Vec<ExtractedString>,
    pub indicators: Vec<Indicator>,
    pub findings: Vec<Finding>,
    pub warnings: Vec<AnalysisWarning>,
    pub stats: AnalysisStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleSummary {
    pub name: String,
    pub size: u64,
    pub detected_format: BinaryFormat,
    pub architecture: Option<String>,
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryFormat {
    Pe,
    Elf,
    MachO,
    WebAssembly,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FormatReport {
    Pe {
        bitness: u8,
        machine: String,
        subsystem: Option<String>,
        timestamp: u32,
        entry_point: u64,
        image_base: u64,
        libraries: Vec<String>,
        is_dll: bool,
        has_tls: bool,
        has_resources: bool,
        has_signature: bool,
        is_dotnet: bool,
        mitigations: Vec<String>,
    },
    Elf {
        bitness: u8,
        machine: String,
        file_type: String,
        entry_point: u64,
        interpreter: Option<String>,
        libraries: Vec<String>,
        rpaths: Vec<String>,
        hardening: Vec<String>,
    },
    MachO {
        bitness: Option<u8>,
        machine: String,
        entry_point: Option<u64>,
        slices: Vec<MachSlice>,
        libraries: Vec<String>,
        rpaths: Vec<String>,
        has_code_signature: bool,
    },
    WebAssembly {
        encoding: String,
        version: u16,
        valid: bool,
        types: u32,
        functions: u32,
        memories: u32,
        tables: u32,
        globals: u32,
        start_function: Option<u32>,
        custom_sections: Vec<String>,
    },
    Unknown {
        magic: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachSlice {
    pub machine: String,
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionRecord {
    pub name: String,
    pub offset: u64,
    pub virtual_address: Option<u64>,
    pub size: u64,
    pub entropy: f64,
    pub permissions: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolRecord {
    pub name: String,
    pub module: Option<String>,
    pub address: Option<u64>,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedString {
    pub offset: u64,
    pub encoding: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Indicator {
    pub kind: String,
    pub value: String,
    pub offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub rationale: String,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub offset: Option<u64>,
    pub length: Option<u64>,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisWarning {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisStats {
    pub elapsed_ms: f64,
    pub bytes_scanned: u64,
    pub strings_truncated: bool,
    pub collections_truncated: bool,
}
