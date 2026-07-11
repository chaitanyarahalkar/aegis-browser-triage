use serde::{Deserialize, Serialize};

pub const DYNAMIC_SCHEMA_VERSION: u32 = 3;
pub const HARD_MAX_INSTRUCTIONS: u64 = 10_000_000;
pub const HARD_MAX_TRACE_EVENTS: usize = 5_000;
pub const HARD_MAX_API_EVENTS: usize = 100_000;
pub const HARD_MAX_MEMORY_BYTES: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicOptions {
    #[serde(default = "default_max_instructions")]
    pub max_instructions: u64,
    #[serde(default = "default_max_trace_events")]
    pub max_trace_events: usize,
}

const fn default_max_instructions() -> u64 {
    1_000_000
}

const fn default_max_trace_events() -> usize {
    2_000
}

impl Default for DynamicOptions {
    fn default() -> Self {
        Self {
            max_instructions: default_max_instructions(),
            max_trace_events: default_max_trace_events(),
        }
    }
}

impl DynamicOptions {
    pub fn bounded(mut self) -> Self {
        self.max_instructions = self.max_instructions.clamp(1, HARD_MAX_INSTRUCTIONS);
        self.max_trace_events = self.max_trace_events.clamp(1, HARD_MAX_TRACE_EVENTS);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicReport {
    pub schema_version: u32,
    pub engine_version: String,
    pub sample_sha256: String,
    pub profile: ExecutionProfile,
    pub termination: Termination,
    pub instruction_count: u64,
    pub elapsed_ms: f64,
    pub virtual_time_ms: u64,
    pub instructions: Vec<InstructionEvent>,
    pub api_calls: Vec<ApiEvent>,
    pub processes: Vec<ProcessEvent>,
    pub filesystem: Vec<FileEvent>,
    pub registry: Vec<RegistryEvent>,
    pub network: Vec<NetworkEvent>,
    pub memory: Vec<MemoryEvent>,
    pub injection: Vec<InjectionEvent>,
    pub persistence: Vec<PersistenceEvent>,
    pub artifacts: Vec<ArtifactSummary>,
    pub artifact_stats: ArtifactStats,
    pub timeline: Vec<TimelineEvent>,
    pub coverage: ExecutionCoverage,
    pub findings: Vec<DynamicFinding>,
    pub warnings: Vec<String>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Memory,
    VirtualFile,
    RemoteMemory,
    Configuration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactSummary {
    pub id: String,
    pub kind: ArtifactKind,
    pub name: String,
    pub size: u64,
    pub captured_size: u64,
    pub sha256: String,
    pub entropy: f64,
    pub detected_format: String,
    pub trigger: String,
    pub address: Option<u32>,
    pub path: Option<String>,
    pub permissions: Option<String>,
    pub strings: Vec<ArtifactString>,
    pub indicators: Vec<ArtifactIndicator>,
    pub origins: Vec<ArtifactOrigin>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactOrigin {
    pub api: String,
    pub instruction: u64,
    pub virtual_time_ms: u64,
    pub timeline_sequence: Option<u64>,
    pub trigger: String,
    pub address: Option<u32>,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactString {
    pub offset: u64,
    pub encoding: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactIndicator {
    pub kind: String,
    pub value: String,
    pub offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactStats {
    pub count: usize,
    pub retained_bytes: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceEvent {
    pub mechanism: String,
    pub operation: String,
    pub target: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionEvent {
    pub operation: String,
    pub process_handle: u32,
    pub address: u32,
    pub size: u32,
    pub preview: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub sequence: u64,
    pub instruction: u64,
    pub virtual_time_ms: u64,
    pub category: String,
    pub operation: String,
    pub subject: String,
    pub source_api: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionCoverage {
    pub unique_instruction_addresses: usize,
    pub unique_api_names: usize,
    pub modeled_api_calls: usize,
    pub unmodeled_api_calls: usize,
    pub dynamic_api_resolutions: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionProfile {
    pub architecture: String,
    pub operating_system: String,
    pub image_base: u32,
    pub entry_point: u32,
    pub instruction_limit: u64,
    pub trace_limit: usize,
    pub network_mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum Termination {
    ExitProcess { code: u32 },
    ReturnedFromEntryPoint,
    InstructionLimit,
    Halted,
    UnsupportedInstruction { address: u32, instruction: String },
    InvalidInstruction { address: u32 },
    MemoryFault { address: u32, operation: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionEvent {
    pub index: u64,
    pub address: u32,
    pub bytes: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEvent {
    pub index: u64,
    pub instruction: u64,
    pub module: String,
    pub name: String,
    pub arguments: Vec<String>,
    pub result: u32,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub operation: String,
    pub command: String,
    pub synthetic_result: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    pub operation: String,
    pub path: String,
    pub size: Option<u32>,
    pub preview: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEvent {
    pub operation: String,
    pub key: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub operation: String,
    pub destination: String,
    pub size: Option<u32>,
    pub preview: Option<String>,
    pub synthetic_result: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEvent {
    pub operation: String,
    pub address: u32,
    pub size: u32,
    pub permissions: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicFinding {
    pub id: String,
    pub title: String,
    pub severity: DynamicSeverity,
    pub rationale: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DynamicSeverity {
    Info,
    Low,
    Medium,
    High,
}
