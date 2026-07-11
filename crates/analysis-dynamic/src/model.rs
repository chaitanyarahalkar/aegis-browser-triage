use serde::{Deserialize, Serialize};

pub const DYNAMIC_SCHEMA_VERSION: u32 = 5;
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
    #[serde(default)]
    pub environment: EnvironmentProfile,
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
            environment: EnvironmentProfile::default(),
        }
    }
}

impl DynamicOptions {
    pub fn bounded(mut self) -> Self {
        self.max_instructions = self.max_instructions.clamp(1, HARD_MAX_INSTRUCTIONS);
        self.max_trace_events = self.max_trace_events.clamp(1, HARD_MAX_TRACE_EVENTS);
        self.environment = self.environment.bounded();
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentProfile {
    pub id: String,
    pub label: String,
    pub windows_version: String,
    pub computer_name: String,
    pub user_name: String,
    pub locale: String,
    pub timezone_offset_minutes: i32,
    pub memory_mb: u32,
    pub cpu_count: u32,
    pub debugger_present: bool,
    pub network_mode: NetworkMode,
    pub initial_virtual_time_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    Online,
    Offline,
    Sinkhole,
}

impl NetworkMode {
    pub fn description(self) -> &'static str {
        match self {
            Self::Online => "Synthetic online responses; no external access",
            Self::Offline => "Synthetic offline failures; no external access",
            Self::Sinkhole => "Synthetic sinkhole responses; no external access",
        }
    }
}

impl Default for EnvironmentProfile {
    fn default() -> Self {
        Self::balanced()
    }
}

impl EnvironmentProfile {
    pub fn balanced() -> Self {
        Self {
            id: "balanced".into(),
            label: "Balanced workstation".into(),
            windows_version: "Windows 10 22H2".into(),
            computer_name: "AEGIS-WORKSTATION".into(),
            user_name: "analyst".into(),
            locale: "en-US".into(),
            timezone_offset_minutes: -360,
            memory_mb: 8 * 1024,
            cpu_count: 4,
            debugger_present: false,
            network_mode: NetworkMode::Online,
            initial_virtual_time_ms: 1_000_000,
        }
    }

    pub fn legacy() -> Self {
        Self {
            id: "legacy".into(),
            label: "Legacy workstation".into(),
            windows_version: "Windows 7 SP1".into(),
            computer_name: "OFFICE-PC".into(),
            user_name: "user".into(),
            locale: "en-US".into(),
            timezone_offset_minutes: -300,
            memory_mb: 2 * 1024,
            cpu_count: 2,
            debugger_present: false,
            network_mode: NetworkMode::Online,
            initial_virtual_time_ms: 500_000,
        }
    }

    pub fn hardened() -> Self {
        Self {
            id: "hardened".into(),
            label: "Hardened offline host".into(),
            windows_version: "Windows 11 24H2".into(),
            computer_name: "CORP-WKS-042".into(),
            user_name: "employee".into(),
            locale: "en-GB".into(),
            timezone_offset_minutes: 0,
            memory_mb: 16 * 1024,
            cpu_count: 8,
            debugger_present: false,
            network_mode: NetworkMode::Offline,
            initial_virtual_time_ms: 2_000_000,
        }
    }

    pub fn analysis() -> Self {
        Self {
            id: "analysis".into(),
            label: "Instrumented analysis host".into(),
            windows_version: "Windows 10 analysis".into(),
            computer_name: "MALWARE-LAB".into(),
            user_name: "sandbox".into(),
            locale: "en-US".into(),
            timezone_offset_minutes: 0,
            memory_mb: 1024,
            cpu_count: 1,
            debugger_present: true,
            network_mode: NetworkMode::Sinkhole,
            initial_virtual_time_ms: 3_000_000,
        }
    }

    pub fn presets() -> [Self; 4] {
        [
            Self::balanced(),
            Self::legacy(),
            Self::hardened(),
            Self::analysis(),
        ]
    }

    fn bounded(mut self) -> Self {
        self.id = bounded_text(&self.id, 32, "custom");
        self.label = bounded_text(&self.label, 80, "Custom profile");
        self.windows_version = bounded_text(&self.windows_version, 80, "Synthetic Windows");
        self.computer_name = bounded_text(&self.computer_name, 63, "AEGIS-HOST");
        self.user_name = bounded_text(&self.user_name, 64, "analyst");
        self.locale = bounded_text(&self.locale, 16, "en-US");
        self.timezone_offset_minutes = self.timezone_offset_minutes.clamp(-14 * 60, 14 * 60);
        self.memory_mb = self.memory_mb.clamp(256, 128 * 1024);
        self.cpu_count = self.cpu_count.clamp(1, 64);
        self.initial_virtual_time_ms = self.initial_virtual_time_ms.min(86_400_000);
        self
    }
}

fn bounded_text(value: &str, maximum: usize, fallback: &str) -> String {
    let value: String = value
        .chars()
        .filter(|character| !character.is_control())
        .take(maximum)
        .collect();
    if value.trim().is_empty() {
        fallback.into()
    } else {
        value
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
    pub payload_generations: Vec<PayloadGeneration>,
    pub generation_stats: GenerationStats,
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
pub struct PayloadGeneration {
    pub id: String,
    pub sequence: u64,
    pub parent_id: Option<String>,
    pub artifact_id: String,
    pub region_base: u32,
    pub size: u64,
    pub capture_instruction: u64,
    pub virtual_time_ms: u64,
    pub trigger: String,
    pub permissions: String,
    pub executed: bool,
    pub entry_point_overwrite: bool,
    pub executable_heap: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerationStats {
    pub count: usize,
    pub chains: usize,
    pub executed_generations: usize,
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
    pub environment: EnvironmentProfile,
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
