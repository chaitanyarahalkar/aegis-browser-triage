use serde::{Deserialize, Serialize};

pub const DYNAMIC_SCHEMA_VERSION: u32 = 14;
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
    #[serde(default)]
    pub network_scenario: NetworkScenario,
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
            network_scenario: NetworkScenario::default(),
        }
    }
}

impl DynamicOptions {
    pub fn bounded(mut self) -> Self {
        self.max_instructions = self.max_instructions.clamp(1, HARD_MAX_INSTRUCTIONS);
        self.max_trace_events = self.max_trace_events.clamp(1, HARD_MAX_TRACE_EVENTS);
        self.environment = self.environment.bounded();
        self.network_scenario = self.network_scenario.bounded();
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkScenario {
    pub id: String,
    pub dns: Vec<DnsScenario>,
    pub http: Vec<HttpScenario>,
    pub sockets: Vec<SocketScenario>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsScenario {
    pub host: String,
    pub address: [u8; 4],
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkHeader {
    pub name: String,
    pub value: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpScenario {
    pub url: String,
    pub status: u16,
    pub headers: Vec<NetworkHeader>,
    pub body: Vec<u8>,
    pub redirect_to: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocketScenario {
    pub destination: String,
    pub response: Vec<u8>,
}

impl Default for NetworkScenario {
    fn default() -> Self {
        Self {
            id: "safe-default".into(),
            dns: vec![DnsScenario {
                host: "artifact.example.test".into(),
                address: [10, 20, 30, 40],
            }],
            http: vec![
                HttpScenario {
                    url: "http://artifact.example.test/start".into(),
                    status: 302,
                    headers: vec![NetworkHeader {
                        name: "Location".into(),
                        value: "http://artifact.example.test/payload".into(),
                    }],
                    body: Vec::new(),
                    redirect_to: Some("http://artifact.example.test/payload".into()),
                },
                HttpScenario {
                    url: "http://artifact.example.test/payload".into(),
                    status: 200,
                    headers: vec![NetworkHeader {
                        name: "Content-Type".into(),
                        value: "application/octet-stream".into(),
                    }],
                    body: b"MZ AEGIS_SAFE_NETWORK_DOWNLOAD\0".to_vec(),
                    redirect_to: None,
                },
            ],
            sockets: vec![SocketScenario {
                destination: "10.20.30.40:8080".into(),
                response: b"AEGIS_SAFE_SOCKET_RESPONSE".to_vec(),
            }],
        }
    }
}

impl NetworkScenario {
    fn bounded(mut self) -> Self {
        self.id = bounded_text(&self.id, 64, "custom-network");
        self.dns.truncate(32);
        self.http.truncate(32);
        self.sockets.truncate(32);
        let mut total = 0usize;
        for item in &mut self.dns {
            item.host = bounded_text(&item.host, 253, "invalid.test");
        }
        for item in &mut self.http {
            item.url = bounded_text(&item.url, 2048, "http://invalid.test/");
            item.headers.truncate(64);
            for header in &mut item.headers {
                header.name = bounded_text(&header.name, 64, "X-Aegis");
                header.value = bounded_text(&header.value, 1024, "");
            }
            if let Some(value) = &item.redirect_to {
                item.redirect_to = Some(bounded_text(value, 2048, "http://invalid.test/"));
            }
            let available = (4 * 1024 * 1024usize)
                .saturating_sub(total)
                .min(1024 * 1024);
            item.body.truncate(available);
            total += item.body.len();
        }
        for item in &mut self.sockets {
            item.destination = bounded_text(&item.destination, 512, "0.0.0.0:0");
            let available = (4 * 1024 * 1024usize)
                .saturating_sub(total)
                .min(1024 * 1024);
            item.response.truncate(available);
            total += item.response.len();
        }
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
    pub network_exchanges: Vec<NetworkExchange>,
    pub provenance_sources: Vec<ProvenanceSource>,
    pub provenance_flows: Vec<ProvenanceFlow>,
    pub provenance_stats: ProvenanceStats,
    pub snapshots: Vec<ExecutionSnapshot>,
    pub snapshot_stats: SnapshotStats,
    pub unwind_functions: Vec<RuntimeFunction>,
    pub memory: Vec<MemoryEvent>,
    pub injection: Vec<InjectionEvent>,
    pub persistence: Vec<PersistenceEvent>,
    pub exceptions: Vec<ExceptionEvent>,
    pub threads: Vec<ThreadSummary>,
    pub thread_events: Vec<ThreadEvent>,
    pub system: Vec<SystemEvent>,
    pub artifacts: Vec<ArtifactSummary>,
    pub artifact_stats: ArtifactStats,
    pub payload_generations: Vec<PayloadGeneration>,
    pub generation_stats: GenerationStats,
    pub timeline: Vec<TimelineEvent>,
    pub coverage: ExecutionCoverage,
    pub diagnostics: ExecutionDiagnostics,
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
    NetworkDownload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkExchange {
    pub sequence: u64,
    pub protocol: String,
    pub operation: String,
    pub destination: String,
    pub request_headers: Vec<NetworkHeader>,
    pub request_preview: Option<String>,
    pub request_size: u64,
    pub request_sha256: Option<String>,
    pub response_status: Option<u16>,
    pub response_headers: Vec<NetworkHeader>,
    pub response_size: u64,
    pub response_sha256: Option<String>,
    pub artifact_id: Option<String>,
    pub outcome: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceSourceKind {
    Sample,
    Network,
    Registry,
    VirtualFile,
    Transformation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceSinkKind {
    ExecutableMemory,
    ProcessCommand,
    Persistence,
    NetworkRequest,
    RemoteProcess,
    VirtualFile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceSource {
    pub id: String,
    pub kind: ProvenanceSourceKind,
    pub label: String,
    pub address: u64,
    pub size: u64,
    pub api: String,
    pub instruction: u64,
    pub parent_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceFlow {
    pub sequence: u64,
    pub source_ids: Vec<String>,
    pub sink: ProvenanceSinkKind,
    pub destination: String,
    pub address: u64,
    pub size: u64,
    pub api: String,
    pub instruction: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProvenanceStats {
    pub source_count: usize,
    pub flow_count: usize,
    pub tracked_ranges: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionSnapshot {
    pub sequence: u64,
    pub trigger: String,
    pub instruction: u64,
    pub virtual_time_ms: u64,
    pub registers: SnapshotRegisters,
    pub events: SnapshotEventCounts,
    pub dirty_memory_regions: usize,
    pub state_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotEventCounts {
    pub api_calls: usize,
    pub processes: usize,
    pub filesystem: usize,
    pub registry: usize,
    pub network: usize,
    pub memory: usize,
    pub injection: usize,
    pub persistence: usize,
    pub provenance_flows: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotStats {
    pub count: usize,
    pub truncated: bool,
    pub max_snapshots: usize,
    pub max_dirty_regions: usize,
    pub sampled_bytes_per_region: usize,
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
    pub address: Option<u64>,
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
    pub address: Option<u64>,
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
    pub region_base: u64,
    pub size: u64,
    pub capture_instruction: u64,
    pub virtual_time_ms: u64,
    pub trigger: String,
    pub permissions: String,
    pub executed: bool,
    pub entry_point_overwrite: bool,
    pub executable_heap: bool,
    pub entry_point_candidate: Option<u64>,
    pub first_execution_instruction: Option<u64>,
    pub reconstructed_imports: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerationStats {
    pub count: usize,
    pub chains: usize,
    pub executed_generations: usize,
    pub entry_point_candidates: usize,
    pub reconstructed_imports: usize,
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
pub struct ExceptionEvent {
    pub sequence: u64,
    pub code: u32,
    pub name: String,
    pub address: u64,
    pub handler: Option<u64>,
    pub establisher_frame: Option<u64>,
    pub disposition: Option<i32>,
    pub outcome: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadSummary {
    pub tid: u32,
    pub start_address: u64,
    pub parameter: u64,
    pub state: String,
    pub instruction_count: u64,
    pub exit_code: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadEvent {
    pub sequence: u64,
    pub tid: u32,
    pub operation: String,
    pub instruction: u64,
    pub virtual_time_ms: u64,
    pub start_address: u64,
    pub parameter: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemEvent {
    pub category: String,
    pub operation: String,
    pub target: String,
    pub detail: String,
    pub result: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionEvent {
    pub operation: String,
    pub process_handle: u64,
    pub address: u64,
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
pub struct ExecutionDiagnostics {
    pub first_unsupported: Option<InstructionDiagnostic>,
    pub invalid_instruction_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionDiagnostic {
    pub address: u64,
    pub instruction: String,
    pub bytes: String,
    pub nearby_trace: Vec<InstructionEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionProfile {
    pub architecture: String,
    pub operating_system: String,
    pub image_base: u64,
    pub entry_point: u64,
    pub instruction_limit: u64,
    pub trace_limit: usize,
    pub network_mode: String,
    pub environment: EnvironmentProfile,
    pub network_scenario: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum Termination {
    ExitProcess { code: u32 },
    ReturnedFromEntryPoint,
    InstructionLimit,
    Halted,
    UnsupportedInstruction { address: u64, instruction: String },
    InvalidInstruction { address: u64 },
    MemoryFault { address: u64, operation: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionEvent {
    pub index: u64,
    pub address: u64,
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
    pub result: u64,
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
    pub address: u64,
    pub size: u32,
    pub permissions: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeFunction {
    pub begin_address: u64,
    pub end_address: u64,
    pub unwind_info_address: u64,
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
