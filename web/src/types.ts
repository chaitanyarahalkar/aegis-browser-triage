export type BinaryFormat = 'pe' | 'elf' | 'mach_o' | 'web_assembly' | 'unknown'
export type Severity = 'info' | 'low' | 'medium' | 'high'
export type Confidence = 'low' | 'medium' | 'high'

export interface SampleSummary {
  name: string
  size: number
  detected_format: BinaryFormat
  architecture: string | null
  sha256: string
  sha1: string
  md5: string
}

export interface SectionRecord {
  name: string
  offset: number
  virtual_address: number | null
  size: number
  entropy: number
  permissions: string
}

export interface SymbolRecord {
  name: string
  module: string | null
  address: number | null
  kind: string
}

export interface ExtractedString {
  offset: number
  encoding: string
  value: string
}

export interface Indicator {
  kind: string
  value: string
  offset: number
}

export interface Evidence {
  offset: number | null
  length: number | null
  value: string
}

export interface Finding {
  id: string
  title: string
  severity: Severity
  confidence: Confidence
  rationale: string
  evidence: Evidence[]
}

export interface AnalysisWarning {
  code: string
  message: string
}

export interface AnalysisStats {
  elapsed_ms: number
  bytes_scanned: number
  strings_truncated: boolean
  collections_truncated: boolean
}

export type FormatReport =
  | ({ kind: 'pe' } & Record<string, unknown>)
  | ({ kind: 'elf' } & Record<string, unknown>)
  | ({ kind: 'mach_o' } & Record<string, unknown>)
  | ({ kind: 'web_assembly' } & Record<string, unknown>)
  | ({ kind: 'unknown' } & Record<string, unknown>)

export interface AnalysisReport {
  schema_version: number
  engine_version: string
  sample: SampleSummary
  format: FormatReport
  sections: SectionRecord[]
  imports: SymbolRecord[]
  exports: SymbolRecord[]
  strings: ExtractedString[]
  indicators: Indicator[]
  findings: Finding[]
  warnings: AnalysisWarning[]
  stats: AnalysisStats
}

export type ProgressStage = 'loading-engine' | 'parsing' | 'finalizing'

export type DynamicProgressStage = 'loading-engine' | 'loading-image' | 'executing' | 'finalizing'

export interface DynamicInstructionEvent {
  index: number
  address: number
  bytes: string
  text: string
}

export interface DynamicApiEvent {
  index: number
  instruction: number
  module: string
  name: string
  arguments: string[]
  result: number
  summary: string
}

export interface DynamicFileEvent {
  operation: string
  path: string
  size: number | null
  preview: string | null
}

export interface DynamicRegistryEvent {
  operation: string
  key: string
  value: string | null
}

export interface DynamicNetworkEvent {
  operation: string
  destination: string
  size: number | null
  preview: string | null
  synthetic_result: string
}
export interface DynamicNetworkHeader { name: string; value: string }
export interface DynamicNetworkExchange { sequence: number; protocol: string; operation: string; destination: string; request_headers: DynamicNetworkHeader[]; request_preview: string | null; request_size: number; request_sha256: string | null; response_status: number | null; response_headers: DynamicNetworkHeader[]; response_size: number; response_sha256: string | null; artifact_id: string | null; outcome: string }
export type DynamicProvenanceSourceKind = 'sample' | 'network' | 'registry' | 'virtual_file' | 'transformation'
export type DynamicProvenanceSinkKind = 'executable_memory' | 'process_command' | 'persistence' | 'network_request' | 'remote_process' | 'virtual_file'
export interface DynamicProvenanceSource { id: string; kind: DynamicProvenanceSourceKind; label: string; address: number; size: number; api: string; instruction: number; parent_ids: string[] }
export interface DynamicProvenanceFlow { sequence: number; source_ids: string[]; sink: DynamicProvenanceSinkKind; destination: string; address: number; size: number; api: string; instruction: number }
export interface DynamicExecutionSnapshot {
  sequence: number; trigger: string; instruction: number; virtual_time_ms: number; dirty_memory_regions: number; state_sha256: string
  registers: { rax: number; rbx: number; rcx: number; rdx: number; rsi: number; rdi: number; rbp: number; rsp: number; r8: number; r9: number; r10: number; r11: number; r12: number; r13: number; r14: number; r15: number; rip: number; rflags: number }
  events: { api_calls: number; processes: number; filesystem: number; registry: number; network: number; memory: number; injection: number; persistence: number; provenance_flows: number }
}

export interface DynamicMemoryEvent {
  operation: string
  address: number
  size: number
  permissions: string
}

export interface DynamicInjectionEvent {
  operation: string
  process_handle: number
  address: number
  size: number
  preview: string | null
}

export interface DynamicPersistenceEvent {
  mechanism: string
  operation: string
  target: string
  value: string | null
}

export interface DynamicExceptionEvent {
  sequence: number
  code: number
  name: string
  address: number
  handler: number | null
  establisher_frame: number | null
  disposition: number | null
  outcome: string
}
export interface DynamicThreadSummary { tid: number; start_address: number; parameter: number; state: string; instruction_count: number; exit_code: number | null }
export interface DynamicThreadEvent { sequence: number; tid: number; operation: string; instruction: number; virtual_time_ms: number; start_address: number; parameter: number }
export interface DynamicSystemEvent { category: string; operation: string; target: string; detail: string; result: number }

export interface DynamicProcessEvent {
  operation: string
  command: string
  synthetic_result: string
}

export interface DynamicTimelineEvent {
  sequence: number
  instruction: number
  virtual_time_ms: number
  category: string
  operation: string
  subject: string
  source_api: string
}

export interface DynamicCoverage {
  unique_instruction_addresses: number
  unique_api_names: number
  modeled_api_calls: number
  unmodeled_api_calls: number
  dynamic_api_resolutions: number
}
export interface DynamicInstructionDiagnostic { address: number; instruction: string; bytes: string; nearby_trace: DynamicInstructionEvent[] }
export interface DynamicExecutionDiagnostics { first_unsupported: DynamicInstructionDiagnostic | null; invalid_instruction_count: number }

export interface DynamicFinding {
  id: string
  title: string
  severity: Severity
  rationale: string
  evidence: string[]
}

export type DynamicTermination =
  | { reason: 'exit_process'; code: number }
  | { reason: 'returned_from_entry_point' }
  | { reason: 'instruction_limit' }
  | { reason: 'halted' }
  | { reason: 'unsupported_instruction'; address: number; instruction: string }
  | { reason: 'invalid_instruction'; address: number }
  | { reason: 'memory_fault'; address: number; operation: string }

export type DynamicNetworkMode = 'online' | 'offline' | 'sinkhole'
export interface DynamicEnvironmentProfile {
  id: string
  label: string
  windows_version: string
  computer_name: string
  user_name: string
  locale: string
  timezone_offset_minutes: number
  memory_mb: number
  cpu_count: number
  debugger_present: boolean
  network_mode: DynamicNetworkMode
  initial_virtual_time_ms: number
}

export interface DynamicReport {
  schema_version: number
  engine_version: string
  sample_sha256: string
  profile: {
    architecture: string
    operating_system: string
    image_base: number
    entry_point: number
    instruction_limit: number
    trace_limit: number
    network_mode: string
    environment: DynamicEnvironmentProfile
    network_scenario: string
  }
  termination: DynamicTermination
  instruction_count: number
  elapsed_ms: number
  virtual_time_ms: number
  instructions: DynamicInstructionEvent[]
  api_calls: DynamicApiEvent[]
  processes: DynamicProcessEvent[]
  filesystem: DynamicFileEvent[]
  registry: DynamicRegistryEvent[]
  network: DynamicNetworkEvent[]
  network_exchanges: DynamicNetworkExchange[]
  provenance_sources: DynamicProvenanceSource[]
  provenance_flows: DynamicProvenanceFlow[]
  provenance_stats: { source_count: number; flow_count: number; tracked_ranges: number; truncated: boolean }
  snapshots: DynamicExecutionSnapshot[]
  snapshot_stats: { count: number; truncated: boolean; max_snapshots: number; max_dirty_regions: number; sampled_bytes_per_region: number }
  unwind_functions: Array<{ begin_address: number; end_address: number; unwind_info_address: number }>
  memory: DynamicMemoryEvent[]
  injection: DynamicInjectionEvent[]
  persistence: DynamicPersistenceEvent[]
  exceptions: DynamicExceptionEvent[]
  threads: DynamicThreadSummary[]
  thread_events: DynamicThreadEvent[]
  system: DynamicSystemEvent[]
  artifacts: ArtifactSummary[]
  artifact_stats: { count: number; retained_bytes: number; truncated: boolean }
  payload_generations: PayloadGeneration[]
  generation_stats: { count: number; chains: number; executed_generations: number; truncated: boolean }
  timeline: DynamicTimelineEvent[]
  coverage: DynamicCoverage
  diagnostics: DynamicExecutionDiagnostics
  findings: DynamicFinding[]
  warnings: string[]
  truncated: boolean
}

export interface PayloadGeneration {
  id: string
  sequence: number
  parent_id: string | null
  artifact_id: string
  region_base: number
  size: number
  capture_instruction: number
  virtual_time_ms: number
  trigger: string
  permissions: string
  executed: boolean
  entry_point_overwrite: boolean
  executable_heap: boolean
}

export type ArtifactKind = 'memory' | 'virtual_file' | 'remote_memory' | 'configuration' | 'network_download'
export interface ArtifactOrigin { api: string; instruction: number; virtual_time_ms: number; timeline_sequence: number | null; trigger: string; address: number | null; path: string | null }
export interface ArtifactSummary {
  id: string; kind: ArtifactKind; name: string; size: number; captured_size: number; sha256: string; entropy: number; detected_format: string; trigger: string; address: number | null; path: string | null; permissions: string | null; strings: Array<{ offset: number; encoding: string; value: string }>; indicators: Array<{ kind: string; value: string; offset: number }>; origins: ArtifactOrigin[]; truncated: boolean
}

export type DynamicWorkerRequest =
  | { type: 'analyze-dynamic'; jobId: string; name: string; buffer: ArrayBuffer; options: string }
  | { type: 'analyze-dynamic-batch'; jobId: string; name: string; buffer: ArrayBuffer; options: string[] }
  | { type: 'read-artifact'; requestId: string; profileId: string; artifactId: string; offset: number; length: number; full: boolean }

export type DynamicWorkerResponse =
  | { type: 'progress'; jobId: string; stage: DynamicProgressStage }
  | { type: 'completed'; jobId: string; report: DynamicReport }
  | { type: 'batch-completed'; jobId: string; reports: DynamicReport[] }
  | { type: 'failed'; jobId: string; message: string }
  | { type: 'artifact-slice'; requestId: string; artifactId: string; offset: number; total: number; buffer: ArrayBuffer }
  | { type: 'artifact-failed'; requestId: string; message: string }
  | { type: 'ready' }

export type WorkerRequest =
  | { type: 'analyze'; jobId: string; name: string; buffer: ArrayBuffer; options: string }
  | { type: 'read-hex'; requestId: string; offset: number; length: number }
  | { type: 'close-sample' }

export type WorkerResponse =
  | { type: 'progress'; jobId: string; stage: ProgressStage }
  | { type: 'completed'; jobId: string; report: AnalysisReport }
  | { type: 'failed'; jobId: string; message: string }
  | { type: 'hex-slice'; requestId: string; offset: number; buffer: ArrayBuffer }
  | { type: 'ready'; maxInputBytes: number }

export type YaraProgressStage = 'loading-engine' | 'compiling' | 'scanning'
export interface YaraDiagnostic { level: string; message: string; details: unknown }
export interface YaraCompileSummary { schema_version: number; engine_version: string; pack_name: string; source_name: string; namespace: string; source_sha256: string; rule_count: number; warnings: YaraDiagnostic[] }
export interface YaraOccurrence { offset: number; length: number; xor_key: number | null }
export interface YaraPatternMatch { identifier: string; kind: string; occurrences: YaraOccurrence[] }
export interface YaraMetadata { identifier: string; value: unknown }
export interface YaraRuleMatch { identifier: string; namespace: string; tags: string[]; metadata: YaraMetadata[]; severity: Severity; patterns: YaraPatternMatch[] }
export interface YaraReport {
  schema_version: number
  engine_version: string
  sample_name: string
  sample_sha256: string
  pack: { name: string; namespace: string; source_name: string; source_sha256: string; rule_count: number }
  elapsed_ms: number
  matches: YaraRuleMatch[]
  stats: { rules_scanned: number; matching_rules: number; matched_patterns: number; reported_occurrences: number }
  truncated: boolean
}
export interface ArtifactYaraResult { artifact_id: string; report: YaraReport | null; error: string | null }
export type YaraWorkerRequest =
  | { type: 'compile-yara'; jobId: string; packName: string; sourceName: string; namespace: string; source: string }
  | { type: 'scan-yara'; jobId: string; name: string; buffer: ArrayBuffer; options: string }
  | { type: 'scan-yara-artifacts'; jobId: string; artifacts: Array<{ id: string; name: string; buffer: ArrayBuffer }>; options: string }
  | { type: 'reset-yara' }
export type YaraWorkerResponse =
  | { type: 'yara-progress'; jobId: string; stage: YaraProgressStage }
  | { type: 'yara-compiled'; jobId: string; summary: YaraCompileSummary }
  | { type: 'yara-completed'; jobId: string; report: YaraReport }
  | { type: 'yara-artifacts-completed'; jobId: string; results: ArtifactYaraResult[] }
  | { type: 'yara-failed'; jobId: string; message: string }
