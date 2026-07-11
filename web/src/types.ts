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

