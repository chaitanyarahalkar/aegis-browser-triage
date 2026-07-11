import { describe, expect, it } from 'vitest'
import { formatBytes, formatLabel, formatMetadata, formatOffset, severityCounts } from './reportUtils'
import type { AnalysisReport } from './types'

const report: AnalysisReport = {
  schema_version: 1,
  engine_version: '0.1.0',
  sample: { name: 'demo.wasm', size: 42, detected_format: 'web_assembly', architecture: 'WebAssembly', sha256: 'a', sha1: 'b', md5: 'c' },
  format: { kind: 'web_assembly', valid: true, custom_sections: ['meta'], entry_point: 8192 },
  sections: [], imports: [], exports: [], strings: [], indicators: [], warnings: [],
  findings: [
    { id: 'one', title: 'one', severity: 'high', confidence: 'high', rationale: '', evidence: [] },
    { id: 'two', title: 'two', severity: 'info', confidence: 'high', rationale: '', evidence: [] },
  ],
  stats: { elapsed_ms: 1, bytes_scanned: 42, strings_truncated: false, collections_truncated: false },
}

describe('report formatting', () => {
  it('formats byte quantities and offsets', () => {
    expect(formatBytes(0)).toBe('0 B')
    expect(formatBytes(1536)).toBe('1.50 KiB')
    expect(formatBytes(128 * 1024 * 1024)).toBe('128 MiB')
    expect(formatOffset(255)).toBe('0x000000ff')
    expect(formatOffset(null)).toBe('—')
  })

  it('labels every supported binary format', () => {
    expect(formatLabel('pe')).toBe('PE')
    expect(formatLabel('elf')).toBe('ELF')
    expect(formatLabel('mach_o')).toBe('Mach-O')
    expect(formatLabel('web_assembly')).toBe('WebAssembly')
    expect(formatLabel('unknown')).toBe('Unknown')
  })

  it('counts severities and creates readable metadata', () => {
    expect(severityCounts(report)).toEqual({ info: 1, low: 0, medium: 0, high: 1 })
    expect(formatMetadata(report)).toContainEqual(['Valid', 'Yes'])
    expect(formatMetadata(report)).toContainEqual(['Custom Sections', 'meta'])
    expect(formatMetadata(report)).toContainEqual(['Entry Point', '8,192  ·  0x2000'])
  })
})

