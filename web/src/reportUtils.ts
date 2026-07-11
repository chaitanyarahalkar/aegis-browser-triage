import type { AnalysisReport, BinaryFormat, Severity } from './types'

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '—'
  const units = ['B', 'KiB', 'MiB', 'GiB']
  let value = bytes
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit += 1
  }
  const precision = unit === 0 || value >= 100 ? 0 : value >= 10 ? 1 : 2
  return `${value.toFixed(precision)} ${units[unit]}`
}

export function formatOffset(value: number | null): string {
  return value == null ? '—' : `0x${value.toString(16).padStart(value > 0xffff_ffff ? 16 : 8, '0')}`
}

export function formatLabel(format: BinaryFormat): string {
  return ({ pe: 'PE', elf: 'ELF', mach_o: 'Mach-O', web_assembly: 'WebAssembly', unknown: 'Unknown' })[format]
}

export function severityCounts(report: AnalysisReport): Record<Severity, number> {
  const counts: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0 }
  for (const finding of report.findings) counts[finding.severity] += 1
  return counts
}

export function formatMetadata(report: AnalysisReport): Array<[string, string]> {
  return Object.entries(report.format)
    .filter(([key]) => key !== 'kind')
    .map(([key, value]) => [humanize(key), displayValue(value)])
}

function displayValue(value: unknown): string {
  if (value == null) return 'Not present'
  if (typeof value === 'boolean') return value ? 'Yes' : 'No'
  if (Array.isArray(value)) {
    if (value.length === 0) return 'None'
    if (value.every((entry) => typeof entry === 'string')) return value.join(', ')
    return `${value.length} entries`
  }
  if (typeof value === 'number' && value > 4096) return `${value.toLocaleString()}  ·  0x${value.toString(16)}`
  return String(value)
}

function humanize(value: string): string {
  return value.replaceAll('_', ' ').replace(/\b\w/g, (character) => character.toUpperCase())
}
