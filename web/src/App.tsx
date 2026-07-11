import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { AnalysisClient } from './analysisClient'
import { formatBytes, formatLabel, formatMetadata, formatOffset, severityCounts } from './reportUtils'
import type { AnalysisReport, ExtractedString, ProgressStage, Severity, SymbolRecord } from './types'

const MAX_INPUT_BYTES = 128 * 1024 * 1024
const PAGE_SIZE = 100
type AppStatus = 'idle' | 'reading' | 'analyzing' | 'done' | 'error'
type Tab = 'overview' | 'structure' | 'symbols' | 'strings' | 'hex'

const progressLabels: Record<ProgressStage, string> = {
  'loading-engine': 'Loading isolated engine',
  parsing: 'Parsing binary structures',
  finalizing: 'Building explainable report',
}

export default function App() {
  const client = useMemo(() => new AnalysisClient(), [])
  const inputRef = useRef<HTMLInputElement>(null)
  const [status, setStatus] = useState<AppStatus>('idle')
  const [stage, setStage] = useState<ProgressStage>('loading-engine')
  const [report, setReport] = useState<AnalysisReport | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [dragging, setDragging] = useState(false)
  const [activeTab, setActiveTab] = useState<Tab>('overview')

  useEffect(() => () => client.close(), [client])

  const inspectFile = useCallback(async (file: File) => {
    if (file.size === 0) {
      setError('The selected file is empty.')
      setStatus('error')
      return
    }
    if (file.size > MAX_INPUT_BYTES) {
      setError(`This sample is ${formatBytes(file.size)}. The hard safety limit is 128 MiB.`)
      setStatus('error')
      return
    }

    setError(null)
    setReport(null)
    setActiveTab('overview')
    setStatus('reading')
    try {
      const buffer = await file.arrayBuffer()
      setStatus('analyzing')
      setStage('loading-engine')
      const result = await client.analyze(file, buffer, (nextStage) => setStage(nextStage))
      setReport(result)
      setStatus('done')
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Analysis failed unexpectedly.')
      setStatus('error')
    }
  }, [client])

  const analyzeDemo = useCallback(() => {
    const encoder = new TextEncoder()
    const sectionName = encoder.encode('meta')
    const indicator = encoder.encode('https://example.test')
    const payload = new Uint8Array(1 + sectionName.length + 1 + indicator.length)
    payload[0] = sectionName.length
    payload.set(sectionName, 1)
    payload.set(indicator, 2 + sectionName.length)
    const bytes = new Uint8Array(8 + 2 + payload.length)
    bytes.set([0, 97, 115, 109, 1, 0, 0, 0], 0)
    bytes.set([0, payload.length], 8)
    bytes.set(payload, 10)
    void inspectFile(new File([bytes], 'safe-demo.wasm', { type: 'application/wasm' }))
  }, [inspectFile])

  const closeSample = () => {
    client.close()
    setReport(null)
    setError(null)
    setStatus('idle')
    setActiveTab('overview')
  }

  const exportReport = () => {
    if (!report) return
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    const baseName = report.sample.name.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 120) || 'sample'
    anchor.href = url
    anchor.download = `${baseName}.aegis-report.json`
    anchor.click()
    window.setTimeout(() => URL.revokeObjectURL(url), 0)
  }

  const busy = status === 'reading' || status === 'analyzing'

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="#top" aria-label="Aegis home">
          <span className="brand-mark"><ShieldIcon /></span>
          <span>
            <strong>AEGIS</strong>
            <small>LOCAL BINARY TRIAGE</small>
          </span>
        </a>
        <div className="topbar-status" aria-label="Privacy status">
          <span className="pulse-dot" />
          <span>Network isolated</span>
          <span className="status-divider" />
          <span>Rust / Wasm</span>
        </div>
      </header>

      <main id="top">
        <section className="hero">
          <div className="hero-grid" aria-hidden="true" />
          <div className="eyebrow"><span>01</span> STATIC ANALYSIS WORKBENCH</div>
          <h1>Inspect suspicious binaries.<br /><em>Keep them contained.</em></h1>
          <p className="hero-copy">
            Parse PE, ELF, Mach-O, and WebAssembly samples entirely inside your browser.
            No uploads, no execution, no telemetry.
          </p>

          <div
            className={`drop-zone ${dragging ? 'is-dragging' : ''} ${busy ? 'is-busy' : ''}`}
            onDragEnter={(event) => { event.preventDefault(); setDragging(true) }}
            onDragOver={(event) => event.preventDefault()}
            onDragLeave={(event) => { if (event.currentTarget === event.target) setDragging(false) }}
            onDrop={(event) => {
              event.preventDefault()
              setDragging(false)
              const file = event.dataTransfer.files[0]
              if (file) void inspectFile(file)
            }}
          >
            {busy ? (
              <AnalysisProgress status={status} stage={stage} onCancel={closeSample} />
            ) : (
              <>
                <div className="drop-icon"><ScanIcon /></div>
                <div className="drop-copy">
                  <strong>Drop a binary to begin</strong>
                  <span>or select a file from this device · 128 MiB maximum</span>
                </div>
                <div className="drop-actions">
                  <button className="button primary" type="button" onClick={() => inputRef.current?.click()}>
                    <UploadIcon /> Select binary
                  </button>
                  <button className="button ghost" type="button" onClick={analyzeDemo}>Try safe demo</button>
                </div>
              </>
            )}
            <input
              ref={inputRef}
              data-testid="file-input"
              type="file"
              hidden
              onChange={(event) => {
                const file = event.target.files?.[0]
                if (file) void inspectFile(file)
                event.currentTarget.value = ''
              }}
            />
          </div>

          <div className="trust-row">
            <TrustItem icon={<LockIcon />} title="In-memory only" text="Sample bytes disappear when closed" />
            <TrustItem icon={<NoNetworkIcon />} title="No external access" text="A strict CSP blocks third-party requests" />
            <TrustItem icon={<CpuIcon />} title="Never executed" text="Every upload is treated as inert data" />
          </div>
        </section>

        {status === 'error' && error && (
          <section className="error-banner" role="alert">
            <div><AlertIcon /></div>
            <span><strong>Analysis stopped safely</strong>{error}</span>
            <button type="button" onClick={closeSample} aria-label="Dismiss error">×</button>
          </section>
        )}

        {report && status === 'done' && (
          <ReportWorkspace
            report={report}
            client={client}
            activeTab={activeTab}
            onTabChange={setActiveTab}
            onClose={closeSample}
            onExport={exportReport}
          />
        )}

        {!report && !busy && (
          <section className="capabilities" aria-label="Analysis capabilities">
            <div className="section-heading">
              <span>WHAT AEGIS READS</span>
              <h2>Fast triage, explainable evidence.</h2>
            </div>
            <div className="capability-grid">
              <Capability number="01" title="Binary structure" text="Headers, sections, permissions, entry points, architectures, and format-specific metadata." />
              <Capability number="02" title="Linkage surface" text="Imported libraries, functions, exported symbols, dynamic paths, and runtime dependencies." />
              <Capability number="03" title="Suspicious signals" text="Entropy, executable-writeable regions, embedded URLs, IPs, commands, and structural anomalies." />
              <Capability number="04" title="Identifiable evidence" text="SHA-256, SHA-1, MD5 identifiers, file offsets, bounded strings, and portable JSON reports." />
            </div>
          </section>
        )}
      </main>

      <footer>
        <span>AEGIS 0.1</span>
        <span>Static signals are not a malware verdict.</span>
        <span>Built with Rust + WebAssembly</span>
      </footer>
    </div>
  )
}

function AnalysisProgress({ status, stage, onCancel }: { status: AppStatus; stage: ProgressStage; onCancel: () => void }) {
  return (
    <div className="analysis-progress" role="status" aria-live="polite">
      <div className="scanner"><span /></div>
      <div>
        <strong>{status === 'reading' ? 'Reading sample locally' : progressLabels[stage]}</strong>
        <span>The interface remains isolated while Rust inspects the file.</span>
      </div>
      <button className="button ghost compact" type="button" onClick={onCancel}>Cancel</button>
    </div>
  )
}

function TrustItem({ icon, title, text }: { icon: React.ReactNode; title: string; text: string }) {
  return <div className="trust-item"><span>{icon}</span><div><strong>{title}</strong><small>{text}</small></div></div>
}

function Capability({ number, title, text }: { number: string; title: string; text: string }) {
  return <article className="capability-card"><span>{number}</span><h3>{title}</h3><p>{text}</p></article>
}

function ReportWorkspace({ report, client, activeTab, onTabChange, onClose, onExport }: {
  report: AnalysisReport
  client: AnalysisClient
  activeTab: Tab
  onTabChange: (tab: Tab) => void
  onClose: () => void
  onExport: () => void
}) {
  const tabs: Array<{ id: Tab; label: string; count?: number }> = [
    { id: 'overview', label: 'Overview', count: report.findings.length },
    { id: 'structure', label: 'Structure', count: report.sections.length },
    { id: 'symbols', label: 'Imports / Exports', count: report.imports.length + report.exports.length },
    { id: 'strings', label: 'Strings / IOCs', count: report.strings.length },
    { id: 'hex', label: 'Hex view' },
  ]
  return (
    <section className="workspace" aria-label="Analysis report">
      <div className="sample-bar">
        <div className="file-badge"><FileIcon /></div>
        <div className="sample-identity">
          <span className="format-chip">{formatLabel(report.sample.detected_format)}</span>
          <strong title={report.sample.name}>{report.sample.name}</strong>
          <small>{formatBytes(report.sample.size)} · {report.sample.architecture ?? 'Architecture unavailable'}</small>
        </div>
        <div className="sample-actions">
          <button className="button ghost compact" type="button" onClick={onExport}><DownloadIcon /> Export JSON</button>
          <button className="icon-button" type="button" onClick={onClose} aria-label="Close sample">×</button>
        </div>
      </div>

      <div className="tabs" role="tablist" aria-label="Report sections">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            type="button"
            role="tab"
            aria-selected={activeTab === tab.id}
            className={activeTab === tab.id ? 'active' : ''}
            onClick={() => onTabChange(tab.id)}
          >
            {tab.label}{tab.count != null && <span>{tab.count.toLocaleString()}</span>}
          </button>
        ))}
      </div>

      <div className="workspace-content" role="tabpanel">
        {activeTab === 'overview' && <Overview report={report} />}
        {activeTab === 'structure' && <StructureView report={report} />}
        {activeTab === 'symbols' && <SymbolsView report={report} />}
        {activeTab === 'strings' && <StringsView report={report} />}
        {activeTab === 'hex' && <HexView client={client} sampleSize={report.sample.size} />}
      </div>
    </section>
  )
}

function Overview({ report }: { report: AnalysisReport }) {
  const counts = severityCounts(report)
  const metadata = formatMetadata(report)
  return (
    <div className="overview-layout">
      <div className="overview-main">
        <div className="metric-grid">
          <Metric label="Format" value={formatLabel(report.sample.detected_format)} detail={`Schema v${report.schema_version}`} />
          <Metric label="Static signals" value={String(report.findings.length - counts.info)} detail={`${counts.high} high · ${counts.medium} medium`} />
          <Metric label="Analysis time" value={`${report.stats.elapsed_ms.toFixed(report.stats.elapsed_ms < 10 ? 2 : 1)} ms`} detail={`${formatBytes(report.stats.bytes_scanned)} scanned`} />
        </div>

        {report.warnings.length > 0 && (
          <div className="warning-list">
            {report.warnings.map((warning, index) => <div key={`${warning.code}-${index}`}><AlertIcon /><span><strong>{warning.code}</strong>{warning.message}</span></div>)}
          </div>
        )}

        <Panel title="Explainable findings" subtitle="Signals are ordered by severity and backed by file evidence.">
          <div className="finding-list">
            {report.findings.map((finding, index) => (
              <article className={`finding severity-${finding.severity}`} key={`${finding.id}-${index}`}>
                <div className="finding-level"><span>{finding.severity}</span><small>{finding.confidence} confidence</small></div>
                <div className="finding-body">
                  <h4>{finding.title}</h4>
                  <p>{finding.rationale}</p>
                  {finding.evidence.length > 0 && <div className="evidence-row">{finding.evidence.map((evidence, evidenceIndex) => <code key={evidenceIndex}>{evidence.offset != null && `${formatOffset(evidence.offset)} · `}{evidence.value}</code>)}</div>}
                </div>
              </article>
            ))}
          </div>
        </Panel>
      </div>

      <aside className="overview-side">
        <Panel title="Cryptographic identifiers" subtitle="SHA-1 and MD5 are shown for ecosystem matching only.">
          <Hash label="SHA-256" value={report.sample.sha256} />
          <Hash label="SHA-1" value={report.sample.sha1} />
          <Hash label="MD5" value={report.sample.md5} />
        </Panel>
        <Panel title="Format metadata" subtitle={`${metadata.length} parsed properties`}>
          <dl className="metadata-list">
            {metadata.map(([label, value]) => <div key={label}><dt>{label}</dt><dd title={value}>{value}</dd></div>)}
          </dl>
        </Panel>
        <div className="safety-note"><LockIcon /><div><strong>Sample remained local</strong><span>No bytes were persisted or transmitted.</span></div></div>
      </aside>
    </div>
  )
}

function Metric({ label, value, detail }: { label: string; value: string; detail: string }) {
  return <div className="metric"><span>{label}</span><strong>{value}</strong><small>{detail}</small></div>
}

function Panel({ title, subtitle, children }: { title: string; subtitle?: string; children: React.ReactNode }) {
  return <section className="panel"><header><div><h3>{title}</h3>{subtitle && <p>{subtitle}</p>}</div></header><div className="panel-body">{children}</div></section>
}

function Hash({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false)
  return <div className="hash-row"><span>{label}</span><code title={value}>{value}</code><button type="button" onClick={() => { void navigator.clipboard.writeText(value); setCopied(true); window.setTimeout(() => setCopied(false), 1200) }}>{copied ? 'Copied' : 'Copy'}</button></div>
}

function StructureView({ report }: { report: AnalysisReport }) {
  return (
    <Panel title="Sections and regions" subtitle={`${report.sections.length.toLocaleString()} bounded records · entropy measured in bits per byte`}>
      {report.sections.length === 0 ? <EmptyState title="No section table available" text="This format did not expose section records in the current analysis view." /> : (
        <div className="table-scroll"><table><thead><tr><th>Name</th><th>File offset</th><th>Virtual address</th><th>Size</th><th>Permissions</th><th>Entropy</th></tr></thead><tbody>
          {report.sections.map((section, index) => <tr key={`${section.name}-${index}`}><td><code className="strong-code">{section.name}</code></td><td><code>{formatOffset(section.offset)}</code></td><td><code>{formatOffset(section.virtual_address)}</code></td><td>{formatBytes(section.size)}</td><td><span className={`permission ${section.permissions.includes('w') && section.permissions.includes('x') ? 'danger' : ''}`}>{section.permissions}</span></td><td><div className="entropy"><span><i style={{ width: `${section.entropy / 8 * 100}%` }} /></span><code>{section.entropy.toFixed(2)}</code></div></td></tr>)}
        </tbody></table></div>
      )}
    </Panel>
  )
}

function SymbolsView({ report }: { report: AnalysisReport }) {
  const [mode, setMode] = useState<'imports' | 'exports'>('imports')
  const records = mode === 'imports' ? report.imports : report.exports
  return (
    <Panel title="Linked symbols" subtitle="Names and addresses are parsed without resolving or loading any dependency.">
      <div className="segmented"><button type="button" className={mode === 'imports' ? 'active' : ''} onClick={() => setMode('imports')}>Imports <span>{report.imports.length}</span></button><button type="button" className={mode === 'exports' ? 'active' : ''} onClick={() => setMode('exports')}>Exports <span>{report.exports.length}</span></button></div>
      <SymbolTable records={records} />
    </Panel>
  )
}

function SymbolTable({ records }: { records: SymbolRecord[] }) {
  const [page, setPage] = useState(0)
  useEffect(() => setPage(0), [records])
  const pages = Math.max(1, Math.ceil(records.length / PAGE_SIZE))
  const visible = records.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)
  if (records.length === 0) return <EmptyState title="No symbols found" text="The binary does not expose symbols of this kind." />
  return <><div className="table-scroll"><table><thead><tr><th>Symbol</th><th>Module</th><th>Kind</th><th>Address / index</th></tr></thead><tbody>{visible.map((record, index) => <tr key={`${record.name}-${index}`}><td><code className="strong-code">{record.name}</code></td><td>{record.module ?? '—'}</td><td><span className="kind-chip">{record.kind}</span></td><td><code>{formatOffset(record.address)}</code></td></tr>)}</tbody></table></div><Pagination page={page} pages={pages} count={records.length} onPage={setPage} /></>
}

function StringsView({ report }: { report: AnalysisReport }) {
  const [query, setQuery] = useState('')
  const [mode, setMode] = useState<'strings' | 'indicators'>('strings')
  const [page, setPage] = useState(0)
  const strings = useMemo(() => report.strings.filter((item) => item.value.toLocaleLowerCase().includes(query.toLocaleLowerCase())), [query, report.strings])
  const indicators = useMemo(() => report.indicators.filter((item) => `${item.kind} ${item.value}`.toLocaleLowerCase().includes(query.toLocaleLowerCase())), [query, report.indicators])
  const records = mode === 'strings' ? strings : indicators
  const pages = Math.max(1, Math.ceil(records.length / PAGE_SIZE))
  useEffect(() => setPage(0), [mode, query])
  return (
    <Panel title="Strings and indicators" subtitle="Bounded extraction with offsets; values are deliberately rendered as non-clickable text.">
      <div className="table-tools"><div className="segmented"><button type="button" className={mode === 'strings' ? 'active' : ''} onClick={() => setMode('strings')}>Strings <span>{report.strings.length}</span></button><button type="button" className={mode === 'indicators' ? 'active' : ''} onClick={() => setMode('indicators')}>Indicators <span>{report.indicators.length}</span></button></div><label className="search"><SearchIcon /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Filter extracted values" aria-label="Filter extracted values" /></label></div>
      {records.length === 0 ? <EmptyState title="No matching values" text={query ? 'Try a broader filter.' : 'No values of this type were extracted.'} /> : (
        <><div className="table-scroll"><table><thead><tr><th>Offset</th><th>{mode === 'strings' ? 'Encoding' : 'Type'}</th><th>Value</th></tr></thead><tbody>{records.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE).map((record, index) => <StringRow key={`${record.offset}-${index}`} record={record as ExtractedString & { kind?: string }} />)}</tbody></table></div><Pagination page={page} pages={pages} count={records.length} onPage={setPage} /></>
      )}
    </Panel>
  )
}

function StringRow({ record }: { record: ExtractedString & { kind?: string } }) {
  return <tr><td><code>{formatOffset(record.offset)}</code></td><td><span className="kind-chip">{record.kind ?? record.encoding}</span></td><td><code className="string-value">{record.value}</code></td></tr>
}

function HexView({ client, sampleSize }: { client: AnalysisClient; sampleSize: number }) {
  const pageSize = 512
  const [offset, setOffset] = useState(0)
  const [bytes, setBytes] = useState<Uint8Array>(new Uint8Array())
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    let alive = true
    setError(null)
    client.readHex(offset, pageSize).then((result) => { if (alive) setBytes(result.bytes) }).catch((cause) => { if (alive) setError(cause instanceof Error ? cause.message : 'Hex read failed') })
    return () => { alive = false }
  }, [client, offset])
  const rows = []
  for (let index = 0; index < bytes.length; index += 16) rows.push(bytes.slice(index, index + 16))
  return (
    <Panel title="Paged hex view" subtitle="Only 512 bytes are copied from the isolated worker at a time.">
      <div className="hex-toolbar"><button className="button ghost compact" type="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - pageSize))}>← Previous</button><code>{formatOffset(offset)} — {formatOffset(Math.min(offset + bytes.length, sampleSize))}</code><button className="button ghost compact" type="button" disabled={offset + pageSize >= sampleSize} onClick={() => setOffset(offset + pageSize)}>Next →</button></div>
      {error ? <EmptyState title="Hex view unavailable" text={error} /> : <div className="hex-view">{rows.map((row, rowIndex) => <div className="hex-row" key={rowIndex}><span>{formatOffset(offset + rowIndex * 16)}</span><code>{Array.from(row).map((byte) => byte.toString(16).padStart(2, '0')).join(' ').padEnd(47, ' ')}</code><code>{Array.from(row).map((byte) => byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.').join('')}</code></div>)}</div>}
    </Panel>
  )
}

function Pagination({ page, pages, count, onPage }: { page: number; pages: number; count: number; onPage: (page: number) => void }) {
  if (pages <= 1) return null
  return <div className="pagination"><span>{count.toLocaleString()} records · page {page + 1} of {pages}</span><div><button type="button" disabled={page === 0} onClick={() => onPage(page - 1)}>←</button><button type="button" disabled={page + 1 >= pages} onClick={() => onPage(page + 1)}>→</button></div></div>
}

function EmptyState({ title, text }: { title: string; text: string }) {
  return <div className="empty-state"><ScanIcon /><strong>{title}</strong><span>{text}</span></div>
}

const icon = (path: React.ReactNode) => <svg viewBox="0 0 24 24" aria-hidden="true">{path}</svg>
function ShieldIcon() { return icon(<><path d="M12 2 20 5v6c0 5-3.3 9.3-8 11-4.7-1.7-8-6-8-11V5l8-3Z"/><path d="m8.5 12 2.2 2.2 4.8-5"/></>) }
function ScanIcon() { return icon(<><path d="M4 8V4h4M16 4h4v4M20 16v4h-4M8 20H4v-4"/><path d="M8 12h8M12 8v8"/></>) }
function UploadIcon() { return icon(<><path d="M12 16V4M7 9l5-5 5 5"/><path d="M5 15v4h14v-4"/></>) }
function LockIcon() { return icon(<><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/></>) }
function NoNetworkIcon() { return icon(<><path d="M5 12.5a10 10 0 0 1 14 0M8 16a6 6 0 0 1 8 0M11 19a2 2 0 0 1 2 0"/><path d="m4 4 16 16"/></>) }
function CpuIcon() { return icon(<><rect x="7" y="7" width="10" height="10" rx="1"/><path d="M9 1v4M15 1v4M9 19v4M15 19v4M1 9h4M1 15h4M19 9h4M19 15h4M10 10h4v4h-4z"/></>) }
function AlertIcon() { return icon(<><path d="M12 3 2.5 20h19L12 3Z"/><path d="M12 9v5M12 17h.01"/></>) }
function FileIcon() { return icon(<><path d="M6 2h8l4 4v16H6z"/><path d="M14 2v5h5M9 12h6M9 16h6"/></>) }
function DownloadIcon() { return icon(<><path d="M12 3v12M7 10l5 5 5-5"/><path d="M5 20h14"/></>) }
function SearchIcon() { return icon(<><circle cx="11" cy="11" r="7"/><path d="m16 16 5 5"/></>) }
