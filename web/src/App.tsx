import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { AnalysisClient } from './analysisClient'
import { DynamicAnalysisClient } from './dynamicClient'
import { YaraClient } from './yaraClient'
import starterRules from './rules/aegis-starter.yar?raw'
import { formatBytes, formatLabel, formatMetadata, formatOffset, severityCounts } from './reportUtils'
import type {
  AnalysisReport,
  ArtifactYaraResult,
  DynamicProgressStage,
  DynamicEnvironmentProfile,
  DynamicReport,
  DynamicTermination,
  ExtractedString,
  ProgressStage,
  SymbolRecord,
  YaraCompileSummary,
  YaraProgressStage,
  YaraReport,
} from './types'

const MAX_INPUT_BYTES = 128 * 1024 * 1024
const PAGE_SIZE = 100
const ENVIRONMENT_PROFILES: DynamicEnvironmentProfile[] = [
  { id: 'balanced', label: 'Balanced workstation', windows_version: 'Windows 10 22H2', computer_name: 'AEGIS-WORKSTATION', user_name: 'analyst', locale: 'en-US', timezone_offset_minutes: -360, memory_mb: 8192, cpu_count: 4, debugger_present: false, network_mode: 'online', initial_virtual_time_ms: 1_000_000 },
  { id: 'legacy', label: 'Legacy workstation', windows_version: 'Windows 7 SP1', computer_name: 'OFFICE-PC', user_name: 'user', locale: 'en-US', timezone_offset_minutes: -300, memory_mb: 2048, cpu_count: 2, debugger_present: false, network_mode: 'online', initial_virtual_time_ms: 500_000 },
  { id: 'hardened', label: 'Hardened offline host', windows_version: 'Windows 11 24H2', computer_name: 'CORP-WKS-042', user_name: 'employee', locale: 'en-GB', timezone_offset_minutes: 0, memory_mb: 16384, cpu_count: 8, debugger_present: false, network_mode: 'offline', initial_virtual_time_ms: 2_000_000 },
  { id: 'analysis', label: 'Instrumented analysis host', windows_version: 'Windows 10 analysis', computer_name: 'MALWARE-LAB', user_name: 'sandbox', locale: 'en-US', timezone_offset_minutes: 0, memory_mb: 1024, cpu_count: 1, debugger_present: true, network_mode: 'sinkhole', initial_virtual_time_ms: 3_000_000 },
]
type AppStatus = 'idle' | 'reading' | 'analyzing' | 'done' | 'error'
type DynamicStatus = 'idle' | 'running' | 'done' | 'error'
type YaraStatus = 'idle' | 'running' | 'done' | 'error'
type Tab = 'summary' | 'structure' | 'symbols' | 'strings' | 'hex' | 'dynamic' | 'yara'

const progressLabels: Record<ProgressStage, string> = {
  'loading-engine': 'Loading analysis engine',
  parsing: 'Parsing binary',
  finalizing: 'Preparing report',
}

const dynamicProgressLabels: Record<DynamicProgressStage, string> = {
  'loading-engine': 'Loading x86 interpreter',
  'loading-image': 'Mapping PE image',
  executing: 'Emulating instructions',
  finalizing: 'Preparing behavior report',
}

export default function App() {
  const staticClient = useMemo(() => new AnalysisClient(), [])
  const dynamicClient = useMemo(() => new DynamicAnalysisClient(), [])
  const yaraClient = useMemo(() => new YaraClient(), [])
  const inputRef = useRef<HTMLInputElement>(null)
  const dynamicRun = useRef(0)
  const [status, setStatus] = useState<AppStatus>('idle')
  const [stage, setStage] = useState<ProgressStage>('loading-engine')
  const [report, setReport] = useState<AnalysisReport | null>(null)
  const [currentFile, setCurrentFile] = useState<File | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [dragging, setDragging] = useState(false)
  const [activeTab, setActiveTab] = useState<Tab>('summary')
  const [dynamicStatus, setDynamicStatus] = useState<DynamicStatus>('idle')
  const [dynamicStage, setDynamicStage] = useState<DynamicProgressStage>('loading-engine')
  const [dynamicReport, setDynamicReport] = useState<DynamicReport | null>(null)
  const [dynamicReports, setDynamicReports] = useState<DynamicReport[]>([])
  const [dynamicProfileId, setDynamicProfileId] = useState('balanced')
  const [dynamicError, setDynamicError] = useState<string | null>(null)
  const [yaraSource, setYaraSource] = useState(starterRules)
  const [yaraSourceName, setYaraSourceName] = useState('aegis-starter.yar')
  const [yaraStatus, setYaraStatus] = useState<YaraStatus>('idle')
  const [yaraStage, setYaraStage] = useState<YaraProgressStage>('loading-engine')
  const [yaraSummary, setYaraSummary] = useState<YaraCompileSummary | null>(null)
  const [yaraReport, setYaraReport] = useState<YaraReport | null>(null)
  const [yaraError, setYaraError] = useState<string | null>(null)
  const [hexTarget, setHexTarget] = useState<number | null>(null)
  const [artifactYara, setArtifactYara] = useState<ArtifactYaraResult[]>([])
  const [artifactYaraStatus, setArtifactYaraStatus] = useState<'idle' | 'running' | 'done' | 'error'>('idle')
  const [artifactYaraError, setArtifactYaraError] = useState<string | null>(null)

  useEffect(() => {
    staticClient.warmup()
    return () => {
      staticClient.dispose()
      dynamicClient.close()
      yaraClient.close()
    }
  }, [dynamicClient, staticClient, yaraClient])

  const resetDynamic = useCallback(() => {
    dynamicRun.current += 1
    dynamicClient.close()
    setDynamicStatus('idle')
    setDynamicStage('loading-engine')
    setDynamicReport(null)
    setDynamicReports([])
    setDynamicError(null)
    setArtifactYara([])
    setArtifactYaraStatus('idle')
    setArtifactYaraError(null)
  }, [dynamicClient])

  const inspectFile = useCallback(async (file: File) => {
    if (file.size === 0) {
      setError('The selected file is empty.')
      setStatus('error')
      return
    }
    if (file.size > MAX_INPUT_BYTES) {
      setError(`This file is ${formatBytes(file.size)}. The maximum is 128 MiB.`)
      setStatus('error')
      return
    }

    resetDynamic()
    setYaraReport(null)
    setArtifactYara([])
    setArtifactYaraStatus('idle')
    setArtifactYaraError(null)
    setCurrentFile(file)
    setError(null)
    setReport(null)
    setActiveTab('summary')
    setStatus('reading')
    try {
      const buffer = await file.arrayBuffer()
      setStatus('analyzing')
      setStage('loading-engine')
      const result = await staticClient.analyze(file, buffer, setStage)
      setReport(result)
      setStatus('done')
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Analysis failed unexpectedly.')
      setStatus('error')
    }
  }, [resetDynamic, staticClient])

  const compileAndScanYara = useCallback(async () => {
    if (!currentFile) return
    setYaraStatus('running')
    setYaraError(null)
    setYaraReport(null)
    try {
      const summary = await yaraClient.compile(yaraSource, yaraSourceName, 'Analyst rules', setYaraStage)
      setYaraSummary(summary)
      const buffer = await currentFile.arrayBuffer()
      const result = await yaraClient.scan(currentFile, buffer, setYaraStage)
      setYaraReport(result)
      setYaraStatus('done')
    } catch (cause) {
      setYaraError(parseYaraError(cause))
      setYaraStatus('error')
    }
  }, [currentFile, yaraClient, yaraSource, yaraSourceName])

  const analyzeDemo = useCallback(async () => {
    try {
      const response = await fetch(`${import.meta.env.BASE_URL}fixtures/aegis-safe-dynamic-pe32.exe`)
      if (!response.ok) throw new Error('Safe fixture could not be loaded')
      const bytes = await response.arrayBuffer()
      await inspectFile(new File([bytes], 'aegis-safe-dynamic-pe32.exe', { type: 'application/octet-stream' }))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Safe fixture could not be loaded')
      setStatus('error')
    }
  }, [inspectFile])

  const analyzeArtifactDemo = useCallback(async () => {
    try {
      const name = 'aegis-safe-runtime-artifact-pe32.exe'
      const response = await fetch(`${import.meta.env.BASE_URL}fixtures/${name}`)
      if (!response.ok) throw new Error('Runtime artifact fixture could not be loaded')
      const bytes = await response.arrayBuffer()
      await inspectFile(new File([bytes], name, { type: 'application/octet-stream' }))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Runtime artifact fixture could not be loaded')
      setStatus('error')
    }
  }, [inspectFile])

  const runDynamicAnalysis = useCallback(async () => {
    if (!currentFile) return
    const run = ++dynamicRun.current
    setDynamicStatus('running')
    setDynamicError(null)
    setDynamicReport(null)
    setDynamicStage('loading-engine')
    setArtifactYara([])
    setArtifactYaraStatus('idle')
    setArtifactYaraError(null)
    try {
      const buffer = await currentFile.arrayBuffer()
      const environment = ENVIRONMENT_PROFILES.find((profile) => profile.id === dynamicProfileId) ?? ENVIRONMENT_PROFILES[0]
      const result = await dynamicClient.analyze(currentFile, buffer, setDynamicStage, environment)
      if (dynamicRun.current !== run) return
      setDynamicReport(result)
      setDynamicReports([result])
      setDynamicStatus('done')
    } catch (cause) {
      if (dynamicRun.current !== run) return
      setDynamicError(cause instanceof Error ? cause.message : 'Dynamic analysis failed unexpectedly.')
      setDynamicStatus('error')
    }
  }, [currentFile, dynamicClient, dynamicProfileId])

  const runDynamicProfiles = useCallback(async () => {
    if (!currentFile) return
    const run = ++dynamicRun.current
    setDynamicStatus('running'); setDynamicError(null); setDynamicReport(null); setDynamicReports([]); setDynamicStage('loading-engine')
    setArtifactYara([]); setArtifactYaraStatus('idle'); setArtifactYaraError(null)
    try {
      const buffer = await currentFile.arrayBuffer()
      const results = await dynamicClient.analyzeProfiles(currentFile, buffer, ENVIRONMENT_PROFILES, setDynamicStage)
      if (dynamicRun.current !== run) return
      setDynamicReports(results)
      setDynamicReport(results.find((result) => result.profile.environment.id === dynamicProfileId) ?? results[0])
      setDynamicStatus('done')
    } catch (cause) {
      if (dynamicRun.current !== run) return
      setDynamicError(cause instanceof Error ? cause.message : 'Profile matrix analysis failed unexpectedly.')
      setDynamicStatus('error')
    }
  }, [currentFile, dynamicClient, dynamicProfileId])

  const selectDynamicProfile = useCallback((profileId: string) => {
    setDynamicProfileId(profileId)
    const existing = dynamicReports.find((result) => result.profile.environment.id === profileId)
    if (existing) { setDynamicReport(existing); setArtifactYara([]); setArtifactYaraStatus('idle'); setArtifactYaraError(null) }
    else if (dynamicReport) { setDynamicReport(null); setDynamicReports([]); setDynamicStatus('idle') }
  }, [dynamicReport, dynamicReports])

  const scanDynamicArtifacts = useCallback(async () => {
    if (!dynamicReport?.artifacts.length) return
    setArtifactYaraStatus('running'); setArtifactYaraError(null); setArtifactYara([])
    try {
      await yaraClient.compile(yaraSource, yaraSourceName, 'Analyst rules', setYaraStage)
      const artifacts = await Promise.all(dynamicReport.artifacts.map(async (artifact) => {
        const result = await dynamicClient.readArtifact(dynamicReport.profile.environment.id, artifact.id)
        return { id: artifact.id, name: artifact.name, buffer: result.bytes.buffer }
      }))
      const results = await yaraClient.scanArtifacts(artifacts, setYaraStage)
      setArtifactYara(results); setArtifactYaraStatus('done')
    } catch (cause) {
      setArtifactYaraError(cause instanceof Error ? cause.message : 'Artifact YARA scan failed')
      setArtifactYaraStatus('error')
    }
  }, [dynamicClient, dynamicReport, yaraClient, yaraSource, yaraSourceName])

  const cancelDynamic = () => {
    dynamicRun.current += 1
    dynamicClient.cancel()
    setDynamicStatus('idle')
    setDynamicError(null)
  }

  const closeSample = () => {
    staticClient.close()
    resetDynamic()
    setCurrentFile(null)
    setReport(null)
    setError(null)
    setStatus('idle')
    setActiveTab('summary')
  }

  const exportReport = () => {
    if (!report) return
    const payload = { static: report, ...(dynamicReport ? { dynamic: { ...dynamicReport, ...(artifactYara.length ? { artifact_yara: artifactYara } : {}) } } : {}), ...(dynamicReports.length > 1 ? { dynamic_profiles: dynamicReports } : {}), ...(yaraReport ? { yara: yaraReport } : {}) }
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
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
      <header className="app-header">
        <a className="wordmark" href="#top" aria-label="Aegis home">
          <span>A</span>
          <strong>Aegis</strong>
        </a>
        <div className="header-meta">
          <span className="quiet-status"><i /> Local only</span>
          <span>Static + dynamic analysis</span>
        </div>
      </header>

      <main id="top" className="page">
        {!report && !busy && (
          <section className="intro">
            <div className="intro-copy">
              <p className="kicker">Browser-native binary analysis</p>
              <h1>Analyze binaries locally.</h1>
              <p>Static inspection and bounded x86 emulation. Files stay in this browser and are never executed by the host.</p>
            </div>
            <UploadPanel
              dragging={dragging}
              setDragging={setDragging}
              inputRef={inputRef}
              inspectFile={inspectFile}
              analyzeDemo={analyzeDemo}
              analyzeArtifactDemo={analyzeArtifactDemo}
            />
            <div className="privacy-row">
              <span>No uploads</span>
              <span>No external network</span>
              <span>Ephemeral memory</span>
              <span>128 MiB limit</span>
            </div>
          </section>
        )}

        {busy && <StaticProgress status={status} stage={stage} onCancel={closeSample} />}

        {status === 'error' && error && (
          <div className="notice error-notice" role="alert">
            <div><strong>Analysis stopped</strong><span>{error}</span></div>
            <button type="button" onClick={() => error.startsWith('The analyzer could not start') ? window.location.reload() : closeSample}>
              {error.startsWith('The analyzer could not start') ? 'Reload app' : 'Dismiss'}
            </button>
          </div>
        )}

        {report && status === 'done' && (
          <Workspace
            report={report}
            dynamicReport={dynamicReport}
            dynamicReports={dynamicReports}
            dynamicProfileId={dynamicProfileId}
            dynamicStatus={dynamicStatus}
            dynamicStage={dynamicStage}
            dynamicError={dynamicError}
            staticClient={staticClient}
            activeTab={activeTab}
            onTabChange={setActiveTab}
            onClose={closeSample}
            onExport={exportReport}
            onRunDynamic={runDynamicAnalysis}
            onRunDynamicProfiles={runDynamicProfiles}
            onSelectDynamicProfile={selectDynamicProfile}
            onCancelDynamic={cancelDynamic}
            dynamicClient={dynamicClient}
            artifactYara={artifactYara}
            artifactYaraStatus={artifactYaraStatus}
            artifactYaraError={artifactYaraError}
            onScanArtifacts={scanDynamicArtifacts}
            yaraSource={yaraSource}
            yaraSourceName={yaraSourceName}
            yaraStatus={yaraStatus}
            yaraStage={yaraStage}
            yaraSummary={yaraSummary}
            yaraReport={yaraReport}
            yaraError={yaraError}
            onYaraSource={(source, name) => { yaraClient.reset(); setYaraSource(source); setYaraSourceName(name); setYaraSummary(null); setYaraReport(null); setYaraStatus('idle'); setYaraError(null) }}
            onRunYara={compileAndScanYara}
            onYaraOffset={(offset) => { setHexTarget(offset); setActiveTab('hex') }}
            hexTarget={hexTarget}
          />
        )}
      </main>

      <footer className="app-footer">
        <span>Aegis 0.3</span>
        <span>Static and emulated behavior are evidence, not a verdict.</span>
      </footer>
    </div>
  )
}

function UploadPanel({ dragging, setDragging, inputRef, inspectFile, analyzeDemo, analyzeArtifactDemo }: {
  dragging: boolean
  setDragging: (value: boolean) => void
  inputRef: React.RefObject<HTMLInputElement | null>
  inspectFile: (file: File) => Promise<void>
  analyzeDemo: () => Promise<void>
  analyzeArtifactDemo: () => Promise<void>
}) {
  return (
    <div
      className={`upload-panel ${dragging ? 'dragging' : ''}`}
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
      <div className="upload-copy">
        <strong>Drop a binary here</strong>
        <span>PE, ELF, Mach-O, or WebAssembly</span>
      </div>
      <div className="button-row">
        <button className="button primary" type="button" onClick={() => inputRef.current?.click()}>Choose file</button>
        <button className="button secondary" type="button" onClick={() => void analyzeDemo()}>Use safe PE demo</button>
        <button className="button secondary" type="button" onClick={() => void analyzeArtifactDemo()}>Use runtime artifact demo</button>
      </div>
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
  )
}

function StaticProgress({ status, stage, onCancel }: { status: AppStatus; stage: ProgressStage; onCancel: () => void }) {
  return (
    <section className="center-card" role="status" aria-live="polite">
      <Spinner />
      <h2>{status === 'reading' ? 'Reading file' : progressLabels[stage]}</h2>
      <p>The analysis runs in an isolated worker.</p>
      <button className="text-button" type="button" onClick={onCancel}>Cancel</button>
    </section>
  )
}

function Workspace({ report, dynamicReport, dynamicReports, dynamicProfileId, dynamicStatus, dynamicStage, dynamicError, staticClient, dynamicClient, artifactYara, artifactYaraStatus, artifactYaraError, onScanArtifacts, activeTab, onTabChange, onClose, onExport, onRunDynamic, onRunDynamicProfiles, onSelectDynamicProfile, onCancelDynamic, yaraSource, yaraSourceName, yaraStatus, yaraStage, yaraSummary, yaraReport, yaraError, onYaraSource, onRunYara, onYaraOffset, hexTarget }: {
  report: AnalysisReport
  dynamicReport: DynamicReport | null
  dynamicReports: DynamicReport[]
  dynamicProfileId: string
  dynamicStatus: DynamicStatus
  dynamicStage: DynamicProgressStage
  dynamicError: string | null
  staticClient: AnalysisClient
  dynamicClient: DynamicAnalysisClient
  artifactYara: ArtifactYaraResult[]
  artifactYaraStatus: 'idle' | 'running' | 'done' | 'error'
  artifactYaraError: string | null
  onScanArtifacts: () => void
  activeTab: Tab
  onTabChange: (tab: Tab) => void
  onClose: () => void
  onExport: () => void
  onRunDynamic: () => void
  onRunDynamicProfiles: () => void
  onSelectDynamicProfile: (profileId: string) => void
  onCancelDynamic: () => void
  yaraSource: string
  yaraSourceName: string
  yaraStatus: YaraStatus
  yaraStage: YaraProgressStage
  yaraSummary: YaraCompileSummary | null
  yaraReport: YaraReport | null
  yaraError: string | null
  onYaraSource: (source: string, name: string) => void
  onRunYara: () => void
  onYaraOffset: (offset: number) => void
  hexTarget: number | null
}) {
  const tabs: Array<{ id: Tab; label: string; count?: number }> = [
    { id: 'summary', label: 'Summary', count: report.findings.length },
    { id: 'structure', label: 'Structure', count: report.sections.length },
    { id: 'symbols', label: 'Symbols', count: report.imports.length + report.exports.length },
    { id: 'strings', label: 'Strings', count: report.strings.length },
    { id: 'hex', label: 'Hex' },
    { id: 'dynamic', label: 'Dynamic', count: dynamicReport?.api_calls.length },
    { id: 'yara', label: 'YARA', count: yaraReport?.matches.length },
  ]
  return (
    <section className="workspace" aria-label="Analysis report">
      <header className="sample-header">
        <div className="sample-mark">{formatLabel(report.sample.detected_format).slice(0, 2)}</div>
        <div className="sample-title">
          <strong>{report.sample.name}</strong>
          <span>{formatLabel(report.sample.detected_format)} · {report.sample.architecture ?? 'Unknown architecture'} · {formatBytes(report.sample.size)}</span>
        </div>
        <div className="sample-actions">
          <button className="button secondary compact" type="button" onClick={onExport}>Export report</button>
          <button className="button secondary compact" type="button" onClick={onClose}>Close</button>
        </div>
      </header>

      <nav className="tabs" role="tablist" aria-label="Report sections">
        {tabs.map((tab) => (
          <button key={tab.id} type="button" role="tab" aria-selected={activeTab === tab.id} className={activeTab === tab.id ? 'active' : ''} onClick={() => onTabChange(tab.id)}>
            {tab.label}{tab.count != null && <span>{tab.count}</span>}
          </button>
        ))}
      </nav>

      <div className="workspace-content" role="tabpanel">
        {activeTab === 'summary' && <SummaryView report={report} />}
        {activeTab === 'structure' && <StructureView report={report} />}
        {activeTab === 'symbols' && <SymbolsView report={report} />}
        {activeTab === 'strings' && <StringsView report={report} />}
        {activeTab === 'hex' && <HexView client={staticClient} sampleSize={report.sample.size} target={hexTarget} />}
        {activeTab === 'dynamic' && (
          <DynamicView
            staticReport={report}
            report={dynamicReport}
            reports={dynamicReports}
            profileId={dynamicProfileId}
            status={dynamicStatus}
            stage={dynamicStage}
            error={dynamicError}
            onRun={onRunDynamic}
            onRunProfiles={onRunDynamicProfiles}
            onSelectProfile={onSelectDynamicProfile}
            onCancel={onCancelDynamic}
            client={dynamicClient}
            artifactYara={artifactYara}
            artifactYaraStatus={artifactYaraStatus}
            artifactYaraError={artifactYaraError}
            onScanArtifacts={onScanArtifacts}
          />
        )}
        {activeTab === 'yara' && <YaraView source={yaraSource} sourceName={yaraSourceName} status={yaraStatus} stage={yaraStage} summary={yaraSummary} report={yaraReport} error={yaraError} onSource={onYaraSource} onRun={onRunYara} onOffset={onYaraOffset} />}
      </div>
    </section>
  )
}

function SummaryView({ report }: { report: AnalysisReport }) {
  const counts = severityCounts(report)
  const metadata = formatMetadata(report)
  return (
    <div className="two-column">
      <div className="main-column">
        <div className="stats-grid">
          <Stat label="Format" value={formatLabel(report.sample.detected_format)} detail={`Schema v${report.schema_version}`} />
          <Stat label="Signals" value={String(report.findings.length - counts.info)} detail={`${counts.high} high, ${counts.medium} medium`} />
          <Stat label="Analysis" value={`${report.stats.elapsed_ms.toFixed(report.stats.elapsed_ms < 10 ? 2 : 1)} ms`} detail={`${formatBytes(report.stats.bytes_scanned)} scanned`} />
        </div>
        {report.warnings.length > 0 && <div className="notice warning-notice">{report.warnings.map((warning, index) => <span key={`${warning.code}-${index}`}>{warning.message}</span>)}</div>}
        <Section title="Findings" description="Explainable static signals ordered by severity.">
          <div className="finding-list">
            {report.findings.map((finding, index) => (
              <article className="finding" key={`${finding.id}-${index}`}>
                <Severity value={finding.severity} />
                <div><h3>{finding.title}</h3><p>{finding.rationale}</p>{finding.evidence.length > 0 && <div className="evidence">{finding.evidence.map((item, itemIndex) => <code key={itemIndex}>{item.offset != null && `${formatOffset(item.offset)} · `}{item.value}</code>)}</div>}</div>
              </article>
            ))}
          </div>
        </Section>
      </div>
      <aside className="side-column">
        <Section title="Hashes" description="SHA-1 and MD5 are identifiers only.">
          <Hash label="SHA-256" value={report.sample.sha256} />
          <Hash label="SHA-1" value={report.sample.sha1} />
          <Hash label="MD5" value={report.sample.md5} />
        </Section>
        <Section title="Metadata">
          <dl className="metadata-list">{metadata.map(([label, value]) => <div key={label}><dt>{label}</dt><dd title={value}>{value}</dd></div>)}</dl>
        </Section>
      </aside>
    </div>
  )
}

function DynamicView({ staticReport, report, reports, profileId, status, stage, error, onRun, onRunProfiles, onSelectProfile, onCancel, client, artifactYara, artifactYaraStatus, artifactYaraError, onScanArtifacts }: {
  staticReport: AnalysisReport
  report: DynamicReport | null
  reports: DynamicReport[]
  profileId: string
  status: DynamicStatus
  stage: DynamicProgressStage
  error: string | null
  onRun: () => void
  onRunProfiles: () => void
  onSelectProfile: (profileId: string) => void
  onCancel: () => void
  client: DynamicAnalysisClient
  artifactYara: ArtifactYaraResult[]
  artifactYaraStatus: 'idle' | 'running' | 'done' | 'error'
  artifactYaraError: string | null
  onScanArtifacts: () => void
}) {
  const format = staticReport.format as Record<string, unknown>
  const eligible = format.kind === 'pe' && format.bitness === 32
  const [view, setView] = useState<'timeline' | 'behavior' | 'api' | 'instructions' | 'coverage' | 'artifacts' | 'profiles'>('timeline')
  const [timelineTarget, setTimelineTarget] = useState<number | null>(null)

  if (!eligible) {
    return <EmptyState title="Dynamic analysis is not available for this file" text="The current emulator supports PE32/x86 executables. Static analysis remains available for every supported format." />
  }
  if (status === 'running') {
    return <div className="dynamic-start"><Spinner /><h2>{dynamicProgressLabels[stage]}</h2><p>Execution is isolated inside a dedicated worker with a 10-second watchdog.</p><button className="button secondary" type="button" onClick={onCancel}>Stop analysis</button></div>
  }
  if (status === 'error' && error) {
    return <div className="dynamic-start"><h2>Dynamic analysis stopped</h2><p>{error}</p><button className="button primary" type="button" onClick={onRun}>Try again</button></div>
  }
  if (!report) {
    return (
      <div className="dynamic-intro">
        <div>
          <p className="kicker">PE32 / x86 interpreter</p>
          <h2>Observe modeled behavior</h2>
          <p>Instructions run in a deterministic Rust interpreter. Windows APIs, files, registry keys, memory, and network operations are synthetic and never map to browser resources.</p>
          <ProfilePicker value={profileId} onChange={onSelectProfile} />
          <div className="button-row"><button className="button primary" type="button" onClick={onRun}>Run selected profile</button><button className="button secondary" type="button" onClick={onRunProfiles}>Compare all profiles</button></div>
        </div>
        <dl className="limits-list">
          <div><dt>Instruction limit</dt><dd>1,000,000</dd></div>
          <div><dt>Wall-time limit</dt><dd>10 seconds</dd></div>
          <div><dt>Guest memory</dt><dd>256 MiB maximum</dd></div>
          <div><dt>Network</dt><dd>Synthetic sink</dd></div>
        </dl>
      </div>
    )
  }

  const behaviorCount = report.processes.length + report.filesystem.length + report.registry.length + report.network.length + report.memory.length + report.injection.length + report.persistence.length
  return (
    <div className="dynamic-report">
      <div className="profile-toolbar"><ProfilePicker value={profileId} onChange={onSelectProfile} /><button className="button secondary compact" type="button" onClick={onRunProfiles}>Run profile matrix</button><span>{report.profile.environment.windows_version} · {report.profile.environment.network_mode}</span></div>
      <div className="stats-grid four">
        <Stat label="Termination" value={terminationLabel(report.termination)} detail="Bounded execution" />
        <Stat label="Instructions" value={report.instruction_count.toLocaleString()} detail={`${report.coverage.unique_instruction_addresses.toLocaleString()} unique addresses`} />
        <Stat label="API calls" value={report.api_calls.length.toLocaleString()} detail={`${report.coverage.modeled_api_calls} modeled · ${report.coverage.unmodeled_api_calls} fallback`} />
        <Stat label="Elapsed" value={`${report.elapsed_ms.toFixed(2)} ms`} detail="Dedicated worker" />
      </div>
      <div className="notice safe-notice"><strong>No guest operation left the browser.</strong><span>Network, filesystem, registry, time, process, and memory APIs were modeled locally.</span></div>
      <Section title="Dynamic findings" description="Signals derived from observed execution.">
        <div className="finding-list">
          {report.findings.map((finding) => <article className="finding" key={finding.id}><Severity value={finding.severity} /><div><h3>{finding.title}</h3><p>{finding.rationale}</p>{finding.evidence.length > 0 && <div className="evidence">{finding.evidence.map((value) => <code key={value}>{value}</code>)}</div>}</div></article>)}
        </div>
      </Section>
      {report.injection.length > 0 && <InjectionChain events={report.injection} />}
      {report.warnings.length > 0 && <div className="notice warning-notice">{report.warnings.map((warning) => <span key={warning}>{warning}</span>)}</div>}
      <div className="subtabs">
        <button className={view === 'timeline' ? 'active' : ''} type="button" onClick={() => setView('timeline')}>Timeline ({report.timeline.length})</button>
        <button className={view === 'behavior' ? 'active' : ''} type="button" onClick={() => setView('behavior')}>Behavior ({behaviorCount})</button>
        <button className={view === 'api' ? 'active' : ''} type="button" onClick={() => setView('api')}>API calls ({report.api_calls.length})</button>
        <button className={view === 'instructions' ? 'active' : ''} type="button" onClick={() => setView('instructions')}>Instructions ({report.instructions.length})</button>
        <button className={view === 'coverage' ? 'active' : ''} type="button" onClick={() => setView('coverage')}>Coverage</button>
        <button className={view === 'artifacts' ? 'active' : ''} type="button" onClick={() => setView('artifacts')}>Artifacts ({report.artifacts.length})</button>
        {reports.length > 1 && <button className={view === 'profiles' ? 'active' : ''} type="button" onClick={() => setView('profiles')}>Profile comparison ({reports.length})</button>}
      </div>
      {view === 'timeline' && <TimelineView report={report} target={timelineTarget} />}
      {view === 'behavior' && <BehaviorView report={report} />}
      {view === 'api' && <ApiView report={report} />}
      {view === 'instructions' && <InstructionView report={report} />}
      {view === 'coverage' && <CoverageView report={report} />}
      {view === 'artifacts' && <ArtifactsView report={report} client={client} yara={artifactYara} status={artifactYaraStatus} error={artifactYaraError} onScan={onScanArtifacts} onTimeline={(sequence) => { setTimelineTarget(sequence); setView('timeline') }} />}
      {view === 'profiles' && <ProfileComparison reports={reports} onSelect={(id) => { onSelectProfile(id); setView('timeline') }} />}
    </div>
  )
}

function ProfilePicker({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  return <label className="profile-picker"><span>Environment profile</span><select aria-label="Environment profile" value={value} onChange={(event) => onChange(event.target.value)}>{ENVIRONMENT_PROFILES.map((profile) => <option key={profile.id} value={profile.id}>{profile.label}</option>)}</select></label>
}

function ProfileComparison({ reports, onSelect }: { reports: DynamicReport[]; onSelect: (profileId: string) => void }) {
  const baseline = reports[0]
  return <Section title="Environment profile comparison" description="The same sample was executed independently under deterministic synthetic environments."><Table><thead><tr><th>Profile</th><th>Environment</th><th>Termination</th><th>Instructions</th><th>Behavior</th><th>Artifacts</th><th>Delta from baseline</th></tr></thead><tbody>{reports.map((report) => { const behavior = report.processes.length + report.filesystem.length + report.registry.length + report.network.length + report.persistence.length + report.injection.length; const baselineBehavior = baseline.processes.length + baseline.filesystem.length + baseline.registry.length + baseline.network.length + baseline.persistence.length + baseline.injection.length; const apiResultChanged = report.api_calls.some((event, index) => event.result !== baseline.api_calls[index]?.result); const delta = report.api_calls.length !== baseline.api_calls.length || apiResultChanged || behavior !== baselineBehavior || report.artifacts.length !== baseline.artifacts.length || JSON.stringify(report.termination) !== JSON.stringify(baseline.termination); return <tr key={report.profile.environment.id}><td><button className="offset-link" type="button" onClick={() => onSelect(report.profile.environment.id)}>{report.profile.environment.label}</button></td><td><small>{report.profile.environment.windows_version}<br />{report.profile.environment.cpu_count} CPU · {formatBytes(report.profile.environment.memory_mb * 1024 * 1024)} · {report.profile.environment.network_mode}{report.profile.environment.debugger_present ? ' · debugger' : ''}</small></td><td>{terminationLabel(report.termination)}</td><td>{report.instruction_count.toLocaleString()}</td><td>{behavior}</td><td>{report.artifacts.length}</td><td><span className={`tag ${delta ? 'danger' : ''}`}>{report === baseline ? 'Baseline' : delta ? 'Behavior changed' : 'Same path'}</span></td></tr> })}</tbody></Table></Section>
}

function InjectionChain({ events }: { events: DynamicReport['injection'] }) {
  return <Section title="Process injection chain" description="Correlated remote operations against synthetic process address spaces."><div className="injection-chain">{events.map((event, index) => <article key={`${event.operation}-${index}`}><span>{index + 1}</span><div><strong>{event.operation.replaceAll('_', ' ')}</strong><code>process {formatOffset(event.process_handle)} · address {formatOffset(event.address)}</code><small>{formatBytes(event.size)}{event.preview ? ` · ${event.preview}` : ''}</small></div></article>)}</div></Section>
}

function ArtifactsView({ report, client, yara, status, error, onScan, onTimeline }: { report: DynamicReport; client: DynamicAnalysisClient; yara: ArtifactYaraResult[]; status: 'idle' | 'running' | 'done' | 'error'; error: string | null; onScan: () => void; onTimeline: (sequence: number) => void }) {
  const [kind, setKind] = useState('all')
  const [selectedId, setSelectedId] = useState(report.artifacts[0]?.id ?? '')
  const [offset, setOffset] = useState(0)
  const [bytes, setBytes] = useState<Uint8Array<ArrayBuffer>>(new Uint8Array(new ArrayBuffer(0)))
  const [readError, setReadError] = useState<string | null>(null)
  const [exportTarget, setExportTarget] = useState<string | null>(null)
  const artifacts = kind === 'all' ? report.artifacts : report.artifacts.filter((artifact) => artifact.kind === kind)
  const selected = report.artifacts.find((artifact) => artifact.id === selectedId) ?? artifacts[0]
  useEffect(() => {
    if (!selected) return
    let alive = true; setReadError(null)
    client.readArtifactSlice(report.profile.environment.id, selected.id, offset, 512).then((result) => { if (alive) setBytes(result.bytes) }).catch((cause) => { if (alive) setReadError(cause instanceof Error ? cause.message : 'Artifact read failed') })
    return () => { alive = false }
  }, [client, offset, selected])
  const exportBytes = async () => {
    if (!selected) return
    const result = await client.readArtifact(report.profile.environment.id, selected.id)
    const url = URL.createObjectURL(new Blob([result.bytes.buffer], { type: 'application/octet-stream' }))
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = `${selected.name.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 120) || 'artifact'}.bin`; anchor.click()
    window.setTimeout(() => URL.revokeObjectURL(url), 0); setExportTarget(null)
  }
  if (!report.artifacts.length) return <EmptyState title="No runtime artifacts captured" text="No written memory or virtual files met the bounded capture policy." />
  const yaraFor = (id: string) => yara.find((result) => result.artifact_id === id)
  return <div className="artifact-layout">
    <div className="artifact-actions"><div className="timeline-filters">{['all', 'memory', 'virtual_file', 'remote_memory', 'configuration'].map((value) => <button type="button" className={kind === value ? 'active' : ''} key={value} onClick={() => setKind(value)}>{value.replaceAll('_', ' ')}</button>)}</div><button className="button primary compact" type="button" disabled={status === 'running'} onClick={onScan}>{status === 'running' ? 'Scanning artifacts…' : 'Scan artifacts with YARA'}</button></div>
    {error && <div className="notice error-notice yara-error" role="alert"><div><strong>Artifact YARA stopped</strong><span>{error}</span></div></div>}
    <div className="artifact-grid"><Section title="Captured artifacts" description={`${report.artifact_stats.count} unique artifacts · ${formatBytes(report.artifact_stats.retained_bytes)} retained in the worker.`}><Table><thead><tr><th>Name</th><th>Kind</th><th>Format</th><th>Size</th><th>Entropy</th><th>YARA</th></tr></thead><tbody>{artifacts.map((artifact) => { const result = yaraFor(artifact.id); return <tr className={selected?.id === artifact.id ? 'selected-row' : ''} key={artifact.id} onClick={() => { setSelectedId(artifact.id); setOffset(0) }}><td><code className="strong-code">{artifact.name}</code></td><td><span className="tag">{artifact.kind}</span></td><td>{artifact.detected_format}</td><td>{formatBytes(artifact.captured_size)}</td><td>{artifact.entropy.toFixed(2)}</td><td>{result?.error ? 'Error' : result ? `${result.report?.matches.length ?? 0} matches` : 'Not scanned'}</td></tr> })}</tbody></Table></Section>
      {selected && <Section title={selected.name} description={`${selected.sha256.slice(0, 20)}… · ${selected.trigger}`}><div className="artifact-detail"><dl className="limits-list"><div><dt>Kind</dt><dd>{selected.kind}</dd></div><div><dt>Format</dt><dd>{selected.detected_format}</dd></div><div><dt>Permissions</dt><dd>{selected.permissions ?? '—'}</dd></div><div><dt>Captured</dt><dd>{formatBytes(selected.captured_size)}</dd></div></dl><div className="button-row"><button className="button secondary compact" type="button" onClick={() => setExportTarget(selected.id)}>Export raw bytes</button>{selected.origins[0]?.timeline_sequence != null && <button className="button secondary compact" type="button" onClick={() => onTimeline(selected.origins[0].timeline_sequence!)}>View timeline origin</button>}</div>{readError ? <div className="notice warning-notice">{readError}</div> : <ArtifactHex bytes={bytes} offset={offset} total={selected.captured_size} onOffset={setOffset} />}<h3>Strings and indicators</h3><div className="artifact-strings">{selected.indicators.map((indicator) => <code key={`${indicator.offset}-${indicator.value}`}>{indicator.kind}: {indicator.value}</code>)}{selected.strings.slice(0, 24).map((item) => <code key={`${item.offset}-${item.value}`}>{formatOffset(item.offset)} {item.value}</code>)}</div>{yaraFor(selected.id)?.report && <div className="notice safe-notice"><strong>{yaraFor(selected.id)!.report!.matches.length} YARA rule matches.</strong><span>{yaraFor(selected.id)!.report!.matches.map((match) => match.identifier).join(', ') || 'No rules matched.'}</span></div>}</div></Section>}
    </div>
    {exportTarget && selected && <div className="modal-backdrop" role="presentation"><div className="confirm-dialog" role="dialog" aria-modal="true" aria-labelledby="artifact-export-title"><h2 id="artifact-export-title">Export potentially malicious bytes?</h2><p><strong>{selected.name}</strong> may contain executable or harmful content. Aegis will download {formatBytes(selected.captured_size)} with SHA-256 <code>{selected.sha256}</code>.</p><div className="button-row"><button className="button secondary" type="button" onClick={() => setExportTarget(null)}>Cancel</button><button className="button primary" type="button" onClick={() => void exportBytes()}>Export raw bytes</button></div></div></div>}
  </div>
}

function ArtifactHex({ bytes, offset, total, onOffset }: { bytes: Uint8Array<ArrayBuffer>; offset: number; total: number; onOffset: (offset: number) => void }) {
  const rows = []
  for (let index = 0; index < bytes.length; index += 16) rows.push(bytes.slice(index, index + 16))
  return <div><div className="hex-toolbar"><button className="button secondary compact" type="button" disabled={offset === 0} onClick={() => onOffset(Math.max(0, offset - 512))}>Previous</button><code>{formatOffset(offset)} – {formatOffset(Math.min(total, offset + bytes.length))}</code><button className="button secondary compact" type="button" disabled={offset + 512 >= total} onClick={() => onOffset(offset + 512)}>Next</button></div><div className="hex-view artifact-hex">{rows.map((row, rowIndex) => <div className="hex-row" key={rowIndex}><span>{formatOffset(offset + rowIndex * 16)}</span><code>{Array.from(row).map((byte) => byte.toString(16).padStart(2, '0')).join(' ').padEnd(47, ' ')}</code><code>{Array.from(row).map((byte) => byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.').join('')}</code></div>)}</div></div>
}

function TimelineView({ report, target }: { report: DynamicReport; target: number | null }) {
  const [category, setCategory] = useState('all')
  const categories = ['all', ...Array.from(new Set(report.timeline.map((event) => event.category)))]
  const events = category === 'all' ? report.timeline : report.timeline.filter((event) => event.category === category)
  if (report.timeline.length === 0) return <EmptyState title="No timeline events" text="Execution ended before reaching a modeled or fallback API." />
  return <Section title="Execution timeline" description="Ordered synthetic activity; virtual timestamps never use the host clock."><div className="timeline-filters">{categories.map((value) => <button type="button" className={category === value ? 'active' : ''} key={value} onClick={() => setCategory(value)}>{value.charAt(0).toUpperCase() + value.slice(1)}</button>)}</div><Table><thead><tr><th>#</th><th>Virtual time</th><th>Category</th><th>Operation</th><th>Subject</th><th>Source API</th><th>Instruction</th></tr></thead><tbody>{events.map((event) => <tr className={target === event.sequence ? 'highlight-row' : ''} key={event.sequence}><td>{event.sequence + 1}</td><td>{event.virtual_time_ms.toLocaleString()} ms</td><td><span className="tag">{event.category}</span></td><td>{event.operation}</td><td><code>{event.subject}</code></td><td><code className="strong-code">{event.source_api}</code></td><td>{event.instruction.toLocaleString()}</td></tr>)}</tbody></Table></Section>
}

function CoverageView({ report }: { report: DynamicReport }) {
  const coverage = report.coverage
  const total = coverage.modeled_api_calls + coverage.unmodeled_api_calls
  const modeledPercent = total === 0 ? 100 : coverage.modeled_api_calls / total * 100
  return <div className="coverage-layout"><div className="stats-grid"><Stat label="Unique code addresses" value={coverage.unique_instruction_addresses.toLocaleString()} detail={`${report.instruction_count.toLocaleString()} instructions executed`} /><Stat label="Unique APIs" value={coverage.unique_api_names.toLocaleString()} detail={`${coverage.dynamic_api_resolutions} dynamically resolved`} /><Stat label="Modeled API coverage" value={`${modeledPercent.toFixed(1)}%`} detail={`${coverage.unmodeled_api_calls} conservative fallbacks`} /></div><Section title="Interpretation limits" description="Coverage describes this emulation path, not every path in the binary."><dl className="limits-list"><div><dt>Trace records</dt><dd>{report.instructions.length.toLocaleString()}</dd></div><div><dt>Report truncated</dt><dd>{report.truncated ? 'Yes' : 'No'}</dd></div><div><dt>Termination</dt><dd>{terminationLabel(report.termination)}</dd></div><div><dt>Schema</dt><dd>Dynamic v{report.schema_version}</dd></div></dl></Section></div>
}

function BehaviorView({ report }: { report: DynamicReport }) {
  const rows = [
    ...report.processes.map((event) => ({ type: 'Process', operation: event.operation, target: event.command, detail: event.synthetic_result })),
    ...report.network.map((event) => ({ type: 'Network', operation: event.operation, target: event.destination, detail: event.synthetic_result })),
    ...report.filesystem.map((event) => ({ type: 'File', operation: event.operation, target: event.path, detail: event.preview ?? 'Virtual filesystem' })),
    ...report.registry.map((event) => ({ type: 'Registry', operation: event.operation, target: event.key, detail: event.value ?? 'Synthetic registry' })),
    ...report.memory.map((event) => ({ type: 'Memory', operation: event.operation, target: formatOffset(event.address), detail: `${formatBytes(event.size)} · ${event.permissions}` })),
    ...report.injection.map((event) => ({ type: 'Injection', operation: event.operation, target: `process ${formatOffset(event.process_handle)} · ${formatOffset(event.address)}`, detail: `${formatBytes(event.size)}${event.preview ? ` · ${event.preview}` : ''}` })),
    ...report.persistence.map((event) => ({ type: 'Persistence', operation: event.operation, target: event.target, detail: `${event.mechanism}${event.value ? ` · ${event.value}` : ''}` })),
  ]
  if (rows.length === 0) return <EmptyState title="No high-level behavior events" text="The sample did not reach the currently modeled APIs." />
  return <Table><thead><tr><th>Type</th><th>Operation</th><th>Target</th><th>Result</th></tr></thead><tbody>{rows.map((row, index) => <tr key={`${row.type}-${index}`}><td><span className="tag">{row.type}</span></td><td>{row.operation}</td><td><code>{row.target}</code></td><td>{row.detail}</td></tr>)}</tbody></Table>
}

function ApiView({ report }: { report: DynamicReport }) {
  if (report.api_calls.length === 0) return <EmptyState title="No API calls recorded" text="Execution ended before reaching a modeled import." />
  return <Table><thead><tr><th>#</th><th>API</th><th>Instruction</th><th>Summary</th><th>Result</th></tr></thead><tbody>{report.api_calls.map((event) => <tr key={event.index}><td>{event.index + 1}</td><td><code className="strong-code">{event.module}!{event.name}</code></td><td>{event.instruction.toLocaleString()}</td><td>{event.summary}</td><td><code>{formatOffset(event.result)}</code></td></tr>)}</tbody></Table>
}

function InstructionView({ report }: { report: DynamicReport }) {
  return <Table><thead><tr><th>#</th><th>Address</th><th>Bytes</th><th>Instruction</th></tr></thead><tbody>{report.instructions.map((event) => <tr key={event.index}><td>{event.index}</td><td><code>{formatOffset(event.address)}</code></td><td><code>{event.bytes}</code></td><td><code className="strong-code">{event.text}</code></td></tr>)}</tbody></Table>
}

function StructureView({ report }: { report: AnalysisReport }) {
  if (report.sections.length === 0) return <EmptyState title="No sections available" text="This format did not expose section records." />
  return <Section title="Sections" description={`${report.sections.length.toLocaleString()} bounded records. Entropy is measured in bits per byte.`}><Table><thead><tr><th>Name</th><th>File offset</th><th>Virtual address</th><th>Size</th><th>Permissions</th><th>Entropy</th></tr></thead><tbody>{report.sections.map((section, index) => <tr key={`${section.name}-${index}`}><td><code className="strong-code">{section.name}</code></td><td><code>{formatOffset(section.offset)}</code></td><td><code>{formatOffset(section.virtual_address)}</code></td><td>{formatBytes(section.size)}</td><td><span className={`permission ${section.permissions.includes('w') && section.permissions.includes('x') ? 'danger' : ''}`}>{section.permissions}</span></td><td><div className="entropy"><span><i style={{ width: `${section.entropy / 8 * 100}%` }} /></span><code>{section.entropy.toFixed(2)}</code></div></td></tr>)}</tbody></Table></Section>
}

function SymbolsView({ report }: { report: AnalysisReport }) {
  const [mode, setMode] = useState<'imports' | 'exports'>('imports')
  return <Section title="Symbols" description="Parsed without loading any dependency."><div className="subtabs"><button type="button" className={mode === 'imports' ? 'active' : ''} onClick={() => setMode('imports')}>Imports ({report.imports.length})</button><button type="button" className={mode === 'exports' ? 'active' : ''} onClick={() => setMode('exports')}>Exports ({report.exports.length})</button></div><SymbolTable records={mode === 'imports' ? report.imports : report.exports} /></Section>
}

function SymbolTable({ records }: { records: SymbolRecord[] }) {
  const [page, setPage] = useState(0)
  useEffect(() => setPage(0), [records])
  const pages = Math.max(1, Math.ceil(records.length / PAGE_SIZE))
  if (records.length === 0) return <EmptyState title="No symbols found" text="The binary does not expose symbols of this kind." />
  return <><Table><thead><tr><th>Symbol</th><th>Module</th><th>Kind</th><th>Address / index</th></tr></thead><tbody>{records.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE).map((record, index) => <tr key={`${record.name}-${index}`}><td><code className="strong-code">{record.name}</code></td><td>{record.module ?? '—'}</td><td><span className="tag">{record.kind}</span></td><td><code>{formatOffset(record.address)}</code></td></tr>)}</tbody></Table><Pagination page={page} pages={pages} count={records.length} onPage={setPage} /></>
}

function StringsView({ report }: { report: AnalysisReport }) {
  const [query, setQuery] = useState('')
  const [mode, setMode] = useState<'strings' | 'indicators'>('strings')
  const [page, setPage] = useState(0)
  const strings = useMemo(() => report.strings.filter((item) => item.value.toLowerCase().includes(query.toLowerCase())), [query, report.strings])
  const indicators = useMemo(() => report.indicators.filter((item) => `${item.kind} ${item.value}`.toLowerCase().includes(query.toLowerCase())), [query, report.indicators])
  const records = mode === 'strings' ? strings : indicators
  const pages = Math.max(1, Math.ceil(records.length / PAGE_SIZE))
  useEffect(() => setPage(0), [mode, query])
  return <Section title="Strings and indicators" description="Values are bounded and deliberately non-clickable."><div className="table-tools"><div className="subtabs"><button type="button" className={mode === 'strings' ? 'active' : ''} onClick={() => setMode('strings')}>Strings ({report.strings.length})</button><button type="button" className={mode === 'indicators' ? 'active' : ''} onClick={() => setMode('indicators')}>Indicators ({report.indicators.length})</button></div><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Filter values" aria-label="Filter extracted values" /></div>{records.length === 0 ? <EmptyState title="No matching values" text={query ? 'Try a broader filter.' : 'No values of this type were extracted.'} /> : <><Table><thead><tr><th>Offset</th><th>{mode === 'strings' ? 'Encoding' : 'Type'}</th><th>Value</th></tr></thead><tbody>{records.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE).map((record, index) => <StringRow key={`${record.offset}-${index}`} record={record as ExtractedString & { kind?: string }} />)}</tbody></Table><Pagination page={page} pages={pages} count={records.length} onPage={setPage} /></>}</Section>
}

function StringRow({ record }: { record: ExtractedString & { kind?: string } }) {
  return <tr><td><code>{formatOffset(record.offset)}</code></td><td><span className="tag">{record.kind ?? record.encoding}</span></td><td><code className="string-value">{record.value}</code></td></tr>
}

function YaraView({ source, sourceName, status, stage, summary, report, error, onSource, onRun, onOffset }: {
  source: string; sourceName: string; status: YaraStatus; stage: YaraProgressStage; summary: YaraCompileSummary | null; report: YaraReport | null; error: string | null; onSource: (source: string, name: string) => void; onRun: () => void; onOffset: (offset: number) => void
}) {
  const importRef = useRef<HTMLInputElement>(null)
  const [importError, setImportError] = useState<string | null>(null)
  const busy = status === 'running'
  const exportRules = () => {
    const url = URL.createObjectURL(new Blob([source], { type: 'text/plain' }))
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = sourceName; anchor.click()
    window.setTimeout(() => URL.revokeObjectURL(url), 0)
  }
  const importRules = async (file: File) => {
    if (!/\.yar(a)?$/i.test(file.name)) throw new Error('Choose a .yar or .yara rule file.')
    if (file.size > 1024 * 1024) throw new Error('Rule source exceeds the 1 MiB safety limit.')
    const text = new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer())
    setImportError(null); onSource(text, file.name)
  }
  return <div className="yara-layout">
    <Section title="Rule editor" description="Rules remain in memory and are never uploaded or saved automatically.">
      <div className="yara-toolbar"><strong>{sourceName}</strong><span>{formatBytes(new Blob([source]).size)} / 1 MiB</span><div><button className="button secondary compact" type="button" onClick={() => importRef.current?.click()}>Import</button><button className="button secondary compact" type="button" onClick={exportRules}>Export rules</button><button className="button secondary compact" type="button" onClick={() => onSource(starterRules, 'aegis-starter.yar')}>Reset starter pack</button></div></div>
      <textarea className="yara-editor" spellCheck={false} aria-label="YARA rule source" value={source} disabled={busy} onChange={(event) => onSource(event.target.value, sourceName)} />
      <div className="yara-run"><span>Includes disabled · slow patterns rejected · 10,000 rule maximum</span><button className="button primary" type="button" disabled={busy || !source.trim()} onClick={onRun}>{busy ? stage === 'scanning' ? 'Scanning…' : 'Compiling…' : 'Compile & scan'}</button></div>
      <input ref={importRef} hidden type="file" accept=".yar,.yara" onChange={(event) => { const file = event.target.files?.[0]; if (file) void importRules(file).catch((cause) => setImportError(cause instanceof Error ? cause.message : 'Rule import failed')); event.currentTarget.value = '' }} />
    </Section>
    {importError && <div className="notice warning-notice">{importError}</div>}
    {error && <div className="notice error-notice yara-error" role="alert"><div><strong>YARA operation stopped</strong><span>{error}</span></div></div>}
    {summary && <div className="stats-grid"><Stat label="Compiled rules" value={summary.rule_count.toLocaleString()} detail={summary.pack_name} /><Stat label="Rule warnings" value={summary.warnings.length.toLocaleString()} detail="Maximum 100 diagnostics" /><Stat label="Matches" value={(report?.matches.length ?? 0).toLocaleString()} detail={report ? `${report.stats.reported_occurrences} occurrences` : 'Ready to scan'} /></div>}
    {report && <Section title="Rule matches" description={`${report.stats.matching_rules} matching rules across ${report.stats.rules_scanned} compiled rules.`}>{report.matches.length === 0 ? <EmptyState title="No YARA rules matched" text="This is evidence only, not proof that the sample is safe." /> : <div className="finding-list">{report.matches.map((match) => {
      const description = match.metadata.find((item) => item.identifier === 'description')?.value
      const occurrences = match.patterns.flatMap((pattern) => pattern.occurrences.map((occurrence) => ({ ...occurrence, pattern: pattern.identifier })))
      return <article className="finding" key={`${match.namespace}-${match.identifier}`}><Severity value={match.severity} /><div><h3>{match.identifier}</h3><p>{typeof description === 'string' ? description : `${match.namespace} namespace`}</p><div className="evidence">{match.tags.map((tag) => <code key={tag}>{tag}</code>)}{occurrences.slice(0, 20).map((occurrence, index) => <button className="offset-link" type="button" key={`${occurrence.offset}-${index}`} onClick={() => onOffset(occurrence.offset)}>{occurrence.pattern} at {formatOffset(occurrence.offset)}</button>)}</div></div></article>
    })}</div>}</Section>}
  </div>
}

function HexView({ client, sampleSize, target }: { client: AnalysisClient; sampleSize: number; target: number | null }) {
  const pageSize = 512
  const [offset, setOffset] = useState(0)
  const [bytes, setBytes] = useState<Uint8Array>(new Uint8Array())
  const [error, setError] = useState<string | null>(null)
  useEffect(() => { if (target != null) setOffset(Math.floor(target / pageSize) * pageSize) }, [target])
  useEffect(() => {
    let alive = true
    setError(null)
    client.readHex(offset, pageSize).then((result) => { if (alive) setBytes(result.bytes) }).catch((cause) => { if (alive) setError(cause instanceof Error ? cause.message : 'Hex read failed') })
    return () => { alive = false }
  }, [client, offset])
  const rows = []
  for (let index = 0; index < bytes.length; index += 16) rows.push(bytes.slice(index, index + 16))
  if (error) return <EmptyState title="Hex view unavailable" text={error} />
  return <Section title="Hex view" description="Only 512 bytes are copied from the static worker at a time."><div className="hex-toolbar"><button className="button secondary compact" type="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - pageSize))}>Previous</button><code>{formatOffset(offset)} – {formatOffset(Math.min(offset + bytes.length, sampleSize))}</code><button className="button secondary compact" type="button" disabled={offset + pageSize >= sampleSize} onClick={() => setOffset(offset + pageSize)}>Next</button></div><div className="hex-view">{rows.map((row, rowIndex) => <div className="hex-row" key={rowIndex}><span>{formatOffset(offset + rowIndex * 16)}</span><code>{Array.from(row).map((byte) => byte.toString(16).padStart(2, '0')).join(' ').padEnd(47, ' ')}</code><code>{Array.from(row).map((byte) => byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.').join('')}</code></div>)}</div></Section>
}

function Section({ title, description, children }: { title: string; description?: string; children: React.ReactNode }) {
  return <section className="section-card"><header><h2>{title}</h2>{description && <p>{description}</p>}</header><div>{children}</div></section>
}

function Table({ children }: { children: React.ReactNode }) {
  return <div className="table-scroll"><table>{children}</table></div>
}

function Stat({ label, value, detail }: { label: string; value: string; detail: string }) {
  return <div className="stat"><span>{label}</span><strong>{value}</strong><small>{detail}</small></div>
}

function Severity({ value }: { value: string }) {
  return <span className={`severity severity-${value}`}>{value}</span>
}

function Hash({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false)
  return <div className="hash-row"><span>{label}</span><code title={value}>{value}</code><button type="button" onClick={() => { void navigator.clipboard.writeText(value); setCopied(true); window.setTimeout(() => setCopied(false), 1200) }}>{copied ? 'Copied' : 'Copy'}</button></div>
}

function Pagination({ page, pages, count, onPage }: { page: number; pages: number; count: number; onPage: (page: number) => void }) {
  if (pages <= 1) return null
  return <div className="pagination"><span>{count.toLocaleString()} records · page {page + 1} of {pages}</span><div><button type="button" disabled={page === 0} onClick={() => onPage(page - 1)}>Previous</button><button type="button" disabled={page + 1 >= pages} onClick={() => onPage(page + 1)}>Next</button></div></div>
}

function EmptyState({ title, text }: { title: string; text: string }) {
  return <div className="empty-state"><strong>{title}</strong><span>{text}</span></div>
}

function Spinner() {
  return <span className="spinner" aria-hidden="true" />
}

function terminationLabel(termination: DynamicTermination): string {
  switch (termination.reason) {
    case 'exit_process': return `Exit ${termination.code}`
    case 'returned_from_entry_point': return 'Returned'
    case 'instruction_limit': return 'Limit reached'
    case 'halted': return 'Halted'
    case 'unsupported_instruction': return 'Unsupported instruction'
    case 'invalid_instruction': return 'Invalid instruction'
    case 'memory_fault': return 'Memory fault'
  }
}

function parseYaraError(cause: unknown): string {
  const message = cause instanceof Error ? cause.message : String(cause)
  try {
    const diagnostic = JSON.parse(message) as { message?: string; errors?: Array<{ message?: string }> }
    return diagnostic.errors?.map((item) => item.message).filter(Boolean).join('\n') || diagnostic.message || message
  } catch {
    return message
  }
}
