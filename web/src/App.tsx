import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { AnalysisClient } from './analysisClient'
import { DynamicAnalysisClient } from './dynamicClient'
import { YaraClient } from './yaraClient'
import starterRules from './rules/nope-starter.yar?raw'
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
  StaticBasicBlock,
  StaticFunction,
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
const LINUX_ENVIRONMENT_PROFILES: DynamicEnvironmentProfile[] = [
  { id: 'balanced', label: 'Linux workstation', windows_version: 'Linux 6.8', computer_name: 'nope-workstation', user_name: 'analyst', locale: 'en-US', timezone_offset_minutes: -360, memory_mb: 8192, cpu_count: 4, debugger_present: false, network_mode: 'online', initial_virtual_time_ms: 1_000_000 },
  { id: 'legacy', label: 'Legacy Linux server', windows_version: 'Linux 4.19', computer_name: 'legacy-server', user_name: 'service', locale: 'en-US', timezone_offset_minutes: 0, memory_mb: 2048, cpu_count: 2, debugger_present: false, network_mode: 'online', initial_virtual_time_ms: 500_000 },
  { id: 'hardened', label: 'Hardened offline Linux', windows_version: 'Linux 6.8 hardened', computer_name: 'corp-linux-042', user_name: 'employee', locale: 'en-GB', timezone_offset_minutes: 0, memory_mb: 16384, cpu_count: 8, debugger_present: false, network_mode: 'offline', initial_virtual_time_ms: 2_000_000 },
  { id: 'analysis', label: 'Instrumented Linux sandbox', windows_version: 'Linux 6.8 analysis', computer_name: 'nope-linux-lab', user_name: 'sandbox', locale: 'en-US', timezone_offset_minutes: 0, memory_mb: 1024, cpu_count: 1, debugger_present: true, network_mode: 'sinkhole', initial_virtual_time_ms: 3_000_000 },
]
type AppStatus = 'idle' | 'reading' | 'analyzing' | 'done' | 'error'
type DynamicStatus = 'idle' | 'running' | 'done' | 'error'
type YaraStatus = 'idle' | 'running' | 'done' | 'error'
type Tab = 'summary' | 'structure' | 'symbols' | 'code' | 'strings' | 'hex' | 'dynamic' | 'yara'

const progressLabels: Record<ProgressStage, string> = {
  'loading-engine': 'Loading analysis engine',
  parsing: 'Parsing and disassembling binary',
  finalizing: 'Preparing report',
}

const dynamicProgressLabels: Record<DynamicProgressStage, string> = {
  'loading-engine': 'Loading x86/x64 interpreter',
  'loading-image': 'Mapping executable image',
  executing: 'Emulating instructions',
  finalizing: 'Preparing behavior report',
}

function LogoMark({ className = '' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 36 36" aria-hidden="true">
      <rect x="2.5" y="2.5" width="31" height="31" rx="8" />
      <path className="logo-play" d="M14 11.5 25 18l-11 6.5z" />
      <path className="logo-slash" d="m9.5 27 17-18" />
    </svg>
  )
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
  const [yaraSourceName, setYaraSourceName] = useState('nope-starter.yar')
  const [yaraStatus, setYaraStatus] = useState<YaraStatus>('idle')
  const [yaraStage, setYaraStage] = useState<YaraProgressStage>('loading-engine')
  const [yaraSummary, setYaraSummary] = useState<YaraCompileSummary | null>(null)
  const [yaraReport, setYaraReport] = useState<YaraReport | null>(null)
  const [yaraError, setYaraError] = useState<string | null>(null)
  const [hexTarget, setHexTarget] = useState<number | null>(null)
  const [artifactYara, setArtifactYara] = useState<ArtifactYaraResult[]>([])
  const [artifactYaraStatus, setArtifactYaraStatus] = useState<'idle' | 'running' | 'done' | 'error'>('idle')
  const [artifactYaraError, setArtifactYaraError] = useState<string | null>(null)
  const dynamicEnvironments = useMemo(
    () => (report?.format as Record<string, unknown> | undefined)?.kind === 'elf' ? LINUX_ENVIRONMENT_PROFILES : ENVIRONMENT_PROFILES,
    [report],
  )

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

  const analyzePe64Demo = useCallback(async () => {
    try {
      const name = 'aegis-safe-dynamic-pe64.exe'
      const response = await fetch(`${import.meta.env.BASE_URL}fixtures/${name}`)
      if (!response.ok) throw new Error('Safe PE64 fixture could not be loaded')
      const bytes = await response.arrayBuffer()
      await inspectFile(new File([bytes], name, { type: 'application/octet-stream' }))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Safe PE64 fixture could not be loaded')
      setStatus('error')
    }
  }, [inspectFile])

  const analyzeLinuxDemo = useCallback(async () => {
    try {
      const name = 'nope-safe-dynamic-linux-x64'
      const response = await fetch(`${import.meta.env.BASE_URL}fixtures/${name}`)
      if (!response.ok) throw new Error('Safe Linux fixture could not be loaded')
      const bytes = await response.arrayBuffer()
      await inspectFile(new File([bytes], name, { type: 'application/octet-stream' }))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Safe Linux fixture could not be loaded')
      setStatus('error')
    }
  }, [inspectFile])

  const analyzeCodeDemo = useCallback(async () => {
    try {
      const name = 'aegis-safe-code-analysis-pe64.exe'
      const response = await fetch(`${import.meta.env.BASE_URL}fixtures/${name}`)
      if (!response.ok) throw new Error('Safe code-analysis fixture could not be loaded')
      const bytes = await response.arrayBuffer()
      await inspectFile(new File([bytes], name, { type: 'application/octet-stream' }))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Safe code-analysis fixture could not be loaded')
      setStatus('error')
    }
  }, [inspectFile])

  const analyzePe64ParityDemo = useCallback(async () => {
    try {
      const name = 'aegis-safe-parity-pe64.exe'
      const response = await fetch(`${import.meta.env.BASE_URL}fixtures/${name}`)
      if (!response.ok) throw new Error('Safe PE64 parity fixture could not be loaded')
      const bytes = await response.arrayBuffer()
      await inspectFile(new File([bytes], name, { type: 'application/octet-stream' }))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Safe PE64 parity fixture could not be loaded')
      setStatus('error')
    }
  }, [inspectFile])

  const analyzePe64UnpackingDemo = useCallback(async () => {
    try {
      const name = 'aegis-safe-unpacking-pe64.exe'
      const response = await fetch(`${import.meta.env.BASE_URL}fixtures/${name}`)
      if (!response.ok) throw new Error('Safe PE64 unpacking fixture could not be loaded')
      const bytes = await response.arrayBuffer()
      await inspectFile(new File([bytes], name, { type: 'application/octet-stream' }))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Safe PE64 unpacking fixture could not be loaded')
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

  const analyzeSehDemo = useCallback(async () => {
    try {
      const name = 'aegis-safe-seh-pe32.exe'
      const response = await fetch(`${import.meta.env.BASE_URL}fixtures/${name}`)
      if (!response.ok) throw new Error('SEH fixture could not be loaded')
      const bytes = await response.arrayBuffer()
      await inspectFile(new File([bytes], name, { type: 'application/octet-stream' }))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'SEH fixture could not be loaded')
      setStatus('error')
    }
  }, [inspectFile])

  const analyzeThreadsDemo = useCallback(async () => {
    try {
      const name = 'aegis-safe-threads-pe32.exe'
      const response = await fetch(`${import.meta.env.BASE_URL}fixtures/${name}`)
      if (!response.ok) throw new Error('Thread fixture could not be loaded')
      const bytes = await response.arrayBuffer()
      await inspectFile(new File([bytes], name, { type: 'application/octet-stream' }))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Thread fixture could not be loaded')
      setStatus('error')
    }
  }, [inspectFile])

  const analyzeInstructionsDemo = useCallback(async () => {
    try {
      const name = 'aegis-safe-instructions-pe32.exe'
      const response = await fetch(`${import.meta.env.BASE_URL}fixtures/${name}`)
      if (!response.ok) throw new Error('Instruction fixture could not be loaded')
      const bytes = await response.arrayBuffer()
      await inspectFile(new File([bytes], name, { type: 'application/octet-stream' }))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Instruction fixture could not be loaded')
      setStatus('error')
    }
  }, [inspectFile])

  const analyzeSystemDemo = useCallback(async () => {
    try {
      const name = 'aegis-safe-system-objects-pe32.exe'
      const response = await fetch(`${import.meta.env.BASE_URL}fixtures/${name}`)
      if (!response.ok) throw new Error('System-object fixture could not be loaded')
      const bytes = await response.arrayBuffer()
      await inspectFile(new File([bytes], name, { type: 'application/octet-stream' }))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'System-object fixture could not be loaded')
      setStatus('error')
    }
  }, [inspectFile])

  const analyzeNetworkDemo = useCallback(async () => {
    try {
      const name = 'aegis-safe-network-pe32.exe'
      const response = await fetch(`${import.meta.env.BASE_URL}fixtures/${name}`)
      if (!response.ok) throw new Error('Network fixture could not be loaded')
      const bytes = await response.arrayBuffer()
      await inspectFile(new File([bytes], name, { type: 'application/octet-stream' }))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Network fixture could not be loaded')
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
      const environment = dynamicEnvironments.find((profile) => profile.id === dynamicProfileId) ?? dynamicEnvironments[0]
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
  }, [currentFile, dynamicClient, dynamicEnvironments, dynamicProfileId])

  const runDynamicProfiles = useCallback(async () => {
    if (!currentFile) return
    const run = ++dynamicRun.current
    setDynamicStatus('running'); setDynamicError(null); setDynamicReport(null); setDynamicReports([]); setDynamicStage('loading-engine')
    setArtifactYara([]); setArtifactYaraStatus('idle'); setArtifactYaraError(null)
    try {
      const buffer = await currentFile.arrayBuffer()
      const results = await dynamicClient.analyzeProfiles(currentFile, buffer, dynamicEnvironments, setDynamicStage)
      if (dynamicRun.current !== run) return
      setDynamicReports(results)
      setDynamicReport(results.find((result) => result.profile.environment.id === dynamicProfileId) ?? results[0])
      setDynamicStatus('done')
    } catch (cause) {
      if (dynamicRun.current !== run) return
      setDynamicError(cause instanceof Error ? cause.message : 'Profile matrix analysis failed unexpectedly.')
      setDynamicStatus('error')
    }
  }, [currentFile, dynamicClient, dynamicEnvironments, dynamicProfileId])

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
    anchor.download = `${baseName}.nope-report.json`
    anchor.click()
    window.setTimeout(() => URL.revokeObjectURL(url), 0)
  }

  const busy = status === 'reading' || status === 'analyzing'

  return (
    <div className="app-shell">
      <header className="app-header">
        <a className="wordmark" href="#top" aria-label="NOPE home">
          <LogoMark className="brand-mark" />
          <strong>NOPE<span>.exe</span></strong>
        </a>
      </header>

      <main id="top" className="page">
        {!report && !busy && (
          <section className="intro">
            <div className="intro-copy">
              <p className="kicker">Browser-native binary workbench</p>
              <h1>Look before<br />you launch.</h1>
              <p>Disassemble, emulate, and interrogate suspicious binaries—entirely in your browser. Your files stay local and never execute on the host.</p>
            </div>
            <UploadPanel
              dragging={dragging}
              setDragging={setDragging}
              inputRef={inputRef}
              inspectFile={inspectFile}
              analyzeDemo={analyzeDemo}
              analyzePe64Demo={analyzePe64Demo}
              analyzeLinuxDemo={analyzeLinuxDemo}
              analyzeCodeDemo={analyzeCodeDemo}
              analyzePe64ParityDemo={analyzePe64ParityDemo}
              analyzePe64UnpackingDemo={analyzePe64UnpackingDemo}
              analyzeArtifactDemo={analyzeArtifactDemo}
              analyzeSehDemo={analyzeSehDemo}
              analyzeThreadsDemo={analyzeThreadsDemo}
              analyzeInstructionsDemo={analyzeInstructionsDemo}
              analyzeSystemDemo={analyzeSystemDemo}
              analyzeNetworkDemo={analyzeNetworkDemo}
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
            onCodeOffset={(offset) => { setHexTarget(offset); setActiveTab('hex') }}
            hexTarget={hexTarget}
          />
        )}
      </main>

      <footer className="app-footer">
        <span>NOPE.exe 0.3</span>
        <span>Static and emulated behavior are evidence, not a verdict.</span>
      </footer>
    </div>
  )
}

function UploadPanel({ dragging, setDragging, inputRef, inspectFile, analyzeDemo, analyzePe64Demo, analyzeLinuxDemo, analyzeCodeDemo, analyzePe64ParityDemo, analyzePe64UnpackingDemo, analyzeArtifactDemo, analyzeSehDemo, analyzeThreadsDemo, analyzeInstructionsDemo, analyzeSystemDemo, analyzeNetworkDemo }: {
  dragging: boolean
  setDragging: (value: boolean) => void
  inputRef: React.RefObject<HTMLInputElement | null>
  inspectFile: (file: File) => Promise<void>
  analyzeDemo: () => Promise<void>
  analyzePe64Demo: () => Promise<void>
  analyzeLinuxDemo: () => Promise<void>
  analyzeCodeDemo: () => Promise<void>
  analyzePe64ParityDemo: () => Promise<void>
  analyzePe64UnpackingDemo: () => Promise<void>
  analyzeArtifactDemo: () => Promise<void>
  analyzeSehDemo: () => Promise<void>
  analyzeThreadsDemo: () => Promise<void>
  analyzeInstructionsDemo: () => Promise<void>
  analyzeSystemDemo: () => Promise<void>
  analyzeNetworkDemo: () => Promise<void>
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
      <div className="upload-main">
        <div className="upload-copy">
          <strong>Drop the suspicious file.</strong>
          <span>PE, ELF, Mach-O, or WebAssembly · 128 MiB maximum</span>
        </div>
        <button className="button primary" type="button" onClick={() => inputRef.current?.click()}>Choose file</button>
      </div>
      <div className="demo-list">
        <span>Or try a safe demo</span>
        <button className="demo-chip" type="button" aria-label="Use safe PE demo" onClick={() => void analyzeDemo()}>Safe PE</button>
        <button className="demo-chip" type="button" aria-label="Use safe PE64 demo" onClick={() => void analyzePe64Demo()}>Safe PE64</button>
        <button className="demo-chip" type="button" aria-label="Use safe Linux demo" onClick={() => void analyzeLinuxDemo()}>Safe Linux</button>
        <button className="demo-chip" type="button" aria-label="Use code analysis demo" onClick={() => void analyzeCodeDemo()}>Code analysis</button>
        <button className="demo-chip" type="button" aria-label="Use PE64 parity demo" onClick={() => void analyzePe64ParityDemo()}>PE64 parity</button>
        <button className="demo-chip" type="button" aria-label="Use PE64 unpacking demo" onClick={() => void analyzePe64UnpackingDemo()}>PE64 unpacking</button>
        <button className="demo-chip" type="button" aria-label="Use runtime artifact demo" onClick={() => void analyzeArtifactDemo()}>Runtime artifact</button>
        <button className="demo-chip" type="button" aria-label="Use SEH demo" onClick={() => void analyzeSehDemo()}>SEH</button>
        <button className="demo-chip" type="button" aria-label="Use threads demo" onClick={() => void analyzeThreadsDemo()}>Threads</button>
        <button className="demo-chip" type="button" aria-label="Use instruction demo" onClick={() => void analyzeInstructionsDemo()}>Instruction</button>
        <button className="demo-chip" type="button" aria-label="Use system-object demo" onClick={() => void analyzeSystemDemo()}>System-object</button>
        <button className="demo-chip" type="button" aria-label="Use network demo" onClick={() => void analyzeNetworkDemo()}>Network</button>
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

function Workspace({ report, dynamicReport, dynamicReports, dynamicProfileId, dynamicStatus, dynamicStage, dynamicError, staticClient, dynamicClient, artifactYara, artifactYaraStatus, artifactYaraError, onScanArtifacts, activeTab, onTabChange, onClose, onExport, onRunDynamic, onRunDynamicProfiles, onSelectDynamicProfile, onCancelDynamic, yaraSource, yaraSourceName, yaraStatus, yaraStage, yaraSummary, yaraReport, yaraError, onYaraSource, onRunYara, onYaraOffset, onCodeOffset, hexTarget }: {
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
  onCodeOffset: (offset: number) => void
  hexTarget: number | null
}) {
  const tabs: Array<{ id: Tab; label: string; count?: number }> = [
    { id: 'summary', label: 'Summary', count: report.findings.length },
    { id: 'structure', label: 'Structure', count: report.sections.length },
    { id: 'symbols', label: 'Symbols', count: report.imports.length + report.exports.length },
    { id: 'code', label: 'Code', count: report.code.functions.length },
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
        {activeTab === 'code' && <CodeView report={report} onOffset={onCodeOffset} />}
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
  const architecture = staticReport.sample.architecture ?? ''
  const windowsEligible = format.kind === 'pe' && ((format.bitness === 32 && architecture.includes('X86')) || (format.bitness === 64 && architecture.includes('X86_64')))
  const linuxEligible = format.kind === 'elf' && format.bitness === 64 && architecture.toUpperCase().includes('X86_64')
  const eligible = windowsEligible || linuxEligible
  const [view, setView] = useState<'timeline' | 'behavior' | 'api' | 'instructions' | 'coverage' | 'artifacts' | 'unpacking' | 'exceptions' | 'threads' | 'system' | 'network' | 'provenance' | 'snapshots' | 'unwind' | 'profiles'>('timeline')
  const [timelineTarget, setTimelineTarget] = useState<number | null>(null)

  if (!eligible) {
    return <EmptyState title="Dynamic analysis is not available for this file" text="The current emulator supports PE32/x86, PE64/x86-64, and Linux ELF64/x86-64 executables. Static analysis remains available for every supported format." />
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
          <p className="kicker">{linuxEligible ? 'Linux ELF64/x86-64 interpreter' : 'PE32/x86 + PE64/x86-64 interpreter'}</p>
          <h2>Observe modeled behavior</h2>
          <p>{linuxEligible ? 'Instructions run against a deterministic synthetic Linux userspace. Syscalls, files, processes, memory, and network operations never map to browser or host resources.' : 'Instructions run in a deterministic Rust interpreter. Windows APIs, files, registry keys, memory, and network operations are synthetic and never map to browser resources.'}</p>
          <ProfilePicker profiles={linuxEligible ? LINUX_ENVIRONMENT_PROFILES : ENVIRONMENT_PROFILES} value={profileId} onChange={onSelectProfile} />
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

  const behaviorCount = report.processes.length + report.filesystem.length + report.registry.length + report.network.length + report.memory.length + report.injection.length + report.persistence.length + report.exceptions.length
  return (
    <div className="dynamic-report">
      <div className="profile-toolbar"><ProfilePicker profiles={linuxEligible ? LINUX_ENVIRONMENT_PROFILES : ENVIRONMENT_PROFILES} value={profileId} onChange={onSelectProfile} /><button className="button secondary compact" type="button" onClick={onRunProfiles}>Run profile matrix</button><span>{report.profile.operating_system} · {report.profile.environment.network_mode}</span></div>
      <div className="stats-grid four">
        <Stat label="Termination" value={terminationLabel(report.termination)} detail="Bounded execution" />
        <Stat label="Instructions" value={report.instruction_count.toLocaleString()} detail={`${report.coverage.unique_instruction_addresses.toLocaleString()} unique addresses`} />
        <Stat label="API calls" value={report.api_calls.length.toLocaleString()} detail={`${report.coverage.modeled_api_calls} modeled · ${report.coverage.unmodeled_api_calls} fallback`} />
        <Stat label="Elapsed" value={`${report.elapsed_ms.toFixed(2)} ms`} detail="Dedicated worker" />
      </div>
      <div className="notice safe-notice"><strong>No guest operation left the browser.</strong><span>Network, filesystem, time, process, and memory operations were modeled locally.</span></div>
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
        <button className={view === 'unpacking' ? 'active' : ''} type="button" onClick={() => setView('unpacking')}>Unpacking ({report.payload_generations.length})</button>
        <button className={view === 'exceptions' ? 'active' : ''} type="button" onClick={() => setView('exceptions')}>Exceptions ({report.exceptions.length})</button>
        <button className={view === 'threads' ? 'active' : ''} type="button" onClick={() => setView('threads')}>Threads ({report.threads.length})</button>
        <button className={view === 'system' ? 'active' : ''} type="button" onClick={() => setView('system')}>System objects ({report.system.length})</button>
        <button className={view === 'network' ? 'active' : ''} type="button" onClick={() => setView('network')}>Network ({report.network_exchanges.length})</button>
        <button className={view === 'provenance' ? 'active' : ''} type="button" onClick={() => setView('provenance')}>Provenance ({report.provenance_flows.length})</button>
        <button className={view === 'snapshots' ? 'active' : ''} type="button" onClick={() => setView('snapshots')}>Snapshots ({report.snapshots.length})</button>
        <button className={view === 'unwind' ? 'active' : ''} type="button" onClick={() => setView('unwind')}>Unwind ({report.unwind_functions.length})</button>
        {reports.length > 1 && <button className={view === 'profiles' ? 'active' : ''} type="button" onClick={() => setView('profiles')}>Profile comparison ({reports.length})</button>}
      </div>
      {view === 'timeline' && <TimelineView report={report} target={timelineTarget} />}
      {view === 'behavior' && <BehaviorView report={report} />}
      {view === 'api' && <ApiView report={report} />}
      {view === 'instructions' && <InstructionView report={report} />}
      {view === 'coverage' && <CoverageView report={report} />}
      {view === 'artifacts' && <ArtifactsView report={report} client={client} yara={artifactYara} status={artifactYaraStatus} error={artifactYaraError} onScan={onScanArtifacts} onTimeline={(sequence) => { setTimelineTarget(sequence); setView('timeline') }} />}
      {view === 'unpacking' && <UnpackingView report={report} yara={artifactYara} status={artifactYaraStatus} onScan={onScanArtifacts} />}
      {view === 'exceptions' && <ExceptionView report={report} />}
      {view === 'threads' && <ThreadView report={report} />}
      {view === 'system' && <SystemView report={report} />}
      {view === 'network' && <NetworkView report={report} />}
      {view === 'provenance' && <ProvenanceView report={report} />}
      {view === 'snapshots' && <SnapshotView report={report} />}
      {view === 'unwind' && <UnwindView report={report} />}
      {view === 'profiles' && <ProfileComparison reports={reports} onSelect={(id) => { onSelectProfile(id); setView('timeline') }} />}
    </div>
  )
}

function SnapshotView({ report }: { report: DynamicReport }) {
  return <div className="generation-layout"><div className="stats-grid"><Stat label="Snapshots" value={report.snapshot_stats.count.toLocaleString()} detail={`${report.snapshot_stats.max_snapshots} maximum`} /><Stat label="Dirty-region cap" value={report.snapshot_stats.max_dirty_regions.toLocaleString()} detail={`${formatBytes(report.snapshot_stats.sampled_bytes_per_region)} sampled per region`} /><Stat label="Capture status" value={report.snapshot_stats.truncated ? 'Truncated' : 'Complete'} detail="Metadata and hashes only" /></div><Section title="Execution state snapshots" description="Entry, API-boundary, and final states contain registers, event counters, and a deterministic bounded memory fingerprint—never raw guest-memory dumps."><Table><thead><tr><th>#</th><th>Trigger</th><th>Instruction</th><th>Virtual time</th><th>RIP / RAX</th><th>Events</th><th>Dirty regions</th><th>State SHA-256</th></tr></thead><tbody>{report.snapshots.map((snapshot) => { const behavior = snapshot.events.processes + snapshot.events.filesystem + snapshot.events.registry + snapshot.events.network + snapshot.events.memory + snapshot.events.injection + snapshot.events.persistence; return <tr key={snapshot.sequence}><td>{snapshot.sequence + 1}</td><td><code className="strong-code">{snapshot.trigger}</code></td><td>{snapshot.instruction.toLocaleString()}</td><td>{snapshot.virtual_time_ms.toLocaleString()} ms</td><td><code>{formatOffset(snapshot.registers.rip)} / {formatOffset(snapshot.registers.rax)}</code></td><td>{snapshot.events.api_calls} API · {behavior} behavior · {snapshot.events.provenance_flows} flows</td><td>{snapshot.dirty_memory_regions}</td><td><code>{snapshot.state_sha256.slice(0, 16)}…</code></td></tr> })}</tbody></Table></Section></div>
}

function UnwindView({ report }: { report: DynamicReport }) {
  if (!report.unwind_functions.length) return <EmptyState title="No PE64 unwind metadata" text={report.profile.operating_system.startsWith('Linux') ? 'Linux ELF64 does not use the PE64 runtime-function table.' : 'PE32 images do not use the PE64 runtime-function table, or this PE64 image did not provide one.'} />
  return <Section title="PE64 unwind metadata" description="Bounded RUNTIME_FUNCTION entries from the exception directory support x64 stack and exception analysis."><Table><thead><tr><th>#</th><th>Function begin</th><th>Function end</th><th>Unwind info</th></tr></thead><tbody>{report.unwind_functions.map((entry, index) => <tr key={`${entry.begin_address}-${index}`}><td>{index + 1}</td><td><code>{formatOffset(entry.begin_address)}</code></td><td><code>{formatOffset(entry.end_address)}</code></td><td><code>{formatOffset(entry.unwind_info_address)}</code></td></tr>)}</tbody></Table></Section>
}

function ProvenanceView({ report }: { report: DynamicReport }) {
  const sources = new Map(report.provenance_sources.map((source) => [source.id, source]))
  if (!report.provenance_flows.length) return <EmptyState title="No provenance flows" text="No labeled sample, network, registry, file, or transformed bytes reached a modeled security-relevant sink." />
  return <div className="generation-layout"><div className="stats-grid"><Stat label="Data sources" value={report.provenance_stats.source_count.toLocaleString()} detail="256 maximum" /><Stat label="Security sinks" value={report.provenance_stats.flow_count.toLocaleString()} detail="4,096 maximum" /><Stat label="Tracked ranges" value={report.provenance_stats.tracked_ranges.toLocaleString()} detail={report.provenance_stats.truncated ? 'Bound reached' : 'Bounded labels'} /></div><Section title="Explainable data flows" description="API-level provenance follows bounded byte ranges through modeled copies and transformations; it is evidence, not whole-program symbolic execution."><Table><thead><tr><th>#</th><th>Source</th><th>Flow</th><th>Destination</th><th>Bytes</th><th>API</th><th>Instruction</th></tr></thead><tbody>{report.provenance_flows.map((flow) => { const labels = flow.source_ids.map((id) => sources.get(id)).filter(Boolean); return <tr key={flow.sequence}><td>{flow.sequence + 1}</td><td>{labels.map((source) => <span className="tag" key={source!.id}>{source!.kind}: {source!.label}</span>)}</td><td><strong>{labels.map((source) => source!.kind).join(' + ')} → {flow.sink.replaceAll('_', ' ')}</strong></td><td><code>{flow.destination}</code></td><td>{formatBytes(flow.size)}</td><td><code>{flow.api}</code></td><td>{flow.instruction.toLocaleString()}</td></tr> })}</tbody></Table></Section><Section title="Tracked data sources" description="Derived sources preserve parent IDs so decoded, converted, or hashed buffers can be traced back to their inputs."><Table><thead><tr><th>ID</th><th>Kind</th><th>Label</th><th>Range</th><th>API</th><th>Parents</th></tr></thead><tbody>{report.provenance_sources.map((source) => <tr key={source.id}><td><code>{source.id}</code></td><td><span className="tag">{source.kind}</span></td><td>{source.label}</td><td><code>{formatOffset(source.address)} · {formatBytes(source.size)}</code></td><td><code>{source.api}</code></td><td><code>{source.parent_ids.join(', ') || '—'}</code></td></tr>)}</tbody></Table></Section></div>
}

function NetworkView({ report }: { report: DynamicReport }) {
  const exportPcap = () => {
    const payload = { schema: 'aegis-synthetic-pcap-v1', sample_sha256: report.sample_sha256, scenario: report.profile.network_scenario, exchanges: report.network_exchanges }
    const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })); const anchor = document.createElement('a'); anchor.href = url; anchor.download = `${report.sample_sha256.slice(0, 12)}.synthetic-pcap.json`; anchor.click(); window.setTimeout(() => URL.revokeObjectURL(url), 0)
  }
  if (!report.network_exchanges.length) return <EmptyState title="No scripted network exchanges" text="The sample did not complete a modeled HTTP or socket exchange." />
  return <div className="generation-layout"><div className="artifact-actions"><div><strong>{report.network_exchanges.length} deterministic exchanges</strong><span>Scenario {report.profile.network_scenario} · no host network access</span></div><button className="button secondary compact" type="button" onClick={exportPcap}>Export synthetic PCAP JSON</button></div><Section title="Scripted network exchanges" description="Redirects, request metadata, response status, and downloaded-artifact links are preserved without raw report bytes."><Table><thead><tr><th>#</th><th>Protocol</th><th>Operation</th><th>Destination</th><th>Response</th><th>Size</th><th>Outcome</th><th>Artifact</th></tr></thead><tbody>{report.network_exchanges.map((exchange) => <tr key={exchange.sequence}><td>{exchange.sequence + 1}</td><td><span className="tag">{exchange.protocol}</span></td><td>{exchange.operation}</td><td><code>{exchange.destination}</code></td><td>{exchange.response_status ?? '—'}</td><td>{formatBytes(exchange.response_size)}</td><td>{exchange.outcome}</td><td><code>{exchange.artifact_id ? `${exchange.artifact_id.slice(0, 12)}…` : '—'}</code></td></tr>)}</tbody></Table></Section></div>
}

function SystemView({ report }: { report: DynamicReport }) {
  if (!report.system.length) return <EmptyState title="No system-object activity" text="No synchronization, enumeration, token, mapping, pipe, resource, or crypto APIs were reached." />
  const linux = report.profile.operating_system.startsWith('Linux')
  return <Section title={linux ? 'Synthetic Linux runtime objects' : 'Synthetic Windows system objects'} description="Every object is bounded in worker memory and has no host counterpart."><Table><thead><tr><th>Category</th><th>Operation</th><th>Target</th><th>Detail</th><th>Result</th></tr></thead><tbody>{report.system.map((event, index) => <tr key={`${event.category}-${index}`}><td><span className="tag">{event.category}</span></td><td>{event.operation.replaceAll('_', ' ')}</td><td><code>{event.target}</code></td><td>{event.detail}</td><td><code>{formatOffset(event.result)}</code></td></tr>)}</tbody></Table></Section>
}

function ThreadView({ report }: { report: DynamicReport }) {
  return <div className="generation-layout"><div className="stats-grid"><Stat label="Guest threads" value={report.threads.length.toLocaleString()} detail="64 maximum" /><Stat label="Scheduler events" value={report.thread_events.length.toLocaleString()} detail="100-instruction quantum" /><Stat label="Terminated" value={report.threads.filter((thread) => thread.state === 'terminated').length.toLocaleString()} detail="Deterministic exits" /></div><Section title="Guest thread states" description="Threads share synthetic process memory while registers, stacks, and TEB/SEH state remain isolated."><Table><thead><tr><th>TID</th><th>Start</th><th>Parameter</th><th>State</th><th>Instructions</th><th>Exit code</th></tr></thead><tbody>{report.threads.map((thread) => <tr key={thread.tid}><td>{thread.tid}</td><td><code>{formatOffset(thread.start_address)}</code></td><td><code>{formatOffset(thread.parameter)}</code></td><td><span className="tag">{thread.state}</span></td><td>{thread.instruction_count.toLocaleString()}</td><td>{thread.exit_code ?? '—'}</td></tr>)}</tbody></Table></Section><Section title="Scheduler timeline" description="Creation, deterministic context switches, and exits are recorded without host threads."><Table><thead><tr><th>#</th><th>TID</th><th>Operation</th><th>Instruction</th><th>Start</th><th>Parameter</th></tr></thead><tbody>{report.thread_events.map((event) => <tr key={event.sequence}><td>{event.sequence + 1}</td><td>{event.tid}</td><td>{event.operation}</td><td>{event.instruction.toLocaleString()}</td><td><code>{formatOffset(event.start_address)}</code></td><td><code>{formatOffset(event.parameter)}</code></td></tr>)}</tbody></Table></Section></div>
}

function ExceptionView({ report }: { report: DynamicReport }) {
  if (!report.exceptions.length) return <EmptyState title="No guest exceptions dispatched" text="Execution did not reach a breakpoint or fault with a valid bounded guest handler." />
  return <Section title="Structured exception handling" description="Guest handlers ran inside the interpreter. Invalid or exhausted chains fall back to structured termination."><Table><thead><tr><th>#</th><th>Exception</th><th>Address</th><th>Handler</th><th>Frame</th><th>Disposition</th><th>Outcome</th></tr></thead><tbody>{report.exceptions.map((event) => <tr key={event.sequence}><td>{event.sequence + 1}</td><td><code className="strong-code">{event.name}</code><small>{formatOffset(event.code)}</small></td><td><code>{formatOffset(event.address)}</code></td><td><code>{event.handler == null ? '—' : formatOffset(event.handler)}</code></td><td><code>{event.establisher_frame == null ? '—' : formatOffset(event.establisher_frame)}</code></td><td>{event.disposition == null ? 'Pending' : event.disposition === -1 ? 'Continue execution' : event.disposition === 0 ? 'Continue search' : event.disposition}</td><td><span className="tag">{event.outcome.replaceAll('_', ' ')}</span></td></tr>)}</tbody></Table></Section>
}

function UnpackingView({ report, yara, status, onScan }: { report: DynamicReport; yara: ArtifactYaraResult[]; status: 'idle' | 'running' | 'done' | 'error'; onScan: () => void }) {
  if (!report.payload_generations.length) return <EmptyState title="No payload generations observed" text="No dirty memory region became executable, overwrote the entry-point region, or produced a distinct executed version." />
  const artifactById = new Map(report.artifacts.map((artifact) => [artifact.id, artifact]))
  const yaraById = new Map(yara.map((result) => [result.artifact_id, result]))
  return <div className="generation-layout"><div className="artifact-actions"><div><strong>{report.generation_stats.count} generations across {report.generation_stats.chains} chains</strong><span>{report.generation_stats.executed_generations} executed · {report.generation_stats.entry_point_candidates} entry candidates · {report.generation_stats.reconstructed_imports} reconstructed imports</span></div><button className="button primary compact" type="button" disabled={status === 'running'} onClick={onScan}>{status === 'running' ? 'Scanning generations…' : 'Scan generations with YARA'}</button></div><Section title="Payload lineage" description="Generated executable regions include bounded entry-point candidates and imports observed from calls originating inside that generation."><Table><thead><tr><th>Generation</th><th>Parent</th><th>Region</th><th>Candidate entry</th><th>Observed runtime imports</th><th>Trigger</th><th>Flags</th><th>SHA-256</th><th>YARA</th></tr></thead><tbody>{report.payload_generations.map((generation) => { const artifact = artifactById.get(generation.artifact_id); const result = yaraById.get(generation.artifact_id); return <tr key={generation.id}><td><code className="strong-code">#{generation.sequence + 1}</code></td><td>{generation.parent_id ? <code>{generation.parent_id.split('-').slice(0, 2).join('-')}</code> : 'Root'}</td><td><code>{formatOffset(generation.region_base)}</code><small>{formatBytes(generation.size)} · {generation.permissions}</small></td><td>{generation.entry_point_candidate == null ? '—' : <><code>{formatOffset(generation.entry_point_candidate)}</code><small>instruction {generation.first_execution_instruction?.toLocaleString()}</small></>}</td><td>{generation.reconstructed_imports.length ? generation.reconstructed_imports.map((item) => <code key={item}>{item}</code>) : '—'}</td><td>{generation.trigger}<small>instruction {generation.capture_instruction.toLocaleString()}</small></td><td><div className="generation-flags">{generation.executed && <span className="tag danger">executed</span>}{generation.executable_heap && <span className="tag">heap</span>}{generation.entry_point_overwrite && <span className="tag danger">entry overwrite</span>}</div></td><td><code>{artifact?.sha256.slice(0, 16) ?? generation.artifact_id.slice(0, 16)}…</code></td><td>{result?.error ? 'Error' : result ? result.report?.matches.map((match) => match.identifier).join(', ') || 'No match' : 'Not scanned'}</td></tr> })}</tbody></Table></Section></div>
}

function ProfilePicker({ profiles, value, onChange }: { profiles: DynamicEnvironmentProfile[]; value: string; onChange: (value: string) => void }) {
  return <label className="profile-picker"><span>Environment profile</span><select aria-label="Environment profile" value={value} onChange={(event) => onChange(event.target.value)}>{profiles.map((profile) => <option key={profile.id} value={profile.id}>{profile.label}</option>)}</select></label>
}

function ProfileComparison({ reports, onSelect }: { reports: DynamicReport[]; onSelect: (profileId: string) => void }) {
  const [baselineId, setBaselineId] = useState(reports[0].profile.environment.id)
  const [candidateId, setCandidateId] = useState(reports[1]?.profile.environment.id ?? baselineId)
  const baseline = reports.find((report) => report.profile.environment.id === baselineId) ?? reports[0]
  const candidate = reports.find((report) => report.profile.environment.id === candidateId) ?? reports[1] ?? baseline
  const comparison = compareDynamicRuns(baseline, candidate)
  const exportComparison = () => { const url = URL.createObjectURL(new Blob([JSON.stringify(comparison, null, 2)], { type: 'application/json' })); const anchor = document.createElement('a'); anchor.href = url; anchor.download = `${baseline.profile.environment.id}-vs-${candidate.profile.environment.id}.nope-run-diff.json`; anchor.click(); window.setTimeout(() => URL.revokeObjectURL(url), 0) }
  return <div className="generation-layout"><Section title="Environment profile comparison" description="The same sample was executed independently under deterministic synthetic environments."><Table><thead><tr><th>Profile</th><th>Environment</th><th>Termination</th><th>Instructions</th><th>Behavior</th><th>Artifacts</th><th>First snapshot delta</th></tr></thead><tbody>{reports.map((report) => { const delta = compareDynamicRuns(reports[0], report); return <tr key={report.profile.environment.id}><td><button className="offset-link" type="button" onClick={() => onSelect(report.profile.environment.id)}>{report.profile.environment.label}</button></td><td><small>{report.profile.operating_system}<br />{report.profile.environment.cpu_count} CPU · {formatBytes(report.profile.environment.memory_mb * 1024 * 1024)} · {report.profile.environment.network_mode}{report.profile.environment.debugger_present ? ' · debugger' : ''}</small></td><td>{terminationLabel(report.termination)}</td><td>{report.instruction_count.toLocaleString()}</td><td>{dynamicBehaviorCount(report)}</td><td>{report.artifacts.length}</td><td><span className={`tag ${delta.different ? 'danger' : ''}`}>{report === reports[0] ? 'Baseline' : delta.first_divergence?.trigger ?? (delta.different ? 'Report delta' : 'Same path')}</span></td></tr> })}</tbody></Table></Section><Section title="Detailed run diff" description="Compare any two deterministic runs and export a metadata-only diff."><div className="artifact-actions"><div className="button-row"><label className="profile-picker"><span>Baseline</span><select aria-label="Comparison baseline" value={baselineId} onChange={(event) => setBaselineId(event.target.value)}>{reports.map((report) => <option key={report.profile.environment.id} value={report.profile.environment.id}>{report.profile.environment.label}</option>)}</select></label><label className="profile-picker"><span>Candidate</span><select aria-label="Comparison candidate" value={candidateId} onChange={(event) => setCandidateId(event.target.value)}>{reports.map((report) => <option key={report.profile.environment.id} value={report.profile.environment.id}>{report.profile.environment.label}</option>)}</select></label></div><button className="button secondary compact" type="button" onClick={exportComparison}>Export run diff JSON</button></div><div className="stats-grid"><Stat label="First divergence" value={comparison.first_divergence?.trigger ?? 'None'} detail={comparison.first_divergence ? `snapshot ${comparison.first_divergence.sequence + 1}` : 'State hashes match'} /><Stat label="Instruction delta" value={comparison.deltas.instructions.toLocaleString()} detail={`${candidate.instruction_count.toLocaleString()} candidate`} /><Stat label="Behavior delta" value={comparison.deltas.behavior.toLocaleString()} detail={`${comparison.deltas.provenance_flows} provenance flows`} /></div><Table><thead><tr><th>Set</th><th>Added</th><th>Removed</th></tr></thead><tbody><tr><td>APIs</td><td><code>{comparison.api_changes.added.join(', ') || 'None'}</code></td><td><code>{comparison.api_changes.removed.join(', ') || 'None'}</code></td></tr><tr><td>Findings</td><td><code>{comparison.finding_changes.added.join(', ') || 'None'}</code></td><td><code>{comparison.finding_changes.removed.join(', ') || 'None'}</code></td></tr></tbody></Table></Section></div>
}

function dynamicBehaviorCount(report: DynamicReport) {
  return report.processes.length + report.filesystem.length + report.registry.length + report.network.length + report.memory.length + report.persistence.length + report.injection.length
}

function setChanges(baseline: string[], candidate: string[]) {
  const before = new Set(baseline); const after = new Set(candidate)
  return { added: [...after].filter((value) => !before.has(value)).sort(), removed: [...before].filter((value) => !after.has(value)).sort() }
}

function compareDynamicRuns(baseline: DynamicReport, candidate: DynamicReport) {
  const count = Math.max(baseline.snapshots.length, candidate.snapshots.length)
  let firstDivergence: { sequence: number; trigger: string; baseline_sha256: string | null; candidate_sha256: string | null } | null = null
  for (let sequence = 0; sequence < count; sequence += 1) { const before = baseline.snapshots[sequence]; const after = candidate.snapshots[sequence]; if (!before || !after || before.trigger !== after.trigger || before.state_sha256 !== after.state_sha256) { firstDivergence = { sequence, trigger: after?.trigger ?? before?.trigger ?? 'missing snapshot', baseline_sha256: before?.state_sha256 ?? null, candidate_sha256: after?.state_sha256 ?? null }; break } }
  const apiChanges = setChanges(baseline.api_calls.map((event) => `${event.module}!${event.name}`), candidate.api_calls.map((event) => `${event.module}!${event.name}`))
  const findingChanges = setChanges(baseline.findings.map((finding) => finding.id), candidate.findings.map((finding) => finding.id))
  const deltas = { instructions: candidate.instruction_count - baseline.instruction_count, api_calls: candidate.api_calls.length - baseline.api_calls.length, behavior: dynamicBehaviorCount(candidate) - dynamicBehaviorCount(baseline), artifacts: candidate.artifacts.length - baseline.artifacts.length, provenance_flows: candidate.provenance_flows.length - baseline.provenance_flows.length }
  const terminationChanged = JSON.stringify(baseline.termination) !== JSON.stringify(candidate.termination)
  const different = firstDivergence !== null || terminationChanged || Object.values(deltas).some((value) => value !== 0) || apiChanges.added.length > 0 || apiChanges.removed.length > 0 || findingChanges.added.length > 0 || findingChanges.removed.length > 0
  return { schema: 'aegis-run-diff-v1', sample_sha256: baseline.sample_sha256, baseline_profile: baseline.profile.environment.id, candidate_profile: candidate.profile.environment.id, different, first_divergence: firstDivergence, termination_changed: terminationChanged, deltas, api_changes: apiChanges, finding_changes: findingChanges }
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
    <div className="artifact-actions"><div className="timeline-filters">{['all', 'memory', 'virtual_file', 'remote_memory', 'configuration', 'network_download'].map((value) => <button type="button" className={kind === value ? 'active' : ''} key={value} onClick={() => setKind(value)}>{value.replaceAll('_', ' ')}</button>)}</div><button className="button primary compact" type="button" disabled={status === 'running'} onClick={onScan}>{status === 'running' ? 'Scanning artifacts…' : 'Scan artifacts with YARA'}</button></div>
    {error && <div className="notice error-notice yara-error" role="alert"><div><strong>Artifact YARA stopped</strong><span>{error}</span></div></div>}
    <div className="artifact-grid"><Section title="Captured artifacts" description={`${report.artifact_stats.count} unique artifacts · ${formatBytes(report.artifact_stats.retained_bytes)} retained in the worker.`}><Table><thead><tr><th>Name</th><th>Kind</th><th>Format</th><th>Size</th><th>Entropy</th><th>YARA</th></tr></thead><tbody>{artifacts.map((artifact) => { const result = yaraFor(artifact.id); return <tr className={selected?.id === artifact.id ? 'selected-row' : ''} key={artifact.id} onClick={() => { setSelectedId(artifact.id); setOffset(0) }}><td><code className="strong-code">{artifact.name}</code></td><td><span className="tag">{artifact.kind}</span></td><td>{artifact.detected_format}</td><td>{formatBytes(artifact.captured_size)}</td><td>{artifact.entropy.toFixed(2)}</td><td>{result?.error ? 'Error' : result ? `${result.report?.matches.length ?? 0} matches` : 'Not scanned'}</td></tr> })}</tbody></Table></Section>
      {selected && <Section title={selected.name} description={`${selected.sha256.slice(0, 20)}… · ${selected.trigger}`}><div className="artifact-detail"><dl className="limits-list"><div><dt>Kind</dt><dd>{selected.kind}</dd></div><div><dt>Format</dt><dd>{selected.detected_format}</dd></div><div><dt>Permissions</dt><dd>{selected.permissions ?? '—'}</dd></div><div><dt>Captured</dt><dd>{formatBytes(selected.captured_size)}</dd></div></dl><div className="button-row"><button className="button secondary compact" type="button" onClick={() => setExportTarget(selected.id)}>Export raw bytes</button>{selected.origins[0]?.timeline_sequence != null && <button className="button secondary compact" type="button" onClick={() => onTimeline(selected.origins[0].timeline_sequence!)}>View timeline origin</button>}</div>{readError ? <div className="notice warning-notice">{readError}</div> : <ArtifactHex bytes={bytes} offset={offset} total={selected.captured_size} onOffset={setOffset} />}<h3>Strings and indicators</h3><div className="artifact-strings">{selected.indicators.map((indicator) => <code key={`${indicator.offset}-${indicator.value}`}>{indicator.kind}: {indicator.value}</code>)}{selected.strings.slice(0, 24).map((item) => <code key={`${item.offset}-${item.value}`}>{formatOffset(item.offset)} {item.value}</code>)}</div>{yaraFor(selected.id)?.report && <div className="notice safe-notice"><strong>{yaraFor(selected.id)!.report!.matches.length} YARA rule matches.</strong><span>{yaraFor(selected.id)!.report!.matches.map((match) => match.identifier).join(', ') || 'No rules matched.'}</span></div>}</div></Section>}
    </div>
    {exportTarget && selected && <div className="modal-backdrop" role="presentation"><div className="confirm-dialog" role="dialog" aria-modal="true" aria-labelledby="artifact-export-title"><h2 id="artifact-export-title">Export potentially malicious bytes?</h2><p><strong>{selected.name}</strong> may contain executable or harmful content. NOPE will download {formatBytes(selected.captured_size)} with SHA-256 <code>{selected.sha256}</code>.</p><div className="button-row"><button className="button secondary" type="button" onClick={() => setExportTarget(null)}>Cancel</button><button className="button primary" type="button" onClick={() => void exportBytes()}>Export raw bytes</button></div></div></div>}
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
  const diagnostic = report.diagnostics.first_unsupported
  return <div className="coverage-layout"><div className="stats-grid"><Stat label="Unique code addresses" value={coverage.unique_instruction_addresses.toLocaleString()} detail={`${report.instruction_count.toLocaleString()} instructions executed`} /><Stat label="Unique APIs" value={coverage.unique_api_names.toLocaleString()} detail={`${coverage.dynamic_api_resolutions} dynamically resolved`} /><Stat label="Modeled API coverage" value={`${modeledPercent.toFixed(1)}%`} detail={`${coverage.unmodeled_api_calls} conservative fallbacks`} /></div><Section title="Interpretation limits" description="Coverage describes this emulation path, not every path in the binary."><dl className="limits-list"><div><dt>Trace records</dt><dd>{report.instructions.length.toLocaleString()}</dd></div><div><dt>Invalid encodings</dt><dd>{report.diagnostics.invalid_instruction_count.toLocaleString()}</dd></div><div><dt>Report truncated</dt><dd>{report.truncated ? 'Yes' : 'No'}</dd></div><div><dt>Termination</dt><dd>{terminationLabel(report.termination)}</dd></div><div><dt>Schema</dt><dd>Dynamic v{report.schema_version}</dd></div></dl></Section>{diagnostic && <Section title="First unsupported instruction" description="Bounded decoder context around the point where emulation stopped."><div className="diagnostic-card"><strong>{diagnostic.instruction}</strong><code>{formatOffset(diagnostic.address)} · {diagnostic.bytes}</code><div className="evidence">{diagnostic.nearby_trace.map((event) => <code key={event.index}>{formatOffset(event.address)} {event.text}</code>)}</div></div></Section>}</div>
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

function CodeView({ report, onOffset }: { report: AnalysisReport; onOffset: (offset: number) => void }) {
  const defaultMode = report.code.capabilities.length > 0 ? 'capabilities' : 'disassembly'
  const [mode, setMode] = useState<'capabilities' | 'disassembly' | 'cfg'>(defaultMode)
  const [selectedAddress, setSelectedAddress] = useState<number | null>(report.code.functions[0]?.address ?? null)
  useEffect(() => {
    setMode(report.code.capabilities.length > 0 ? 'capabilities' : 'disassembly')
    setSelectedAddress(report.code.functions[0]?.address ?? null)
  }, [report.sample.sha256, report.code.capabilities.length, report.code.functions])
  const selected = report.code.functions.find((item) => item.address === selectedAddress) ?? report.code.functions[0] ?? null
  const stats = report.code.stats
  return <div className="code-layout">
    <div className="stats-grid">
      <Stat label="Functions" value={stats.functions.toLocaleString()} detail={`${stats.basic_blocks.toLocaleString()} basic blocks`} />
      <Stat label="Instructions" value={stats.decoded_instructions.toLocaleString()} detail={`${stats.control_flow_edges.toLocaleString()} CFG edges`} />
      <Stat label="Capabilities" value={report.code.capabilities.length.toLocaleString()} detail={`${formatBytes(stats.executable_bytes)} executable bytes`} />
    </div>
    {stats.truncated && <div className="notice warning-notice"><span>Code analysis reached a deterministic safety limit. The retained functions and capabilities remain usable, but the report is incomplete.</span></div>}
    {!report.code.disassembly_supported && <div className="notice warning-notice"><span>{report.code.reason ?? 'Disassembly is unavailable for this architecture.'} Import- and string-based capability evidence is still shown.</span></div>}
    <Section title="Static code analysis" description="Recursive x86/x64 traversal and transparent first-party capability rules; no code is executed.">
      <div className="subtabs">
        <button type="button" className={mode === 'capabilities' ? 'active' : ''} onClick={() => setMode('capabilities')}>Capabilities ({report.code.capabilities.length})</button>
        <button type="button" className={mode === 'disassembly' ? 'active' : ''} disabled={!selected} onClick={() => setMode('disassembly')}>Disassembly ({stats.decoded_instructions})</button>
        <button type="button" className={mode === 'cfg' ? 'active' : ''} disabled={!selected} onClick={() => setMode('cfg')}>Control flow ({stats.control_flow_edges})</button>
      </div>
      {mode === 'capabilities' && <CapabilityView report={report} onOffset={onOffset} />}
      {mode === 'disassembly' && (selected ? <DisassemblyView functions={report.code.functions} selected={selected} onSelect={setSelectedAddress} onOffset={onOffset} /> : <EmptyState title="No functions discovered" text={report.code.reason ?? 'No valid entry, export, or direct-call targets were found in bounded executable bytes.'} />)}
      {mode === 'cfg' && (selected ? <CfgView functions={report.code.functions} selected={selected} onSelect={setSelectedAddress} onOffset={onOffset} /> : <EmptyState title="No control-flow graph available" text="A decoded function is required to construct a graph." />)}
    </Section>
  </div>
}

function CapabilityView({ report, onOffset }: { report: AnalysisReport; onOffset: (offset: number) => void }) {
  if (report.code.capabilities.length === 0) return <EmptyState title="No capabilities matched" text="The bounded first-party rules found no supported import, string, or instruction combination. This is not evidence that the sample is safe." />
  return <div className="capability-list">{report.code.capabilities.map((capability) => <article className="capability" key={capability.id}>
    <div className="capability-heading"><div><span className="capability-namespace">{capability.namespace}</span><h3>{capability.name}</h3></div><span className={`tag confidence-${capability.confidence}`}>{capability.confidence} confidence</span></div>
    <p>{capability.description}</p>
    <div className="evidence">{capability.evidence.map((evidence, index) => evidence.file_offset != null
      ? <button className="offset-link" type="button" key={`${evidence.kind}-${evidence.file_offset}-${index}`} onClick={() => onOffset(evidence.file_offset!)}>{evidence.kind} · {evidence.value} · file {formatOffset(evidence.file_offset)}</button>
      : <code key={`${evidence.kind}-${evidence.address}-${index}`}>{evidence.kind} · {evidence.value}{evidence.address != null ? ` · ${formatOffset(evidence.address)}` : ''}</code>)}</div>
  </article>)}</div>
}

function FunctionPicker({ functions, selected, onSelect }: { functions: StaticFunction[]; selected: StaticFunction; onSelect: (address: number) => void }) {
  const instructionCount = selected.blocks.reduce((total, block) => total + block.instructions.length, 0)
  return <div className="code-function-toolbar"><label><span>Function</span><select aria-label="Static function" value={selected.address} onChange={(event) => onSelect(Number(event.target.value))}>{functions.map((item) => <option key={item.address} value={item.address}>{item.name} · {formatOffset(item.address)}</option>)}</select></label><div><span className="tag">{selected.source.replaceAll('_', ' ')}</span><small>{selected.blocks.length} blocks · {instructionCount} instructions · {selected.calls.length} calls</small></div></div>
}

function DisassemblyView({ functions, selected, onSelect, onOffset }: { functions: StaticFunction[]; selected: StaticFunction; onSelect: (address: number) => void; onOffset: (offset: number) => void }) {
  return <div className="code-detail"><FunctionPicker functions={functions} selected={selected} onSelect={onSelect} /><InstructionTable blocks={selected.blocks} onOffset={onOffset} />{selected.calls.length > 0 && <div className="code-call-list"><strong>Observed call sites</strong>{selected.calls.map((call) => <code key={`${call.instruction_address}-${call.target}`}>{formatOffset(call.instruction_address)} → {call.target != null ? formatOffset(call.target) : 'indirect target'}</code>)}</div>}</div>
}

function InstructionTable({ blocks, onOffset }: { blocks: StaticBasicBlock[]; onOffset: (offset: number) => void }) {
  return <Table><thead><tr><th>Address</th><th>File</th><th>Bytes</th><th>Instruction</th><th>Target</th></tr></thead>{blocks.map((block) => <tbody key={block.start}><tr className="block-row"><td colSpan={5}><strong>Basic block {formatOffset(block.start)}</strong><span>{block.instructions.length} instructions</span></td></tr>{block.instructions.map((instruction) => <tr key={`${instruction.address}-${instruction.file_offset}`}><td><code>{formatOffset(instruction.address)}</code></td><td><button className="offset-link" type="button" onClick={() => onOffset(instruction.file_offset)}>{formatOffset(instruction.file_offset)}</button></td><td><code className="instruction-bytes">{instruction.bytes}</code></td><td><code className="strong-code">{instruction.text}</code></td><td><code>{instruction.branch_target != null ? formatOffset(instruction.branch_target) : '—'}</code></td></tr>)}</tbody>)}</Table>
}

function CfgView({ functions, selected, onSelect, onOffset }: { functions: StaticFunction[]; selected: StaticFunction; onSelect: (address: number) => void; onOffset: (offset: number) => void }) {
  const visibleBlocks = selected.blocks.slice(0, 64)
  const [activeBlock, setActiveBlock] = useState(visibleBlocks[0]?.start ?? null)
  useEffect(() => setActiveBlock(selected.blocks[0]?.start ?? null), [selected.address, selected.blocks])
  const layout = useMemo(() => buildCfgLayout(selected, visibleBlocks), [selected, visibleBlocks])
  const block = selected.blocks.find((item) => item.start === activeBlock) ?? visibleBlocks[0] ?? null
  const marker = `cfg-arrow-${selected.address.toString(16)}`
  return <div className="cfg-layout"><FunctionPicker functions={functions} selected={selected} onSelect={onSelect} />{selected.blocks.length > visibleBlocks.length && <div className="notice warning-notice"><span>The visual graph shows the first 64 of {selected.blocks.length} blocks. The disassembly retains all bounded blocks.</span></div>}<div className="cfg-scroll"><svg className="cfg-graph" viewBox={`0 0 ${layout.width} ${layout.height}`} width={layout.width} height={layout.height} role="img" aria-label={`Control-flow graph for ${selected.name}`}><defs><marker id={marker} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" /></marker></defs>{layout.edges.map((edge, index) => <path key={`${edge.from}-${edge.to}-${edge.kind}-${index}`} className={`cfg-edge cfg-edge-${edge.kind}`} d={edge.path} markerEnd={`url(#${marker})`} />)}{layout.nodes.map((node) => <g key={node.block.start} className={`cfg-node ${activeBlock === node.block.start ? 'selected' : ''}`} transform={`translate(${node.x} ${node.y})`} role="button" aria-label={`Basic block ${formatOffset(node.block.start)}`} tabIndex={0} onClick={() => setActiveBlock(node.block.start)} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') setActiveBlock(node.block.start) }}><rect width={layout.nodeWidth} height={layout.nodeHeight} rx="7" /><text x="12" y="22" className="cfg-address">{formatOffset(node.block.start)}</text>{node.block.instructions.slice(0, 3).map((instruction, index) => <text key={instruction.address} x="12" y={43 + index * 16}>{instruction.text.slice(0, 31)}</text>)}</g>)}</svg></div>{block && <div className="cfg-block-detail"><strong>Selected block {formatOffset(block.start)}</strong><InstructionTable blocks={[block]} onOffset={onOffset} /></div>}</div>
}

function buildCfgLayout(func: StaticFunction, blocks: StaticBasicBlock[]) {
  const nodeWidth = 246
  const nodeHeight = 98
  const horizontalGap = 76
  const verticalGap = 34
  const addresses = new Set(blocks.map((block) => block.start))
  const adjacency = new Map<number, number[]>()
  for (const edge of func.edges) if (addresses.has(edge.from) && addresses.has(edge.to)) adjacency.set(edge.from, [...(adjacency.get(edge.from) ?? []), edge.to])
  const depth = new Map<number, number>()
  if (blocks[0]) depth.set(blocks[0].start, 0)
  const queue = blocks[0] ? [blocks[0].start] : []
  while (queue.length) {
    const current = queue.shift()!
    const nextDepth = (depth.get(current) ?? 0) + 1
    for (const target of adjacency.get(current) ?? []) if (!depth.has(target)) { depth.set(target, nextDepth); queue.push(target) }
  }
  const fallbackDepth = Math.max(0, ...depth.values()) + 1
  for (const block of blocks) if (!depth.has(block.start)) depth.set(block.start, fallbackDepth)
  const rows = new Map<number, number>()
  const positions = new Map<number, { x: number; y: number }>()
  for (const block of blocks) {
    const column = depth.get(block.start) ?? 0
    const row = rows.get(column) ?? 0
    rows.set(column, row + 1)
    positions.set(block.start, { x: 22 + column * (nodeWidth + horizontalGap), y: 22 + row * (nodeHeight + verticalGap) })
  }
  const nodes = blocks.map((block) => ({ block, ...(positions.get(block.start) ?? { x: 22, y: 22 }) }))
  const edges = func.edges.filter((edge) => positions.has(edge.from) && positions.has(edge.to)).map((edge) => {
    const from = positions.get(edge.from)!
    const to = positions.get(edge.to)!
    const x1 = from.x + nodeWidth
    const y1 = from.y + nodeHeight / 2
    const x2 = to.x
    const y2 = to.y + nodeHeight / 2
    const bend = Math.max(40, Math.abs(x2 - x1) / 2)
    return { ...edge, path: `M ${x1} ${y1} C ${x1 + bend} ${y1}, ${x2 - bend} ${y2}, ${x2} ${y2}` }
  })
  const maxColumn = Math.max(0, ...depth.values())
  const maxRows = Math.max(1, ...rows.values())
  return { nodes, edges, nodeWidth, nodeHeight, width: Math.max(760, 44 + (maxColumn + 1) * nodeWidth + maxColumn * horizontalGap), height: Math.max(260, 44 + maxRows * nodeHeight + (maxRows - 1) * verticalGap) }
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
      <div className="yara-toolbar"><strong>{sourceName}</strong><span>{formatBytes(new Blob([source]).size)} / 1 MiB</span><div><button className="button secondary compact" type="button" onClick={() => importRef.current?.click()}>Import</button><button className="button secondary compact" type="button" onClick={exportRules}>Export rules</button><button className="button secondary compact" type="button" onClick={() => onSource(starterRules, 'nope-starter.yar')}>Reset starter pack</button></div></div>
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
