import type { ArtifactYaraResult, YaraCompileSummary, YaraProgressStage, YaraReport, YaraWorkerResponse } from './types'

const COMPILE_TIMEOUT_MS = 5_000
const SCAN_TIMEOUT_MS = 10_000
type YaraResult = YaraCompileSummary | YaraReport | ArtifactYaraResult[]
type Pending = { resolve: (value: YaraResult) => void; reject: (error: Error) => void; onProgress: (stage: YaraProgressStage) => void; timeout: number }

export class YaraClient {
  private worker: Worker | null = null
  private pending = new Map<string, Pending>()

  compile(source: string, sourceName: string, packName: string, onProgress: (stage: YaraProgressStage) => void): Promise<YaraCompileSummary> {
    return this.request<YaraCompileSummary>('compile', COMPILE_TIMEOUT_MS, onProgress, (worker, jobId) => worker.postMessage({ type: 'compile-yara', jobId, source, sourceName, packName, namespace: 'analyst' }))
  }

  scan(file: File, buffer: ArrayBuffer, onProgress: (stage: YaraProgressStage) => void): Promise<YaraReport> {
    return this.request<YaraReport>('scan', SCAN_TIMEOUT_MS, onProgress, (worker, jobId) => worker.postMessage({ type: 'scan-yara', jobId, name: file.name, buffer, options: JSON.stringify({ max_matches_per_pattern: 100, max_reported_matches: 10_000 }) }, [buffer]))
  }

  scanArtifacts(artifacts: Array<{ id: string; name: string; buffer: ArrayBuffer }>, onProgress: (stage: YaraProgressStage) => void): Promise<ArtifactYaraResult[]> {
    const total = artifacts.reduce((sum, artifact) => sum + artifact.buffer.byteLength, 0)
    if (artifacts.length > 128 || total > 32 * 1024 * 1024) return Promise.reject(new Error('Artifact YARA batch exceeds the safety limit'))
    return this.request<ArtifactYaraResult[]>('artifact scan', 15_000, onProgress, (worker, jobId) => worker.postMessage({ type: 'scan-yara-artifacts', jobId, artifacts, options: JSON.stringify({ max_matches_per_pattern: 100, max_reported_matches: 10_000 }) }, artifacts.map((artifact) => artifact.buffer)))
  }

  reset(): void { if (this.worker) this.worker.postMessage({ type: 'reset-yara' }) }
  close(): void { this.failAndReset(new Error('YARA session closed')) }

  private request<T extends YaraResult>(label: string, limit: number, onProgress: (stage: YaraProgressStage) => void, send: (worker: Worker, jobId: string) => void): Promise<T> {
    if (this.pending.size) this.failAndReset(new Error('Replaced by a new YARA operation'))
    const worker = this.ensureWorker()
    const jobId = crypto.randomUUID()
    return new Promise((resolve, reject) => {
      const timeout = window.setTimeout(() => this.failAndReset(new Error(`YARA ${label} exceeded the ${limit / 1000} second safety limit`)), limit)
      this.pending.set(jobId, { resolve: resolve as Pending['resolve'], reject, onProgress, timeout })
      send(worker, jobId)
    })
  }

  private ensureWorker(): Worker {
    if (this.worker) return this.worker
    const worker = new Worker(new URL('./yara.worker.ts', import.meta.url), { type: 'module', name: 'aegis-yara-analyzer' })
    worker.onmessage = (event: MessageEvent<YaraWorkerResponse>) => this.handle(event.data)
    worker.onerror = () => this.failAndReset(new Error('The isolated YARA worker crashed'))
    worker.onmessageerror = () => this.failAndReset(new Error('The YARA worker returned an unreadable response'))
    this.worker = worker
    return worker
  }

  private handle(message: YaraWorkerResponse) {
    const pending = this.pending.get(message.jobId)
    if (!pending) return
    if (message.type === 'yara-progress') { pending.onProgress(message.stage); return }
    window.clearTimeout(pending.timeout)
    this.pending.delete(message.jobId)
    if (message.type === 'yara-compiled') pending.resolve(message.summary)
    else if (message.type === 'yara-completed') pending.resolve(message.report)
    else if (message.type === 'yara-artifacts-completed') pending.resolve(message.results)
    else pending.reject(new Error(message.message))
  }

  private failAndReset(error: Error) {
    for (const pending of this.pending.values()) { window.clearTimeout(pending.timeout); pending.reject(error) }
    this.pending.clear()
    this.worker?.terminate()
    this.worker = null
  }
}
