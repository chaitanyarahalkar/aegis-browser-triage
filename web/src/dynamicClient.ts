import type { DynamicEnvironmentProfile, DynamicProgressStage, DynamicReport, DynamicWorkerResponse } from './types'

const DYNAMIC_TIMEOUT_MS = 10_000

type PendingJob = {
  resolve: (report: DynamicReport | DynamicReport[]) => void
  reject: (error: Error) => void
  onProgress: (stage: DynamicProgressStage) => void
  timeout: number
}
type PendingArtifact = { resolve: (value: { bytes: Uint8Array<ArrayBuffer>; total: number }) => void; reject: (error: Error) => void; timeout: number }

export class DynamicAnalysisClient {
  private worker: Worker | null = null
  private pending = new Map<string, PendingJob>()
  private artifactReads = new Map<string, PendingArtifact>()

  analyze(
    file: File,
    buffer: ArrayBuffer,
    onProgress: (stage: DynamicProgressStage) => void,
    environment?: DynamicEnvironmentProfile,
  ): Promise<DynamicReport> {
    this.cancel('Replaced by a new dynamic analysis')
    const worker = this.ensureWorker()
    const jobId = crypto.randomUUID()
    return new Promise((resolve, reject) => {
      const timeout = window.setTimeout(() => {
        this.failAndReset(new Error('Dynamic analysis exceeded the 10 second safety limit'))
      }, DYNAMIC_TIMEOUT_MS)
      this.pending.set(jobId, { resolve: resolve as PendingJob['resolve'], reject, onProgress, timeout })
      worker.postMessage({
        type: 'analyze-dynamic',
        jobId,
        name: file.name,
        buffer,
        options: JSON.stringify({ max_instructions: 1_000_000, max_trace_events: 2_000, environment }),
      }, [buffer])
    })
  }

  analyzeProfiles(file: File, buffer: ArrayBuffer, environments: DynamicEnvironmentProfile[], onProgress: (stage: DynamicProgressStage) => void): Promise<DynamicReport[]> {
    this.cancel('Replaced by a profile matrix analysis')
    const worker = this.ensureWorker()
    const jobId = crypto.randomUUID()
    return new Promise((resolve, reject) => {
      const timeout = window.setTimeout(() => this.failAndReset(new Error('Profile matrix analysis exceeded the 40 second safety limit')), 40_000)
      this.pending.set(jobId, { resolve: resolve as PendingJob['resolve'], reject, onProgress, timeout })
      worker.postMessage({ type: 'analyze-dynamic-batch', jobId, name: file.name, buffer, options: environments.map((environment) => JSON.stringify({ max_instructions: 1_000_000, max_trace_events: 2_000, environment })) }, [buffer])
    })
  }

  cancel(reason = 'Dynamic analysis cancelled'): void {
    if (this.worker || this.pending.size) this.failAndReset(new Error(reason))
  }

  close(): void {
    this.cancel('Dynamic sample closed')
  }

  readArtifactSlice(profileId: string, artifactId: string, offset = 0, length = 64 * 1024): Promise<{ bytes: Uint8Array<ArrayBuffer>; total: number }> {
    return this.requestArtifact(profileId, artifactId, offset, Math.min(length, 64 * 1024), false)
  }

  readArtifact(profileId: string, artifactId: string): Promise<{ bytes: Uint8Array<ArrayBuffer>; total: number }> {
    return this.requestArtifact(profileId, artifactId, 0, 4 * 1024 * 1024, true)
  }

  private requestArtifact(profileId: string, artifactId: string, offset: number, length: number, full: boolean): Promise<{ bytes: Uint8Array<ArrayBuffer>; total: number }> {
    const worker = this.ensureWorker()
    const requestId = crypto.randomUUID()
    return new Promise((resolve, reject) => {
      const timeout = window.setTimeout(() => { this.artifactReads.delete(requestId); reject(new Error('Artifact read timed out')) }, 5_000)
      this.artifactReads.set(requestId, { resolve, reject, timeout })
      worker.postMessage({ type: 'read-artifact', requestId, profileId, artifactId, offset, length, full })
    })
  }

  private ensureWorker(): Worker {
    if (this.worker) return this.worker
    const worker = new Worker(new URL('./dynamic.worker.ts', import.meta.url), {
      type: 'module',
      name: 'nope-dynamic-analyzer',
    })
    worker.onmessage = (event: MessageEvent<DynamicWorkerResponse>) => this.handleMessage(event.data)
    worker.onerror = () => this.failAndReset(new Error('The dynamic analysis worker crashed'))
    worker.onmessageerror = () => this.failAndReset(new Error('The dynamic worker returned an unreadable response'))
    this.worker = worker
    return worker
  }

  private handleMessage(message: DynamicWorkerResponse): void {
    if (message.type === 'ready') return
    if (message.type === 'artifact-slice' || message.type === 'artifact-failed') {
      const pending = this.artifactReads.get(message.requestId)
      if (!pending) return
      window.clearTimeout(pending.timeout)
      this.artifactReads.delete(message.requestId)
      if (message.type === 'artifact-slice') pending.resolve({ bytes: new Uint8Array(message.buffer), total: message.total })
      else pending.reject(new Error(message.message))
      return
    }
    const pending = this.pending.get(message.jobId)
    if (!pending) return
    if (message.type === 'progress') {
      pending.onProgress(message.stage)
      return
    }
    window.clearTimeout(pending.timeout)
    this.pending.delete(message.jobId)
    if (message.type === 'completed') pending.resolve(message.report)
    else if (message.type === 'batch-completed') pending.resolve(message.reports)
    else pending.reject(new Error(message.message))
  }

  private failAndReset(error: Error): void {
    for (const pending of this.pending.values()) {
      window.clearTimeout(pending.timeout)
      pending.reject(error)
    }
    this.pending.clear()
    for (const pending of this.artifactReads.values()) { window.clearTimeout(pending.timeout); pending.reject(error) }
    this.artifactReads.clear()
    this.worker?.terminate()
    this.worker = null
  }
}
