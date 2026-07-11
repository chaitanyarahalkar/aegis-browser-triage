import type { AnalysisReport, ProgressStage, WorkerResponse } from './types'

const ANALYSIS_TIMEOUT_MS = 30_000
const MAX_HEX_READ = 64 * 1024

type PendingAnalysis = {
  resolve: (report: AnalysisReport) => void
  reject: (error: Error) => void
  onProgress: (stage: ProgressStage) => void
  timeout: number
}

type PendingHex = {
  resolve: (value: { offset: number; bytes: Uint8Array }) => void
  reject: (error: Error) => void
}

export class AnalysisClient {
  private worker: Worker | null = null
  private pendingAnalysis = new Map<string, PendingAnalysis>()
  private pendingHex = new Map<string, PendingHex>()

  analyze(file: File, buffer: ArrayBuffer, onProgress: (stage: ProgressStage) => void): Promise<AnalysisReport> {
    this.cancel('Replaced by a new sample')
    const worker = this.ensureWorker()
    const jobId = crypto.randomUUID()
    return new Promise((resolve, reject) => {
      const timeout = window.setTimeout(() => {
        this.failAndReset(new Error('Analysis exceeded the 30 second safety limit'))
      }, ANALYSIS_TIMEOUT_MS)
      this.pendingAnalysis.set(jobId, { resolve, reject, onProgress, timeout })
      worker.postMessage({ type: 'analyze', jobId, name: file.name, buffer, options: '{}' }, [buffer])
    })
  }

  readHex(offset: number, length: number): Promise<{ offset: number; bytes: Uint8Array }> {
    const worker = this.worker
    if (!worker) return Promise.reject(new Error('No sample is open'))
    const requestId = crypto.randomUUID()
    const boundedLength = Math.max(1, Math.min(length, MAX_HEX_READ))
    return new Promise((resolve, reject) => {
      this.pendingHex.set(requestId, { resolve, reject })
      worker.postMessage({ type: 'read-hex', requestId, offset: Math.max(0, offset), length: boundedLength })
    })
  }

  cancel(reason = 'Analysis cancelled'): void {
    if (this.worker || this.pendingAnalysis.size || this.pendingHex.size) {
      this.failAndReset(new Error(reason))
    }
  }

  close(): void {
    if (this.worker) this.worker.postMessage({ type: 'close-sample' })
    this.cancel('Sample closed')
  }

  private ensureWorker(): Worker {
    if (this.worker) return this.worker
    const worker = new Worker(new URL('./analyzer.worker.ts', import.meta.url), { type: 'module', name: 'aegis-analyzer' })
    worker.onmessage = (event: MessageEvent<WorkerResponse>) => this.handleMessage(event.data)
    worker.onerror = () => this.failAndReset(new Error('The isolated analyzer worker crashed'))
    worker.onmessageerror = () => this.failAndReset(new Error('The analyzer returned an unreadable response'))
    this.worker = worker
    return worker
  }

  private handleMessage(message: WorkerResponse): void {
    if (message.type === 'ready') return
    if (message.type === 'progress') {
      this.pendingAnalysis.get(message.jobId)?.onProgress(message.stage)
      return
    }
    if (message.type === 'completed' || message.type === 'failed') {
      const pending = this.pendingAnalysis.get(message.jobId)
      if (!pending) return
      window.clearTimeout(pending.timeout)
      this.pendingAnalysis.delete(message.jobId)
      if (message.type === 'completed') pending.resolve(message.report)
      else pending.reject(new Error(message.message))
      return
    }
    if (message.type === 'hex-slice') {
      const pending = this.pendingHex.get(message.requestId)
      if (!pending) return
      this.pendingHex.delete(message.requestId)
      pending.resolve({ offset: message.offset, bytes: new Uint8Array(message.buffer) })
    }
  }

  private failAndReset(error: Error): void {
    for (const pending of this.pendingAnalysis.values()) {
      window.clearTimeout(pending.timeout)
      pending.reject(error)
    }
    for (const pending of this.pendingHex.values()) pending.reject(error)
    this.pendingAnalysis.clear()
    this.pendingHex.clear()
    this.worker?.terminate()
    this.worker = null
  }
}

