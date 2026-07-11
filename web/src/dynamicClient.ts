import type { DynamicProgressStage, DynamicReport, DynamicWorkerResponse } from './types'

const DYNAMIC_TIMEOUT_MS = 10_000

type PendingJob = {
  resolve: (report: DynamicReport) => void
  reject: (error: Error) => void
  onProgress: (stage: DynamicProgressStage) => void
  timeout: number
}

export class DynamicAnalysisClient {
  private worker: Worker | null = null
  private pending = new Map<string, PendingJob>()

  analyze(
    file: File,
    buffer: ArrayBuffer,
    onProgress: (stage: DynamicProgressStage) => void,
  ): Promise<DynamicReport> {
    this.cancel('Replaced by a new dynamic analysis')
    const worker = this.ensureWorker()
    const jobId = crypto.randomUUID()
    return new Promise((resolve, reject) => {
      const timeout = window.setTimeout(() => {
        this.failAndReset(new Error('Dynamic analysis exceeded the 10 second safety limit'))
      }, DYNAMIC_TIMEOUT_MS)
      this.pending.set(jobId, { resolve, reject, onProgress, timeout })
      worker.postMessage({
        type: 'analyze-dynamic',
        jobId,
        name: file.name,
        buffer,
        options: JSON.stringify({ max_instructions: 1_000_000, max_trace_events: 2_000 }),
      }, [buffer])
    })
  }

  cancel(reason = 'Dynamic analysis cancelled'): void {
    if (this.worker || this.pending.size) this.failAndReset(new Error(reason))
  }

  close(): void {
    this.cancel('Dynamic sample closed')
  }

  private ensureWorker(): Worker {
    if (this.worker) return this.worker
    const worker = new Worker(new URL('./dynamic.worker.ts', import.meta.url), {
      type: 'module',
      name: 'aegis-dynamic-analyzer',
    })
    worker.onmessage = (event: MessageEvent<DynamicWorkerResponse>) => this.handleMessage(event.data)
    worker.onerror = () => this.failAndReset(new Error('The dynamic analysis worker crashed'))
    worker.onmessageerror = () => this.failAndReset(new Error('The dynamic worker returned an unreadable response'))
    this.worker = worker
    return worker
  }

  private handleMessage(message: DynamicWorkerResponse): void {
    if (message.type === 'ready') return
    const pending = this.pending.get(message.jobId)
    if (!pending) return
    if (message.type === 'progress') {
      pending.onProgress(message.stage)
      return
    }
    window.clearTimeout(pending.timeout)
    this.pending.delete(message.jobId)
    if (message.type === 'completed') pending.resolve(message.report)
    else pending.reject(new Error(message.message))
  }

  private failAndReset(error: Error): void {
    for (const pending of this.pending.values()) {
      window.clearTimeout(pending.timeout)
      pending.reject(error)
    }
    this.pending.clear()
    this.worker?.terminate()
    this.worker = null
  }
}

