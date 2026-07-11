/// <reference lib="webworker" />
import init, { analyze_sample, max_input_bytes } from './generated/analysis-wasm/analyzer.js'
import type { WorkerRequest, WorkerResponse } from './types'

const scope = self as DedicatedWorkerGlobalScope
const engineReady = init()
let currentSample: ArrayBuffer | null = null

function send(message: WorkerResponse, transfer: Transferable[] = []): void {
  scope.postMessage(message, transfer)
}

engineReady.then(() => send({ type: 'ready', maxInputBytes: max_input_bytes() })).catch(() => {
  // The first analysis request reports initialization errors with job context.
})

scope.onmessage = async (event: MessageEvent<WorkerRequest>) => {
  const message = event.data
  if (message.type === 'close-sample') {
    currentSample = null
    return
  }
  if (message.type === 'read-hex') {
    const source = currentSample
    if (!source) {
      send({ type: 'hex-slice', requestId: message.requestId, offset: 0, buffer: new ArrayBuffer(0) })
      return
    }
    const start = Math.min(Math.max(0, message.offset), source.byteLength)
    const end = Math.min(start + Math.min(message.length, 64 * 1024), source.byteLength)
    const slice = source.slice(start, end)
    send({ type: 'hex-slice', requestId: message.requestId, offset: start, buffer: slice }, [slice])
    return
  }

  const { jobId } = message
  try {
    send({ type: 'progress', jobId, stage: 'loading-engine' })
    await engineReady
    if (message.buffer.byteLength > max_input_bytes()) throw new Error('Sample exceeds the 128 MiB hard limit')
    currentSample = message.buffer
    send({ type: 'progress', jobId, stage: 'parsing' })
    const started = performance.now()
    const json = analyze_sample(message.name, new Uint8Array(currentSample), message.options)
    const report = JSON.parse(json)
    report.stats.elapsed_ms = performance.now() - started
    send({ type: 'progress', jobId, stage: 'finalizing' })
    send({ type: 'completed', jobId, report })
  } catch (error) {
    currentSample = null
    const message = error instanceof Error ? error.message : String(error)
    send({ type: 'failed', jobId, message })
  }
}
