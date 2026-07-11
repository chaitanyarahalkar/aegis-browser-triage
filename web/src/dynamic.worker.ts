/// <reference lib="webworker" />
import init, { analyze_dynamic_sample } from './generated/analysis-dynamic-wasm/dynamic_analyzer.js'
import type { DynamicWorkerRequest, DynamicWorkerResponse } from './types'

const scope = self as DedicatedWorkerGlobalScope
const engineReady = init()

function send(message: DynamicWorkerResponse): void {
  scope.postMessage(message)
}

engineReady.then(() => send({ type: 'ready' })).catch(() => {
  // Initialization failures are reported against the first job.
})

scope.onmessage = async (event: MessageEvent<DynamicWorkerRequest>) => {
  const { jobId, name, buffer, options } = event.data
  try {
    send({ type: 'progress', jobId, stage: 'loading-engine' })
    await engineReady
    send({ type: 'progress', jobId, stage: 'loading-image' })
    const started = performance.now()
    send({ type: 'progress', jobId, stage: 'executing' })
    const json = analyze_dynamic_sample(name, new Uint8Array(buffer), options)
    const report = JSON.parse(json)
    report.elapsed_ms = performance.now() - started
    send({ type: 'progress', jobId, stage: 'finalizing' })
    send({ type: 'completed', jobId, report })
  } catch (error) {
    send({ type: 'failed', jobId, message: error instanceof Error ? error.message : String(error) })
  }
}

