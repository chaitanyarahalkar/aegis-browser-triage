/// <reference lib="webworker" />
import init, { DynamicSession, analyze_dynamic_session } from './generated/analysis-dynamic-wasm/dynamic_analyzer.js'
import type { DynamicWorkerRequest, DynamicWorkerResponse } from './types'

const scope = self as DedicatedWorkerGlobalScope
const engineReady = init()
let session: DynamicSession | null = null

function send(message: DynamicWorkerResponse): void {
  scope.postMessage(message)
}

engineReady.then(() => send({ type: 'ready' })).catch(() => {
  // Initialization failures are reported against the first job.
})

scope.onmessage = async (event: MessageEvent<DynamicWorkerRequest>) => {
  const request = event.data
  if (request.type === 'read-artifact') {
    try {
      if (!session) throw new Error('No dynamic artifact session is active')
      const bytes = session.artifact_bytes(request.artifactId)
      const offset = Math.min(request.offset, bytes.length)
      const limit = request.full ? 4 * 1024 * 1024 : 64 * 1024
      const length = Math.min(request.length, limit, bytes.length - offset)
      const slice = bytes.slice(offset, offset + length).buffer
      scope.postMessage({ type: 'artifact-slice', requestId: request.requestId, artifactId: request.artifactId, offset, total: bytes.length, buffer: slice }, [slice])
    } catch (error) {
      send({ type: 'artifact-failed', requestId: request.requestId, message: error instanceof Error ? error.message : String(error) })
    }
    return
  }
  const { jobId, name, buffer, options } = request
  try {
    send({ type: 'progress', jobId, stage: 'loading-engine' })
    await engineReady
    send({ type: 'progress', jobId, stage: 'loading-image' })
    const started = performance.now()
    send({ type: 'progress', jobId, stage: 'executing' })
    session?.free()
    session = analyze_dynamic_session(name, new Uint8Array(buffer), options)
    const report = JSON.parse(session.report_json())
    report.elapsed_ms = performance.now() - started
    send({ type: 'progress', jobId, stage: 'finalizing' })
    send({ type: 'completed', jobId, report })
  } catch (error) {
    send({ type: 'failed', jobId, message: error instanceof Error ? error.message : String(error) })
  }
}
