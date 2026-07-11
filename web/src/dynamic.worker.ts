/// <reference lib="webworker" />
import init, { DynamicSession, analyze_dynamic_session } from './generated/analysis-dynamic-wasm/dynamic_analyzer.js'
import type { DynamicWorkerRequest, DynamicWorkerResponse } from './types'

const scope = self as DedicatedWorkerGlobalScope
const engineReady = init()
const sessions = new Map<string, DynamicSession>()

function clearSessions(): void {
  for (const session of sessions.values()) session.free()
  sessions.clear()
}

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
      const session = sessions.get(request.profileId)
      if (!session) throw new Error(`No dynamic artifact session is active for ${request.profileId}`)
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
  const { jobId, name, buffer } = request
  try {
    send({ type: 'progress', jobId, stage: 'loading-engine' })
    await engineReady
    send({ type: 'progress', jobId, stage: 'loading-image' })
    send({ type: 'progress', jobId, stage: 'executing' })
    clearSessions()
    const optionList = request.type === 'analyze-dynamic-batch' ? request.options : [request.options]
    if (optionList.length === 0 || optionList.length > 4) throw new Error('Profile matrix must contain between one and four profiles')
    const reports = optionList.map((options) => {
      const started = performance.now()
      const session = analyze_dynamic_session(name, new Uint8Array(buffer), options)
      const report = JSON.parse(session.report_json())
      report.elapsed_ms = performance.now() - started
      if (sessions.has(report.profile.environment.id)) { session.free(); throw new Error('Profile matrix IDs must be unique') }
      sessions.set(report.profile.environment.id, session)
      return report
    })
    send({ type: 'progress', jobId, stage: 'finalizing' })
    if (request.type === 'analyze-dynamic-batch') send({ type: 'batch-completed', jobId, reports })
    else send({ type: 'completed', jobId, report: reports[0] })
  } catch (error) {
    clearSessions()
    send({ type: 'failed', jobId, message: error instanceof Error ? error.message : String(error) })
  }
}
