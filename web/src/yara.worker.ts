/// <reference lib="webworker" />
import init, { CompiledYaraRules, compile_yara_rules } from './generated/analysis-yara-wasm/yara_analyzer'
import type { YaraWorkerRequest, YaraWorkerResponse } from './types'

const scope = self as DedicatedWorkerGlobalScope
let initialized: Promise<unknown> | null = null
let compiled: CompiledYaraRules | null = null

function loadEngine() {
  initialized ??= init()
  return initialized
}

function post(message: YaraWorkerResponse) {
  scope.postMessage(message)
}

function messageFrom(error: unknown): string {
  return typeof error === 'string' ? error : error instanceof Error ? error.message : String(error)
}

scope.onmessage = async (event: MessageEvent<YaraWorkerRequest>) => {
  const request = event.data
  if (request.type === 'reset-yara') {
    compiled?.free()
    compiled = null
    return
  }
  try {
    post({ type: 'yara-progress', jobId: request.jobId, stage: 'loading-engine' })
    await loadEngine()
    if (request.type === 'compile-yara') {
      post({ type: 'yara-progress', jobId: request.jobId, stage: 'compiling' })
      const next = compile_yara_rules(request.packName, request.sourceName, request.namespace, request.source)
      compiled?.free()
      compiled = next
      post({ type: 'yara-compiled', jobId: request.jobId, summary: JSON.parse(next.summary_json()) })
      return
    }
    if (!compiled) throw new Error('Compile the rule pack before scanning.')
    post({ type: 'yara-progress', jobId: request.jobId, stage: 'scanning' })
    if (request.type === 'scan-yara-artifacts') {
      const results = request.artifacts.map((artifact) => {
        try {
          return { artifact_id: artifact.id, report: JSON.parse(compiled!.scan(artifact.name, new Uint8Array(artifact.buffer), request.options)), error: null }
        } catch (error) {
          return { artifact_id: artifact.id, report: null, error: messageFrom(error) }
        }
      })
      post({ type: 'yara-artifacts-completed', jobId: request.jobId, results })
      return
    }
    const report = JSON.parse(compiled.scan(request.name, new Uint8Array(request.buffer), request.options))
    post({ type: 'yara-completed', jobId: request.jobId, report })
  } catch (error) {
    post({ type: 'yara-failed', jobId: request.jobId, message: messageFrom(error) })
  }
}
