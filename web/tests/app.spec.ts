import { expect, test } from '@playwright/test'
import { readFileSync } from 'node:fs'

const safePe = readFileSync(new URL('../public/fixtures/aegis-safe-dynamic-pe32.exe', import.meta.url))
const safeMacos = readFileSync(new URL('../../fixtures/aegis-safe-sample-macos', import.meta.url))

async function loadSafeDemo(page: import('@playwright/test').Page) {
  await page.goto('/')
  await page.getByRole('button', { name: 'Use safe PE demo' }).click()
  await expect(page.getByText('aegis-safe-dynamic-pe32.exe')).toBeVisible()
  await expect(page.locator('.sample-title')).toContainText('PE · 32-bit X86')
}

async function loadCodeDemo(page: import('@playwright/test').Page) {
  await page.goto('/')
  await page.getByRole('button', { name: 'Use code analysis demo' }).click()
  await expect(page.getByText('aegis-safe-code-analysis-pe64.exe')).toBeVisible()
  await expect(page.locator('.sample-title')).toContainText('PE · 64-bit X86_64')
}

async function runDynamic(page: import('@playwright/test').Page) {
  await page.getByRole('tab', { name: /^Dynamic/ }).click()
  await page.getByRole('button', { name: 'Run selected profile' }).click()
  await expect(page.getByText('Exit 0', { exact: true })).toBeVisible()
}

async function runYara(page: import('@playwright/test').Page) {
  await page.getByRole('tab', { name: /^YARA/ }).click()
  await page.getByRole('button', { name: 'Compile & scan' }).click()
  await expect(page.getByText('NOPE_Safe_Demo', { exact: true })).toBeVisible()
}

test('runs the safe PE through static and dynamic Rust workers', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Look before you launch.' })).toBeVisible()
  await expect(page.getByText('No uploads', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Use safe PE demo' }).click()

  await expect(page.getByText('aegis-safe-dynamic-pe32.exe')).toBeVisible()
  await expect(page.locator('.sample-title')).toContainText('PE · 32-bit X86')
  await expect(page.getByRole('heading', { name: 'Findings' })).toBeVisible()

  await runDynamic(page)
  await expect(page.getByText('Process execution requested')).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Execution timeline' })).toBeVisible()
  await expect(page.getByRole('cell', { name: 'WinExec', exact: true })).toBeVisible()
  await expect(page.getByRole('cell', { name: 'process', exact: true })).toBeVisible()
  await page.getByRole('button', { name: /^Behavior/ }).click()
  await expect(page.getByRole('cell', { name: 'powershell.exe -NoProfile https://example.test 10.20.30.40', exact: true })).toBeVisible()
  await expect(page.getByText('Captured only; no host process created')).toBeVisible()
  await expect(page.getByText('No guest operation left the browser.')).toBeVisible()

  await page.getByRole('button', { name: /^API calls/ }).click()
  for (const api of ['GetTickCount', 'Sleep', 'WinExec', 'ExitProcess']) {
    await expect(page.getByText(`KERNEL32.dll!${api}`, { exact: true })).toBeVisible()
  }
  await page.getByRole('button', { name: /^Instructions/ }).click()
  await expect(page.locator('tbody')).toContainText('call dword ptr')
  await page.getByRole('button', { name: 'Coverage' }).click()
  await expect(page.getByText('100.0%', { exact: true })).toBeVisible()
  await expect(page.getByText('Dynamic v14', { exact: true })).toBeVisible()
})

test('explores static capabilities, disassembly, and control flow', async ({ page, isMobile }) => {
  await loadCodeDemo(page)
  await page.getByRole('tab', { name: /^Code/ }).click()
  await expect(page.getByRole('heading', { name: 'Static code analysis' })).toBeVisible()
  await expect(page.getByText('Execute a process or command', { exact: true })).toBeVisible()
  await expect(page.getByText('Communicate over a network', { exact: true })).toBeVisible()
  await expect(page.getByText('high confidence', { exact: true })).toBeVisible()
  if (isMobile) {
    await expect(page.getByText('4 CFG edges', { exact: true })).toBeVisible()
    return
  }

  await page.getByRole('button', { name: /^Disassembly/ }).click()
  await expect(page.getByLabel('Static function')).toHaveValue('4096')
  await expect(page.getByRole('cell', { name: /call /i }).first()).toBeVisible()
  await expect(page.locator('.block-row').first()).toContainText('Basic block')

  await page.getByRole('button', { name: /^Control flow/ }).click()
  await expect(page.locator('.cfg-graph')).toBeVisible()
  await expect(page.locator('.cfg-node').first()).toBeVisible()
  await expect(page.locator('.cfg-edge')).toHaveCount(4)
  await expect(page.getByText(/Selected block 0x/)).toBeVisible()

  const downloadPromise = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Export report' }).click()
  const download = await downloadPromise
  const json = JSON.parse(readFileSync(await download.path()!, 'utf8'))
  expect(json.static.schema_version).toBe(2)
  expect(json.static.code.disassembly_supported).toBe(true)
  expect(json.static.code.functions.length).toBeGreaterThan(0)
  expect(json.static.code.capabilities.some((item: { id: string }) => item.id === 'process-execution')).toBe(true)
})

test('runs a PE64 image through the x86-64 interpreter and ABI', async ({ page, isMobile }) => {
  test.skip(isMobile, 'desktop x64 inspection workflow')
  await page.goto('/')
  await page.getByRole('button', { name: 'Use safe PE64 demo' }).click()
  await expect(page.getByText('aegis-safe-dynamic-pe64.exe')).toBeVisible()
  await expect(page.locator('.sample-title')).toContainText('PE · 64-bit X86_64')
  await runDynamic(page)
  await expect(page.getByText('Process execution requested')).toBeVisible()
  await page.getByRole('button', { name: /^API calls/ }).click()
  for (const api of ['GetTickCount', 'Sleep', 'WinExec', 'ExitProcess']) {
    await expect(page.getByText(`KERNEL32.dll!${api}`, { exact: true })).toBeVisible()
  }
  await page.getByRole('button', { name: 'Unwind (1)' }).click()
  await expect(page.getByRole('heading', { name: 'PE64 unwind metadata' })).toBeVisible()
  await expect(page.getByRole('cell', { name: '0x0000000140001000' })).toBeVisible()
  await page.getByRole('button', { name: /^Instructions/ }).click()
  await expect(page.locator('tbody')).toContainText('sub rsp,28h')
  await expect(page.locator('tbody')).toContainText('lea rcx')
  const downloadPromise = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Export report' }).click()
  const download = await downloadPromise
  const json = JSON.parse(readFileSync(await download.path()!, 'utf8'))
  expect(json.dynamic.schema_version).toBe(14)
  expect(json.dynamic.profile.architecture).toBe('x86-64 (64-bit)')
  expect(json.dynamic.profile.image_base).toBe(0x140000000)
  expect(json.dynamic.unwind_functions).toHaveLength(1)
})

test('shows PE64 parity artifacts, state, provenance, threads, and exceptions', async ({ page, isMobile }) => {
  test.skip(isMobile, 'desktop x64 parity workflow')
  await page.goto('/')
  await page.getByRole('button', { name: 'Use PE64 parity demo' }).click()
  await expect(page.getByText('aegis-safe-parity-pe64.exe')).toBeVisible()
  await expect(page.locator('.sample-title')).toContainText('PE · 64-bit X86_64')
  await runDynamic(page)

  await page.getByRole('button', { name: /^Artifacts \([1-9]/ }).click()
  await expect(page.getByRole('heading', { name: 'Captured artifacts' })).toBeVisible()
  await expect(page.getByText('virtual_file', { exact: true })).toBeVisible()
  await expect(page.getByText('network_download', { exact: true })).toBeVisible()

  await page.getByRole('button', { name: /^Unpacking \([1-9]/ }).click()
  await expect(page.getByRole('heading', { name: 'Payload lineage' })).toBeVisible()
  await page.getByRole('button', { name: /^Provenance \([1-9]/ }).click()
  await expect(page.getByRole('heading', { name: 'Explainable data flows' })).toBeVisible()
  await expect(page.getByText(/network → process command/)).toBeVisible()

  await page.getByRole('button', { name: 'Threads (2)' }).click()
  await expect(page.getByRole('heading', { name: 'Guest thread states' })).toBeVisible()
  await expect(page.getByRole('cell', { name: 'scheduled', exact: true })).toBeVisible()
  await page.getByRole('button', { name: /^Exceptions \([1-9]/ }).click()
  await expect(page.getByRole('heading', { name: 'Structured exception handling' })).toBeVisible()
  await expect(page.getByText('Continue execution', { exact: true })).toBeVisible()

  const downloadPromise = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Export report' }).click()
  const download = await downloadPromise
  const dynamic = JSON.parse(readFileSync(await download.path()!, 'utf8')).dynamic
  expect(dynamic.profile.architecture).toBe('x86-64 (64-bit)')
  expect(dynamic.filesystem.some((event: { operation: string }) => event.operation === 'write')).toBe(true)
  expect(dynamic.registry.some((event: { operation: string }) => event.operation === 'set')).toBe(true)
  expect(dynamic.network.some((event: { operation: string }) => event.operation === 'read')).toBe(true)
  expect(dynamic.artifacts.length).toBeGreaterThanOrEqual(3)
  expect(dynamic.payload_generations.length).toBeGreaterThan(0)
  expect(dynamic.provenance_flows.length).toBeGreaterThanOrEqual(2)
  expect(dynamic.thread_events.some((event: { operation: string }) => event.operation === 'scheduled')).toBe(true)
  expect(dynamic.exceptions[0].outcome).toBe('continued_execution')
  expect(dynamic.system.some((event: { operation: string }) => event.operation === 'runtime_function_lookup')).toBe(true)
})

test('identifies a generated PE64 entry candidate and reconstructs runtime imports', async ({ page, isMobile }) => {
  test.skip(isMobile, 'desktop x64 unpacking workflow')
  await page.goto('/')
  await page.getByRole('button', { name: 'Use PE64 unpacking demo' }).click()
  await expect(page.getByText('aegis-safe-unpacking-pe64.exe')).toBeVisible()
  await runDynamic(page)
  await expect(page.getByText('Generated payload entry point identified', { exact: true })).toBeVisible()
  await expect(page.getByText('Runtime imports reconstructed', { exact: true })).toBeVisible()

  await page.getByRole('button', { name: /^Unpacking \([1-9]/ }).click()
  await expect(page.getByRole('heading', { name: 'Payload lineage' })).toBeVisible()
  await expect(page.getByText('0x0000005000000020', { exact: true })).toBeVisible()
  await expect(page.getByRole('cell', { name: 'KERNEL32.dll!GetTickCount', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Coverage' }).click()
  await expect(page.getByText('2 dynamically resolved', { exact: true })).toBeVisible()

  const downloadPromise = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Export report' }).click()
  const download = await downloadPromise
  const dynamic = JSON.parse(readFileSync(await download.path()!, 'utf8')).dynamic
  expect(dynamic.schema_version).toBe(14)
  expect(dynamic.coverage.dynamic_api_resolutions).toBe(2)
  expect(dynamic.generation_stats.entry_point_candidates).toBeGreaterThanOrEqual(1)
  expect(dynamic.generation_stats.reconstructed_imports).toBe(1)
  const generation = dynamic.payload_generations.find((item: { entry_point_candidate: number | null }) => item.entry_point_candidate != null)
  expect(generation.entry_point_candidate).toBe(0x5000000020)
  expect(generation.reconstructed_imports).toEqual(['KERNEL32.dll!GetTickCount'])
})

test('runs and compares deterministic environment profiles', async ({ page, isMobile }) => {
  test.skip(isMobile, 'desktop profile comparison workflow')
  await loadSafeDemo(page)
  await page.getByRole('tab', { name: /^Dynamic/ }).click()
  await expect(page.getByLabel('Environment profile')).toHaveValue('balanced')
  await page.getByRole('button', { name: 'Compare all profiles' }).click()
  await expect(page.getByRole('button', { name: 'Profile comparison (4)' })).toBeVisible()
  await page.getByRole('button', { name: 'Profile comparison (4)' }).click()
  for (const profile of ['Balanced workstation', 'Legacy workstation', 'Hardened offline host', 'Instrumented analysis host']) {
    await expect(page.getByRole('button', { name: profile, exact: true })).toBeVisible()
  }
  await expect(page.getByRole('heading', { name: 'Detailed run diff' })).toBeVisible()
  await expect(page.getByText('api:GetTickCount', { exact: true }).first()).toBeVisible()
  const diffDownloadPromise = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Export run diff JSON' }).click()
  const diffDownload = await diffDownloadPromise
  const diff = JSON.parse(readFileSync(await diffDownload.path()!, 'utf8'))
  expect(diff.schema).toBe('aegis-run-diff-v1')
  expect(diff.different).toBe(true)
  expect(diff.first_divergence.trigger).toBe('api:GetTickCount')
  await page.getByRole('button', { name: 'Hardened offline host', exact: true }).click()
  await expect(page.getByText('Windows 11 24H2 · offline', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: /^Snapshots/ }).click()
  await expect(page.getByRole('heading', { name: 'Execution state snapshots' })).toBeVisible()
  await expect(page.getByRole('cell', { name: 'entry', exact: true })).toBeVisible()
  await expect(page.getByRole('cell', { name: 'final', exact: true })).toBeVisible()

  const downloadPromise = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Export report' }).click()
  const download = await downloadPromise
  const json = JSON.parse(readFileSync(await download.path()!, 'utf8'))
  expect(json.dynamic.profile.environment.id).toBe('hardened')
  expect(json.dynamic_profiles).toHaveLength(4)
  expect(json.dynamic_profiles.map((report: { profile: { environment: { id: string } } }) => report.profile.environment.id)).toEqual(['balanced', 'legacy', 'hardened', 'analysis'])
})

test('bounds an infinite loop by instruction count', async ({ page, isMobile }) => {
  test.skip(isMobile, 'covered by desktop hostile-fixture suite')
  const loop = Buffer.from(safePe)
  loop.set([0xeb, 0xfe], 0x200)
  await page.goto('/')
  await page.getByTestId('file-input').setInputFiles({ name: 'bounded-loop.exe', mimeType: 'application/octet-stream', buffer: loop })
  await expect(page.getByText('bounded-loop.exe')).toBeVisible()
  await page.getByRole('tab', { name: /^Dynamic/ }).click()
  await page.getByRole('button', { name: 'Run selected profile' }).click()
  await expect(page.getByText('Limit reached', { exact: true })).toBeVisible()
  await expect(page.getByText('1,000,000', { exact: true })).toBeVisible()
})

test('turns invalid guest memory access into a reportable fault', async ({ page, isMobile }) => {
  test.skip(isMobile, 'covered by desktop hostile-fixture suite')
  const fault = Buffer.from(safePe)
  fault.set([0xa1, 0x00, 0x00, 0x00, 0x00], 0x200)
  await page.goto('/')
  await page.getByTestId('file-input').setInputFiles({ name: 'memory-fault.exe', mimeType: 'application/octet-stream', buffer: fault })
  await expect(page.getByText('memory-fault.exe')).toBeVisible()
  await page.getByRole('tab', { name: /^Dynamic/ }).click()
  await page.getByRole('button', { name: 'Run selected profile' }).click()
  await expect(page.getByText('Memory fault', { exact: true })).toBeVisible()
})

test('handles unsupported and malformed binaries safely', async ({ page }) => {
  await page.goto('/')
  const input = page.getByTestId('file-input')
  await input.setInputFiles({ name: 'unknown.bin', mimeType: 'application/octet-stream', buffer: Buffer.from('plain inert content') })
  await expect(page.getByText('unknown.bin')).toBeVisible()
  await page.getByRole('tab', { name: /^Dynamic/ }).click()
  await expect(page.getByText('Dynamic analysis is not available for this file')).toBeVisible()
  await page.getByRole('button', { name: 'Close' }).click()

  await input.setInputFiles({ name: 'broken.exe', mimeType: 'application/octet-stream', buffer: Buffer.from([0x4d, 0x5a, 0, 0]) })
  await expect(page.getByRole('alert')).toContainText('Analysis stopped')
  await expect(page.getByRole('alert')).toContainText('failed to parse PE')
})

test('analyzes the supplied ARM64 macOS fixture without crashing the worker', async ({ page }) => {
  const workerRequests: string[] = []
  page.on('request', (request) => {
    if (request.url().includes('.worker')) workerRequests.push(request.url())
  })
  await page.goto('/')
  await page.getByTestId('file-input').setInputFiles({
    name: 'aegis-safe-sample-macos',
    mimeType: 'application/octet-stream',
    buffer: safeMacos,
  })

  await expect(page.getByText('aegis-safe-sample-macos')).toBeVisible()
  await expect(page.locator('.sample-title')).toContainText('Mach-O · 64-bit ARM64')
  await expect(page.getByRole('heading', { name: 'Findings' })).toBeVisible()
  expect(workerRequests.some((url) => url.endsWith('/assets/analyzer.worker.js'))).toBe(true)
})

test('compiles starter YARA rules, links matches to hex, and exports the combined report', async ({ page }) => {
  await loadSafeDemo(page)
  await runDynamic(page)
  await runYara(page)
  await expect(page.getByText('Identifies the first-party NOPE safe test fixture', { exact: true })).toBeVisible()
  await page.locator('.offset-link').first().click()
  await expect(page.getByRole('heading', { name: 'Hex view' })).toBeVisible()
  const downloadPromise = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Export report' }).click()
  const download = await downloadPromise
  expect(download.suggestedFilename()).toBe('aegis-safe-dynamic-pe32.exe.nope-report.json')
  const json = JSON.parse(readFileSync(await download.path()!, 'utf8'))
  expect(json.static.sample.detected_format).toBe('pe')
  expect(json.dynamic.termination).toEqual({ reason: 'exit_process', code: 0 })
  expect(json.dynamic.schema_version).toBe(14)
  expect(json.dynamic.timeline).toHaveLength(4)
  expect(json.dynamic.coverage.modeled_api_calls).toBe(4)
  expect(json.dynamic.processes[0].command).toContain('powershell.exe')
  expect(json.yara.matches[0].identifier).toBe('NOPE_Safe_Demo')
  expect(JSON.stringify(json.yara)).not.toContain('powershell.exe -NoProfile https://example.test 10.20.30.40')
})

test('shows structured YARA diagnostics without taking down static analysis', async ({ page, isMobile }) => {
  test.skip(isMobile, 'covered by desktop rule-editor suite')
  await loadSafeDemo(page)
  await page.getByRole('tab', { name: /^YARA/ }).click()
  await page.getByLabel('YARA rule source').fill('rule broken {')
  await page.getByRole('button', { name: 'Compile & scan' }).click()
  await expect(page.getByRole('alert')).toContainText('YARA operation stopped')
  await expect(page.getByRole('alert')).toContainText('syntax error')
  await page.getByRole('tab', { name: /^Summary/ }).click()
  await expect(page.getByRole('heading', { name: 'Findings' })).toBeVisible()
})

test('captures runtime artifacts, scans them with YARA, and gates raw export', async ({ page, isMobile }) => {
  test.skip(isMobile, 'desktop artifact inspection workflow')
  await page.goto('/')
  await page.getByRole('button', { name: 'Use runtime artifact demo' }).click()
  await expect(page.getByText('aegis-safe-runtime-artifact-pe32.exe')).toBeVisible()
  await runDynamic(page)
  await page.getByRole('button', { name: /^Unpacking \([2-9]/ }).click()
  await expect(page.getByRole('heading', { name: 'Payload lineage' })).toBeVisible()
  await expect(page.getByText('executed', { exact: true }).first()).toBeVisible()
  await expect(page.getByText('Root', { exact: true }).first()).toBeVisible()
  await page.getByRole('button', { name: 'Scan generations with YARA' }).click()
  await expect(page.getByText('NOPE_Safe_Runtime_Artifact', { exact: true }).first()).toBeVisible()
  await page.getByRole('button', { name: /^Artifacts/ }).click()
  await expect(page.locator('.artifact-strings')).toContainText('AEGIS_SAFE_RUNTIME_ARTIFACT')
  await expect(page.getByText('NOPE_Safe_Runtime_Artifact', { exact: true }).first()).toBeVisible()

  await page.getByRole('button', { name: 'Export raw bytes' }).click()
  const dialog = page.getByRole('dialog', { name: 'Export potentially malicious bytes?' })
  await expect(dialog).toBeVisible()
  const downloadPromise = page.waitForEvent('download')
  await dialog.getByRole('button', { name: 'Export raw bytes' }).click()
  const download = await downloadPromise
  expect(download.suggestedFilename()).toMatch(/\.bin$/)
  const bytes = readFileSync(await download.path()!)
  expect(bytes.subarray(0, 2).toString()).toBe('MZ')

  const reportPromise = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Export report' }).click()
  const reportDownload = await reportPromise
  const json = JSON.parse(readFileSync(await reportDownload.path()!, 'utf8'))
  expect(json.dynamic.artifacts.length).toBeGreaterThanOrEqual(2)
  expect(json.dynamic.payload_generations.length).toBeGreaterThanOrEqual(2)
  expect(json.dynamic.payload_generations.some((generation: { parent_id: string | null; executed: boolean }) => generation.parent_id && generation.executed)).toBe(true)
  expect(json.dynamic.artifact_yara.some((result: { report?: { matches: Array<{ identifier: string }> } }) => result.report?.matches.some((match) => match.identifier === 'NOPE_Safe_Runtime_Artifact'))).toBe(true)
  expect(json.dynamic.artifacts.every((artifact: Record<string, unknown>) => !('bytes' in artifact) && !('data' in artifact))).toBe(true)
})

test('dispatches a breakpoint through bounded guest SEH', async ({ page, isMobile }) => {
  test.skip(isMobile, 'desktop exception inspection workflow')
  await page.goto('/')
  await page.getByRole('button', { name: 'Use SEH demo' }).click()
  await expect(page.getByText('aegis-safe-seh-pe32.exe')).toBeVisible()
  await runDynamic(page)
  await page.getByRole('button', { name: 'Exceptions (1)' }).click()
  await expect(page.getByRole('heading', { name: 'Structured exception handling', exact: true })).toBeVisible()
  await expect(page.getByText('breakpoint', { exact: true })).toBeVisible()
  await expect(page.getByText('Continue execution', { exact: true })).toBeVisible()
  await expect(page.getByText('continued execution', { exact: true })).toBeVisible()
})

test('schedules a bounded guest thread with isolated state', async ({ page, isMobile }) => {
  test.skip(isMobile, 'desktop thread inspection workflow')
  await page.goto('/')
  await page.getByRole('button', { name: 'Use threads demo' }).click()
  await expect(page.getByText('aegis-safe-threads-pe32.exe')).toBeVisible()
  await runDynamic(page)
  await page.getByRole('button', { name: 'Threads (2)' }).click()
  await expect(page.getByRole('heading', { name: 'Guest thread states' })).toBeVisible()
  await expect(page.getByRole('cell', { name: '42', exact: true })).toBeVisible()
  await expect(page.getByRole('cell', { name: 'scheduled', exact: true })).toBeVisible()
  await expect(page.getByText('100-instruction quantum', { exact: true })).toBeVisible()
})

test('executes extended integer, SSE2, and x87 instructions', async ({ page, isMobile }) => {
  test.skip(isMobile, 'desktop instruction coverage workflow')
  await page.goto('/')
  await page.getByRole('button', { name: 'Use instruction demo' }).click()
  await expect(page.getByText('aegis-safe-instructions-pe32.exe')).toBeVisible()
  await runDynamic(page)
  await page.getByRole('button', { name: /^Instructions/ }).click()
  await expect(page.locator('tbody')).toContainText('addss xmm0,xmm1')
  await expect(page.locator('tbody')).toContainText('faddp')
  await page.getByRole('button', { name: 'Coverage' }).click()
  await expect(page.getByText('Invalid encodings').locator('..')).toContainText('0')
})

test('models bounded synthetic Windows system objects', async ({ page, isMobile }) => {
  test.skip(isMobile, 'desktop system-object inspection workflow')
  await page.goto('/')
  await page.getByRole('button', { name: 'Use system-object demo' }).click()
  await expect(page.getByText('aegis-safe-system-objects-pe32.exe')).toBeVisible()
  await runDynamic(page)
  await page.getByRole('button', { name: 'System objects (4)' }).click()
  await expect(page.getByRole('heading', { name: 'Synthetic Windows system objects' })).toBeVisible()
  await expect(page.getByRole('cell', { name: 'create event' })).toBeVisible()
  await expect(page.getByRole('cell', { name: 'timeout or invalid' })).toBeVisible()
  await expect(page.getByRole('cell', { name: 'signaled', exact: true }).last()).toBeVisible()
})

test('follows scripted network redirects and captures a download artifact', async ({ page, isMobile }) => {
  test.skip(isMobile, 'desktop network inspection workflow')
  await page.goto('/')
  await page.getByRole('button', { name: 'Use network demo' }).click()
  await expect(page.getByText('aegis-safe-network-pe32.exe')).toBeVisible()
  await runDynamic(page)
  await page.getByRole('button', { name: 'Network (2)' }).click()
  await expect(page.getByRole('heading', { name: 'Scripted network exchanges' })).toBeVisible()
  await expect(page.getByRole('cell', { name: '302', exact: true })).toBeVisible()
  await expect(page.getByRole('cell', { name: 'redirect hop 1' })).toBeVisible()
  const downloadPromise = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Export synthetic PCAP JSON' }).click()
  const download = await downloadPromise
  const pcap = JSON.parse(readFileSync(await download.path()!, 'utf8'))
  expect(pcap.schema).toBe('aegis-synthetic-pcap-v1')
  expect(pcap.exchanges).toHaveLength(2)
  expect(pcap.exchanges[1].response_size).toBe(31)
  expect(pcap.exchanges[1].response_sha256).toMatch(/^[0-9a-f]{64}$/)
  expect(JSON.stringify(pcap)).not.toContain('AEGIS_SAFE_NETWORK_DOWNLOAD')
  await page.getByRole('button', { name: /^Provenance/ }).click()
  await expect(page.getByRole('heading', { name: 'Explainable data flows' })).toBeVisible()
  await expect(page.getByText('network → process command', { exact: true })).toBeVisible()
  await expect(page.getByRole('cell', { name: 'InternetReadFile' })).toBeVisible()
  await expect(page.getByRole('cell', { name: 'WinExec' })).toBeVisible()
  await page.getByRole('button', { name: /^Artifacts/ }).click()
  await expect(page.getByRole('cell', { name: 'network_download' })).toBeVisible()
  await page.getByRole('button', { name: 'Scan artifacts with YARA' }).click()
  await expect(page.getByText('NOPE_Safe_Network_Download', { exact: true }).first()).toBeVisible()
})

test('does not contact third parties or persist sample data', async ({ page }) => {
  const externalRequests: string[] = []
  page.on('request', (request) => {
    const url = new URL(request.url())
    if (url.origin !== 'http://127.0.0.1:4173') externalRequests.push(request.url())
  })
  const response = await page.goto('/')
  const headers = response?.headers() ?? {}
  expect(headers['content-security-policy']).toContain("object-src 'none'")
  expect(headers['content-security-policy']).toContain("connect-src 'self'")
  expect(headers['x-content-type-options']).toBe('nosniff')
  await page.getByRole('button', { name: 'Use safe PE demo' }).click()
  await expect(page.getByText('aegis-safe-dynamic-pe32.exe')).toBeVisible()
  await runDynamic(page)
  const storage = await page.evaluate(async () => ({
    local: localStorage.length,
    session: sessionStorage.length,
    databases: 'databases' in indexedDB ? (await indexedDB.databases()).length : 0,
  }))
  expect(storage).toEqual({ local: 0, session: 0, databases: 0 })
  expect(externalRequests).toEqual([])
})

test('analyzes a multi-megabyte sample within the browser budget', async ({ page, isMobile }) => {
  test.skip(isMobile, 'desktop performance budget')
  await page.goto('/')
  const started = Date.now()
  await page.getByTestId('file-input').setInputFiles({
    name: 'four-megabytes.bin',
    mimeType: 'application/octet-stream',
    buffer: Buffer.alloc(4 * 1024 * 1024, 0x41),
  })
  await expect(page.getByText('four-megabytes.bin')).toBeVisible()
  expect(Date.now() - started).toBeLessThan(5_000)
  await expect(page.getByText('4.00 MiB scanned')).toBeVisible()
})

test('keeps the complete mobile workflow usable', async ({ page, isMobile }) => {
  test.skip(!isMobile, 'mobile project only')
  await page.goto('/')
  await expect(page.getByRole('button', { name: 'Choose file' })).toBeVisible()
  await page.getByRole('button', { name: 'Use safe PE demo' }).click()
  await expect(page.getByText('aegis-safe-dynamic-pe32.exe')).toBeVisible()
  await page.getByRole('tab', { name: /^Strings/ }).click()
  await expect(page.getByLabel('Filter extracted values')).toBeVisible()
  await runDynamic(page)
  await expect(page.getByText('Process execution requested')).toBeVisible()
})
