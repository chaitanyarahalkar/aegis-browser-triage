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

async function runDynamic(page: import('@playwright/test').Page) {
  await page.getByRole('tab', { name: /^Dynamic/ }).click()
  await page.getByRole('button', { name: 'Run selected profile' }).click()
  await expect(page.getByText('Exit 0', { exact: true })).toBeVisible()
}

async function runYara(page: import('@playwright/test').Page) {
  await page.getByRole('tab', { name: /^YARA/ }).click()
  await page.getByRole('button', { name: 'Compile & scan' }).click()
  await expect(page.getByText('Aegis_Safe_Demo', { exact: true })).toBeVisible()
}

test('runs the safe PE through static and dynamic Rust workers', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Analyze binaries locally.' })).toBeVisible()
  await expect(page.getByText('No uploads')).toBeVisible()
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
  await expect(page.getByText('Dynamic v7', { exact: true })).toBeVisible()
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
  await expect(page.getByText('Behavior changed', { exact: true }).first()).toBeVisible()
  await page.getByRole('button', { name: 'Hardened offline host', exact: true }).click()
  await expect(page.getByText('Windows 11 24H2 · offline', { exact: true })).toBeVisible()

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
  await expect(page.getByText('Identifies the first-party Aegis safe test fixture', { exact: true })).toBeVisible()
  await page.locator('.offset-link').first().click()
  await expect(page.getByRole('heading', { name: 'Hex view' })).toBeVisible()
  const downloadPromise = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Export report' }).click()
  const download = await downloadPromise
  expect(download.suggestedFilename()).toBe('aegis-safe-dynamic-pe32.exe.aegis-report.json')
  const json = JSON.parse(readFileSync(await download.path()!, 'utf8'))
  expect(json.static.sample.detected_format).toBe('pe')
  expect(json.dynamic.termination).toEqual({ reason: 'exit_process', code: 0 })
  expect(json.dynamic.schema_version).toBe(7)
  expect(json.dynamic.timeline).toHaveLength(4)
  expect(json.dynamic.coverage.modeled_api_calls).toBe(4)
  expect(json.dynamic.processes[0].command).toContain('powershell.exe')
  expect(json.yara.matches[0].identifier).toBe('Aegis_Safe_Demo')
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
  await expect(page.getByText('Aegis_Safe_Runtime_Artifact', { exact: true }).first()).toBeVisible()
  await page.getByRole('button', { name: /^Artifacts/ }).click()
  await expect(page.locator('.artifact-strings')).toContainText('AEGIS_SAFE_RUNTIME_ARTIFACT')
  await expect(page.getByText('Aegis_Safe_Runtime_Artifact', { exact: true }).first()).toBeVisible()

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
  expect(json.dynamic.artifact_yara.some((result: { report?: { matches: Array<{ identifier: string }> } }) => result.report?.matches.some((match) => match.identifier === 'Aegis_Safe_Runtime_Artifact'))).toBe(true)
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
