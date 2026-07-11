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
  await page.getByRole('button', { name: 'Run dynamic analysis' }).click()
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
  await expect(page.getByRole('cell', { name: 'powershell.exe -NoProfile https://example.test 10.20.30.40', exact: true })).toBeVisible()
  await expect(page.getByText('Captured only; no host process created')).toBeVisible()
  await expect(page.getByText('No guest operation left the browser.')).toBeVisible()

  await page.getByRole('button', { name: /^API calls/ }).click()
  for (const api of ['GetTickCount', 'Sleep', 'WinExec', 'ExitProcess']) {
    await expect(page.getByText(`KERNEL32.dll!${api}`, { exact: true })).toBeVisible()
  }
  await page.getByRole('button', { name: /^Instructions/ }).click()
  await expect(page.locator('tbody')).toContainText('call dword ptr')
})

test('bounds an infinite loop by instruction count', async ({ page, isMobile }) => {
  test.skip(isMobile, 'covered by desktop hostile-fixture suite')
  const loop = Buffer.from(safePe)
  loop.set([0xeb, 0xfe], 0x200)
  await page.goto('/')
  await page.getByTestId('file-input').setInputFiles({ name: 'bounded-loop.exe', mimeType: 'application/octet-stream', buffer: loop })
  await expect(page.getByText('bounded-loop.exe')).toBeVisible()
  await page.getByRole('tab', { name: /^Dynamic/ }).click()
  await page.getByRole('button', { name: 'Run dynamic analysis' }).click()
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
  await page.getByRole('button', { name: 'Run dynamic analysis' }).click()
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
