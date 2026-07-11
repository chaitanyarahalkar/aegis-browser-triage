import { expect, test } from '@playwright/test'

test('analyzes a safe WebAssembly sample through the Rust worker', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByRole('heading', { name: /Inspect suspicious binaries/i })).toBeVisible()
  await page.getByRole('button', { name: 'Try safe demo' }).click()

  await expect(page.getByText('safe-demo.wasm')).toBeVisible()
  await expect(page.getByText('WebAssembly', { exact: true }).first()).toBeVisible()
  await expect(page.getByText('Static analysis completed')).toBeVisible()
  await expect(page.getByText('Sample remained local')).toBeVisible()

  await page.getByRole('tab', { name: /Structure/ }).click()
  await expect(page.getByText('custom:meta')).toBeVisible()
  await page.getByRole('tab', { name: /Strings \/ IOCs/ }).click()
  await page.getByRole('button', { name: /Indicators/ }).click()
  await expect(page.getByText('https://example.test')).toBeVisible()
  await page.getByRole('tab', { name: 'Hex view' }).click()
  await expect(page.getByText('Paged hex view')).toBeVisible()
  await expect(page.locator('.hex-row').first()).toContainText('00 61 73 6d')
})

test('handles unsupported and malformed binaries safely', async ({ page }) => {
  await page.goto('/')
  const input = page.getByTestId('file-input')
  await input.setInputFiles({ name: 'unknown.bin', mimeType: 'application/octet-stream', buffer: Buffer.from('plain inert content') })
  await expect(page.getByText('unknown.bin')).toBeVisible()
  await expect(page.getByText('Unrecognized binary format')).toBeVisible()
  await page.getByRole('button', { name: 'Close sample' }).click()

  await input.setInputFiles({ name: 'broken.exe', mimeType: 'application/octet-stream', buffer: Buffer.from([0x4d, 0x5a, 0, 0]) })
  await expect(page.getByRole('alert')).toContainText('Analysis stopped safely')
  await expect(page.getByRole('alert')).toContainText('failed to parse PE')
})

test('exports a sanitized local JSON report', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: 'Try safe demo' }).click()
  await expect(page.getByText('safe-demo.wasm')).toBeVisible()
  const downloadPromise = page.waitForEvent('download')
  await page.getByRole('button', { name: /Export JSON/ }).click()
  const download = await downloadPromise
  expect(download.suggestedFilename()).toBe('safe-demo.wasm.aegis-report.json')
})

test('does not contact any third-party origin', async ({ page }) => {
  const externalRequests: string[] = []
  page.on('request', (request) => {
    const url = new URL(request.url())
    if (url.origin !== 'http://127.0.0.1:4173') externalRequests.push(request.url())
  })
  await page.goto('/')
  await page.getByRole('button', { name: 'Try safe demo' }).click()
  await expect(page.getByText('safe-demo.wasm')).toBeVisible()
  expect(externalRequests).toEqual([])
})

test('ships hardened headers and leaves browser storage empty', async ({ page }) => {
  const response = await page.goto('/')
  const headers = response?.headers() ?? {}
  expect(headers['content-security-policy']).toContain("object-src 'none'")
  expect(headers['content-security-policy']).toContain("connect-src 'self'")
  expect(headers['x-content-type-options']).toBe('nosniff')
  await page.getByRole('button', { name: 'Try safe demo' }).click()
  await expect(page.getByText('safe-demo.wasm')).toBeVisible()
  const storage = await page.evaluate(async () => ({
    local: localStorage.length,
    session: sessionStorage.length,
    databases: 'databases' in indexedDB ? (await indexedDB.databases()).length : 0,
  }))
  expect(storage).toEqual({ local: 0, session: 0, databases: 0 })
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

test('keeps the responsive mobile workflow usable', async ({ page, isMobile }) => {
  test.skip(!isMobile, 'mobile project only')
  await page.goto('/')
  await expect(page.getByRole('button', { name: 'Select binary' })).toBeVisible()
  await page.getByRole('button', { name: 'Try safe demo' }).click()
  await expect(page.getByText('safe-demo.wasm')).toBeVisible()
  await page.getByRole('tab', { name: /Strings \/ IOCs/ }).click()
  await expect(page.getByLabel('Filter extracted values')).toBeVisible()
})
