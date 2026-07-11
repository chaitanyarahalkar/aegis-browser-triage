import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const productionHeaders = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; worker-src 'self' blob:; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
}

export default defineConfig(({ command }) => ({
  base: './',
  plugins: [react()],
  worker: {
    rolldownOptions: {
      output: {
        entryFileNames: 'assets/[name].js',
      },
    },
  },
  server: {
    headers: command === 'serve' ? {
      ...productionHeaders,
      'Content-Security-Policy': "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' ws:; worker-src 'self' blob:; object-src 'none'; base-uri 'none'",
    } : productionHeaders,
  },
  preview: { headers: productionHeaders },
  build: {
    target: 'es2022',
    sourcemap: false,
    chunkSizeWarningLimit: 700,
  },
  test: {
    environment: 'jsdom',
    setupFiles: './src/test/setup.ts',
    include: ['src/**/*.test.{ts,tsx}'],
    coverage: { reporter: ['text', 'html'] },
  },
}))
