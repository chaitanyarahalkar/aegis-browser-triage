# Aegis security model

## Security objective

Aegis lets an analyst inspect an untrusted binary without transmitting it or
executing its instructions. Uploaded files are data supplied to a Rust parser
compiled to WebAssembly. Uploaded Wasm files are parsed with `wasmparser`; they
are never passed to a browser WebAssembly instantiation API.

## Trust boundaries

The trusted computing base consists of the current browser, the Aegis
JavaScript and WebAssembly bundles, Rust dependencies recorded in the lockfile,
and the static server delivering those files. The uploaded sample and every
name, string, symbol, offset, count, and length derived from it are untrusted.

Sample bytes cross one boundary: a transferable `ArrayBuffer` moves from the UI
to a dedicated Worker. The worker copies the bytes into analyzer linear memory
for the duration of the Rust call. After analysis, only the worker retains the
original buffer for bounded hex reads. Closing, replacing, cancelling, timing
out, or crashing terminates that worker and drops the buffer.

## Enforced controls

- 128 MiB maximum input and a 30-second worker watchdog
- 4,096 sections and 50,000 items per large collection
- 50,000 strings, 4 KiB per string, and 8 MiB aggregate string data
- 64 KiB maximum worker hex response; the UI requests 512-byte pages
- Parser failures become structured errors; a trap or timeout discards the worker
- Magic-based format detection instead of trusting filenames or MIME types
- Sample values rendered as React text; no raw HTML or clickable IOC links
- No telemetry, analytics, external fonts, reputation lookups, or third-party runtime assets
- Production CSP limits scripts, workers, and network connections to the same origin
- No automatic localStorage, IndexedDB, OPFS, service-worker, or server persistence
- No original sample bytes in the exported JSON report

`connect-src 'self'` is required because the worker fetches the same-origin
analyzer Wasm asset. Browser tests assert that analysis creates no third-party
requests. A deployment should serve only immutable application assets from this
origin; it must not colocate sample-upload endpoints on the same host.

## Guarantees and non-guarantees

Aegis prevents application-level execution of the sample and bounds ordinary
parser resource use. It does not make a browser invulnerable. A browser-engine,
WebAssembly-runtime, compiler, or dependency vulnerability may escape these
controls. Use a fully updated browser and an isolated browser profile for highly
sensitive samples.

The static findings are evidence, not a malware verdict. Absence of a finding
does not mean a file is safe. Packed, encrypted, self-modifying, environment-
dependent, or runtime-downloaded behavior may be invisible to static analysis.

## Future dynamic analysis boundary

Dynamic analysis must use a separate crate and worker. A guest would execute
only in a CPU emulator with a synthetic loader and synthetic OS APIs. Time,
randomness, filesystem, registry, process, and network behavior must be virtual,
deterministic, and quota-bound. No guest syscall or emulated API may map to the
browser's real network, filesystem, DOM, clipboard, or storage APIs. Full guest-
OS virtualization is a separate product phase, not an extension of the static
worker.

