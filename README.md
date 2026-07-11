# Aegis

Aegis is a local-only binary triage workbench that runs in the browser. A Rust
engine performs static inspection of PE, ELF, Mach-O, and WebAssembly files. A
second Rust engine can emulate 32-bit x86 Windows PE samples inside a dedicated
Web Worker.

Samples are never uploaded or executed by the host. Dynamic analysis uses an
interpreter, an in-memory PE loader, and synthetic Windows APIs. Files, registry
keys, processes, memory mappings, time, and network activity exist only as
modeled events in the worker.

## Capabilities

Static reports include:

- SHA-256, SHA-1, and MD5 identifiers
- Format, architecture, entry point, mitigations, and linkage metadata
- Sections, permissions, offsets, sizes, and byte entropy
- Imports, exports, bounded strings, and non-clickable indicators
- Explainable findings and a paged hex view

Dynamic reports currently include:

- PE32/x86 image loading, import resolution, stack, and guest memory
- Bounded instruction traces and termination reasons
- Modeled Windows API calls and deterministic virtual time
- Synthetic process, filesystem, registry, network, and memory events
- Explainable findings derived from observed behavior

This is a triage tool, not a clean or malicious verdict. The interpreter
supports a useful subset of x86 and Windows APIs; unsupported instructions,
malformed memory access, timeouts, and instruction limits stop safely and are
reported.

## Development

Requirements:

- Rust via `rustup`, with the `wasm32-unknown-unknown` target
- `wasm-pack` 0.15 or newer
- Node.js 22 or newer

```sh
cargo test --workspace --all-features
cd web
npm install
npm test
npm run build
npm run test:e2e
```

Open <http://127.0.0.1:4173> after `npm run preview`. `npm run dev` builds both
Rust engines and starts the development server. Browser tests cover desktop and
mobile Chromium, dynamic API behavior, instruction and memory limits, CSP,
storage, malformed input, export, and a static performance budget.

On Homebrew systems where `rustup` is keg-only, prepend its shim directory for
Wasm builds:

```sh
PATH="$(brew --prefix rustup)/bin:$PATH" npm run build
```

## Repository structure

- `crates/analysis-core`: platform-neutral static analysis and report schema
- `crates/analysis-wasm`: static `wasm-bindgen` adapter
- `crates/analysis-dynamic`: bounded PE32 loader, x86 interpreter, and virtual APIs
- `crates/analysis-dynamic-wasm`: dynamic `wasm-bindgen` adapter
- `web`: React UI, separate workers, production CSP, fixtures, and browser tests
- `docs/security-model.md`: trust boundaries, limits, guarantees, and non-goals

The production app has no telemetry, third-party assets, reputation lookups, or
automatic persistence. See the security model before analyzing hostile samples.

Licensed under MIT.

Live app: <https://chaitanyarahalkar.github.io/aegis-browser-triage/>
