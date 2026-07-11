# Aegis

Aegis is a local-only static binary triage workbench. Its Rust analysis engine
parses PE, ELF, Mach-O, and WebAssembly samples inside a dedicated browser Web
Worker. Samples are treated as inert bytes: the application never instantiates,
loads, or executes an uploaded binary.

## What it reports

- SHA-256, SHA-1, and MD5 identifiers
- Format, architecture, entry-point, mitigation, and linkage metadata
- Sections, permissions, offsets, sizes, and byte entropy
- Imports, exports, printable strings, and non-clickable indicators
- Explainable findings with severity, confidence, rationale, and evidence
- Paged hex data and an explicit JSON report export

The current version performs static triage only. It does not provide a clean or
malicious verdict, unpack archives, disassemble instructions, run YARA rules, or
execute samples.

## Development

Requirements:

- Rust via `rustup`, with the `wasm32-unknown-unknown` target
- `wasm-pack` 0.15 or newer
- Node.js 22 or newer

```sh
cargo test --workspace
cd web
npm install
npm run build
npm run preview
```

Open <http://127.0.0.1:4173>. `npm run dev` builds the Rust engine and starts a
development server. `npm run test:e2e` runs the production workflow in desktop
and mobile Chromium after the production bundle has been built.

On Homebrew systems where `rustup` is keg-only, prepend its shim directory for
Wasm builds:

```sh
PATH="$(brew --prefix rustup)/bin:$PATH" npm run build
```

## Repository structure

- `crates/analysis-core`: deterministic, platform-neutral analysis and report schema
- `crates/analysis-wasm`: narrow `wasm-bindgen` adapter
- `web`: React UI, transferable worker protocol, production CSP, and browser tests
- `docs/security-model.md`: guarantees, trust boundaries, limits, and non-goals

The production app has no telemetry, third-party assets, remote reputation
lookups, or automatic persistence. See the security model before analyzing
hostile samples.

Licensed under MIT.
