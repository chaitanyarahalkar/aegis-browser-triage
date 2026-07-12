# NOPE.exe

**Look before you launch.**

NOPE is a local-only binary triage workbench that runs in the browser. A Rust
engine performs static inspection of PE, ELF, Mach-O, and WebAssembly files. A
second Rust engine emulates 32-bit x86 and 64-bit x86-64 Windows PE samples plus
Linux ELF64/x86-64 executables inside a dedicated Web Worker. A third, lazy-loaded Rust engine compiles and scans YARA rules with
YARA-X entirely in the browser.

Samples are never uploaded or executed by the host. Dynamic analysis uses an
interpreter, in-memory PE and ELF loaders, and synthetic Windows/Linux userspaces.
Files, registry keys, processes, memory mappings, time, and network activity exist
only as modeled events in the worker.

## Capabilities

Static reports include:

- SHA-256, SHA-1, and MD5 identifiers
- Format, architecture, entry point, mitigations, and linkage metadata
- Sections, permissions, offsets, sizes, and byte entropy
- Imports, exports, bounded strings, and non-clickable indicators
- Explainable findings and a paged hex view
- Bounded x86/x64 recursive disassembly from entry points, exports, and direct calls
- Function, basic-block, call-site, and control-flow edge records with an interactive CFG
- Transparent CAPA-style capability matches correlated from imports, strings, and decoded instructions

Dynamic reports currently include:

- Linux ELF64/x86-64 `ET_EXEC` and basic PIE loading, System V register and stack
  rules, `argc`/`argv`/`envp`/auxv initialization, common x86-64 relocations, and
  bounded synthetic libc import stubs
- Direct Linux syscall modeling for file I/O, memory mappings/protection, process
  metadata, clocks/randomness, sockets, and denied process execution, with a
  deterministic virtual filesystem and scripted network sink
- Linux runtime artifacts, syscall timelines, findings, profile matrices, and
  API-level provenance from loaded-image/file/network bytes into virtual-file,
  network-request, process-command, and executable-memory sinks
- PE32/x86 image loading, TLS callbacks, imports, dynamic API resolution, a
  minimal PEB/TEB, stack, and guest memory
- PE64/x86-64 loading with sparse 64-bit guest addresses, RIP- and GS-relative
  addressing, 16 general-purpose registers, Microsoft x64 register arguments,
  shadow-space/stack arguments, TLS callbacks, and bounded unwind metadata
- PE64 parity for runtime memory/file/network artifacts, payload generations,
  synthetic files and registry values, scripted WinINet responses, API-level
  provenance, deterministic guest threads, and vectored exception dispatch
- PE64 dynamic module and export resolution through `LoadLibrary`,
  `GetProcAddress`, `LdrLoadDll`, and `LdrGetProcedureAddress`, with
  emulator-owned stubs and a bounded native-memory/runtime API subset
- Bounded instruction traces and termination reasons
- Expanded integer, conditional, flag, loop, and repeated string instructions
- Bit-test/scan, atomic exchange, double-shift, SSE2 move/logic/scalar arithmetic,
  and bounded basic x87 stack execution
- Nearby trace and byte diagnostics for malformed or still-unsupported instructions
- Typed Windows API signatures, ANSI/UTF-16 arguments, and deterministic virtual time
- Stateful synthetic handles, files, registry values, processes, DNS, sockets,
  HTTP sessions, heaps, environment, and memory
- Stateful mutexes/events and waits, file/process enumeration, restricted tokens,
  shared mappings, named pipes, resources, and bounded SHA-256 crypto handles
- Scripted DNS, TCP, WinINet, and WinHTTP responses with bounded redirects, typed
  exchanges, downloaded artifacts, YARA scanning, and synthetic-PCAP JSON export
- Bounded API-level byte provenance from sample, network, registry, virtual-file,
  and transformed data into process, executable-memory, persistence, network,
  file, and remote-process sinks
- Entry, API-boundary, and final execution snapshots with register/event metadata,
  bounded memory fingerprints, first-divergence detection, and exportable run diffs
- Ordered behavior timeline and execution/API coverage metrics
- Four deterministic Windows environment profiles with selectable single runs and
  a bounded profile-matrix comparison for environment-sensitive behavior
- Correlated process-injection primitives such as remote allocation, writes,
  protection changes, remote threads, and APCs
- Bounded runtime artifact capture from interesting memory, virtual files, and
  synthetic remote memory, with hashes, entropy, strings, indicators, and origins
- Bounded unpacking lineage for distinct written/executable memory generations,
  including parent links, execution state, executable heaps, and entry-point overwrites
- Automated generated-code entry-point candidates and runtime import reconstruction
  from API calls whose return sites originate inside a captured payload generation
- Bounded x86 structured exception dispatch through guest `FS:[0]` chains and x64
  vectored dispatch with runtime-function lookup evidence, including bounded
  continue-execution/search dispositions and synthetic records/contexts
- Deterministic x86/x64 guest-thread execution with isolated registers, 64 KiB
  stacks and TEB state, shared guest memory, and a 100-instruction round-robin quantum
- Explicit batch YARA scanning of captured artifacts and confirmation-gated raw export
- Explainable findings derived from observed behavior

YARA analysis includes:

- A conservative first-party starter pack and an editable rule workspace
- Ephemeral `.yar` / `.yara` import and local rule export
- Structured compiler diagnostics, severity metadata, tags, and match offsets
- Links from occurrences to the bounded hex viewer
- Batch scans of explicitly selected runtime artifacts using the current editor rules
- PE, ELF, Mach-O, .NET, hash, math, string, and time modules

This is a triage tool, not a clean or malicious verdict. The interpreter
supports a useful subset of x86/x64 instructions, Windows APIs, Linux syscalls,
and libc entry points; unsupported instructions or interfaces,
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

Open <http://127.0.0.1:4173> after `npm run preview`. `npm run dev` builds all
Rust engines and starts the development server. Browser tests cover desktop and
mobile Chromium, static disassembly and CFG interaction, capability evidence,
dynamic API behavior, YARA compilation and matches, instruction
and memory limits, deterministic environment matrices, runtime artifact capture and
YARA, CSP, storage, malformed input, export, and a static performance budget.

On Homebrew systems where `rustup` is keg-only, prepend its shim directory for
Wasm builds:

```sh
PATH="$(brew --prefix rustup)/bin:$PATH" npm run build
```

## Repository structure

- `crates/analysis-core`: platform-neutral static analysis and report schema
- `crates/analysis-wasm`: static `wasm-bindgen` adapter
- `crates/analysis-dynamic`: bounded PE32/PE64 and ELF64 loaders, x86/x64 interpreters, and synthetic Windows/Linux runtimes
- `crates/analysis-dynamic-wasm`: dynamic `wasm-bindgen` adapter
- `crates/analysis-yara`: bounded YARA-X compiler, scanner, and report schema
- `crates/analysis-yara-wasm`: YARA `wasm-bindgen` adapter
- `web`: React UI, separate workers, production CSP, fixtures, and browser tests
- `docs/security-model.md`: trust boundaries, limits, guarantees, and non-goals

The production app has no telemetry, third-party assets, reputation lookups, or
automatic persistence. See the security model before analyzing hostile samples.

Licensed under MIT.

Live app: <https://chaitanyarahalkar.github.io/aegis-browser-triage/>

The repository and legacy fixture identifiers retain the original Aegis naming
for link and report compatibility during the rebrand.
