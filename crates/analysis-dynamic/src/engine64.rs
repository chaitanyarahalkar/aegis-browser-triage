use crate::{
    ApiEvent, ArtifactKind, ArtifactOrigin, DynamicAnalysis, DynamicError, DynamicFinding,
    DynamicOptions, DynamicReport, DynamicSeverity, ExceptionEvent, ExecutionCoverage,
    ExecutionDiagnostics, ExecutionProfile, ExecutionSnapshot, FileEvent, InstructionDiagnostic,
    InstructionEvent, MemoryEvent, NetworkEvent, NetworkExchange, NetworkMode, PersistenceEvent,
    ProcessEvent, ProvenanceSinkKind, ProvenanceSourceKind, RegistryEvent, RuntimeFunction,
    SnapshotEventCounts, SnapshotRegisters, SnapshotStats, SystemEvent, Termination, ThreadEvent,
    ThreadSummary, TimelineEvent,
    api::normalize_name,
    artifact::{ArtifactCapture, ArtifactStore, MAX_ARTIFACT_BYTES},
    cpu64::Cpu64,
    generation::{GenerationObservation, GenerationTracker},
    loader::ApiImport,
    loader64::{self, STACK64_TOP},
    memory::Permissions,
    memory64::Memory64,
    network::NetworkRuntime,
    provenance::ProvenanceTracker,
    windows::{HandleResource, VirtualWindows},
};
use iced_x86::{Code, Decoder, DecoderOptions, Instruction, Mnemonic};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const ENTRY64_RETURN_SENTINEL: u64 = 0x0000_006e_ffff_fff0;
const TLS64_RETURN_SENTINEL: u64 = 0x0000_006e_ffff_ffe0;
const EXCEPTION64_RETURN_SENTINEL: u64 = 0x0000_006e_ffff_ffd0;
const THREAD64_RETURN_SENTINEL: u64 = 0x0000_006e_ffff_ffc0;
const PROCESS_ENV64_BASE: u64 = 0x0000_007e_0000_0000;
const COMMAND_LINE64_A: u64 = PROCESS_ENV64_BASE;
const TEB64_BASE: u64 = 0x0000_007f_fde0_0000;
const PEB64_BASE: u64 = 0x0000_007f_fdf0_0000;
const HEAP64_BASE: u64 = 0x0000_0050_0000_0000;
const DYNAMIC_API64_BASE: u64 = 0x0000_006e_0000_0000;
const MAX_DYNAMIC_API64_STUBS: usize = 4_096;
const EXCEPTION64_SCRATCH_BASE: u64 = PROCESS_ENV64_BASE + 0x1000;
const EXCEPTION64_RECORD_BASE: u64 = EXCEPTION64_SCRATCH_BASE;
const EXCEPTION64_CONTEXT_BASE: u64 = EXCEPTION64_SCRATCH_BASE + 0x200;
const MAX_EXCEPTION_EVENTS: usize = 128;
const MAX_EXCEPTION_DEPTH: usize = 16;
const MAX_GUEST_THREADS: usize = 64;
const MAX_THREAD_EVENTS: usize = 4_096;
const THREAD_QUANTUM: u64 = 100;
const THREAD_STACK_SIZE: usize = 64 * 1024;
const MAX_SNAPSHOTS: usize = 256;
const MAX_DIRTY_REGIONS: usize = 64;
const SNAPSHOT_SAMPLE: usize = 512;

pub(crate) fn run(
    _name: String,
    bytes: &[u8],
    options: DynamicOptions,
) -> Result<DynamicAnalysis, DynamicError> {
    let mut loaded = loader64::load(bytes)?;
    loaded.memory.map(
        PROCESS_ENV64_BASE,
        0x2000,
        Permissions::READ_WRITE,
        "x64 process environment",
    )?;
    loaded
        .memory
        .write_force(COMMAND_LINE64_A, b"sample64.exe\0")?;
    loaded.memory.map(
        TEB64_BASE,
        0x1000,
        Permissions::READ_WRITE,
        "x64 synthetic TEB",
    )?;
    loaded.memory.map(
        PEB64_BASE,
        0x1000,
        Permissions::READ_WRITE,
        "x64 synthetic PEB",
    )?;
    loaded
        .memory
        .write_force(TEB64_BASE + 0x30, &TEB64_BASE.to_le_bytes())?;
    loaded
        .memory
        .write_force(TEB64_BASE + 0x60, &PEB64_BASE.to_le_bytes())?;
    loaded
        .memory
        .write_force(PEB64_BASE + 0x10, &loaded.image_base.to_le_bytes())?;
    loaded
        .memory
        .write_force(PEB64_BASE + 0x20, &PROCESS_ENV64_BASE.to_le_bytes())?;

    let main_cpu = Cpu64 {
        rip: loaded.entry_point,
        gs_base: TEB64_BASE,
        ..Cpu64::default()
    };
    let mut provenance = ProvenanceTracker::default();
    provenance.source(
        ProvenanceSourceKind::Sample,
        "loaded PE64 image",
        loaded.image_base,
        loaded.image_size as usize,
        "loader64",
        0,
    );

    let environment = options.environment.clone();
    let network_scenario = options.network_scenario.clone();
    let profile = ExecutionProfile {
        architecture: "x86-64 (64-bit)".into(),
        operating_system: environment.windows_version.clone(),
        image_base: loaded.image_base,
        entry_point: loaded.entry_point,
        instruction_limit: options.max_instructions,
        trace_limit: options.max_trace_events,
        network_mode: environment.network_mode.description().into(),
        environment: environment.clone(),
        network_scenario: network_scenario.id.clone(),
    };
    let mut machine = Machine64 {
        cpu: main_cpu.clone(),
        memory: loaded.memory,
        imports: loaded.imports,
        options,
        environment,
        entry_point: loaded.entry_point,
        image_base: loaded.image_base,
        tls_callbacks: loaded.tls_callbacks.into(),
        instruction_count: 0,
        virtual_time_ms: profile.environment.initial_virtual_time_ms,
        instructions: Vec::new(),
        api_calls: Vec::new(),
        processes: Vec::new(),
        filesystem: Vec::new(),
        registry: Vec::new(),
        network: Vec::new(),
        network_exchanges: Vec::new(),
        memory_events: Vec::new(),
        persistence: Vec::new(),
        exceptions: Vec::new(),
        timeline: Vec::new(),
        warnings: loaded.warnings,
        termination: None,
        truncated: false,
        unique_instruction_addresses: BTreeSet::new(),
        unique_api_names: BTreeSet::new(),
        modeled_api_calls: 0,
        unmodeled_api_calls: 0,
        first_unsupported: None,
        invalid_instruction_count: 0,
        snapshots: Vec::new(),
        snapshots_truncated: false,
        heap_next: HEAP64_BASE,
        dynamic_api_next: DYNAMIC_API64_BASE,
        dynamic_api_resolutions: 0,
        windows: VirtualWindows::default(),
        network_runtime: NetworkRuntime::new(network_scenario),
        artifacts: ArtifactStore::default(),
        generations: GenerationTracker::default(),
        provenance,
        vectored_handlers: Vec::new(),
        pending_exception: None,
        queued_exception: None,
        thread_states: vec![GuestThread64 {
            tid: 1,
            start_address: loaded.entry_point,
            parameter: 0,
            cpu: main_cpu,
            state: GuestThreadState64::Runnable,
            instruction_count: 0,
            exit_code: None,
        }],
        thread_events: Vec::new(),
        current_thread: 0,
        thread_exit_requested: None,
        next_thread_switch: THREAD_QUANTUM,
        system: Vec::new(),
        unwind_functions: loaded.unwind_functions.clone(),
    };
    machine.start_next_target()?;
    machine.record_snapshot("entry", false);
    machine.execute();
    machine.record_snapshot("final", true);
    machine.capture_final_artifacts();
    machine.save_current_thread();

    let mut findings = machine.build_findings();
    if !loaded.unwind_functions.is_empty() {
        findings.push(DynamicFinding {
            id: "x64-unwind-metadata".into(),
            title: "x64 unwind metadata mapped".into(),
            severity: DynamicSeverity::Info,
            rationale: "Bounded PE64 runtime-function entries were retained for stack and exception analysis.".into(),
            evidence: vec![format!("{} runtime functions", loaded.unwind_functions.len())],
        });
    }
    let snapshot_stats = SnapshotStats {
        count: machine.snapshots.len(),
        truncated: machine.snapshots_truncated,
        max_snapshots: MAX_SNAPSHOTS,
        max_dirty_regions: MAX_DIRTY_REGIONS,
        sampled_bytes_per_region: SNAPSHOT_SAMPLE * 2,
    };
    let (artifacts, artifact_stats, artifact_blobs) = machine.artifacts.finish();
    let (payload_generations, generation_stats) = machine.generations.finish();
    let (provenance_sources, provenance_flows, provenance_stats) = machine.provenance.finish();
    if generation_stats.entry_point_candidates > 0 {
        findings.retain(|finding| finding.id != "no-modeled-behavior");
        findings.push(DynamicFinding {
            id: "unpacked-entry-point-candidate".into(),
            title: "Generated payload entry point identified".into(),
            severity: DynamicSeverity::High,
            rationale: "Execution entered a dirty executable allocation. The address is a bounded unpacking candidate, not a guaranteed original entry point.".into(),
            evidence: payload_generations
                .iter()
                .filter_map(|generation| {
                    generation.entry_point_candidate.map(|address| {
                        format!(
                            "{} · 0x{address:016x} · {} observed imports",
                            generation.id,
                            generation.reconstructed_imports.len()
                        )
                    })
                })
                .collect(),
        });
    }
    if generation_stats.reconstructed_imports > 0 {
        findings.push(DynamicFinding {
            id: "runtime-import-reconstruction".into(),
            title: "Runtime imports reconstructed".into(),
            severity: DynamicSeverity::Medium,
            rationale: "API calls originating inside generated executable memory were associated with the active payload generation.".into(),
            evidence: payload_generations
                .iter()
                .flat_map(|generation| generation.reconstructed_imports.iter().cloned())
                .collect(),
        });
    }
    let unwind_count = loaded.unwind_functions.len();
    let report = DynamicReport {
        schema_version: crate::DYNAMIC_SCHEMA_VERSION,
        engine_version: env!("CARGO_PKG_VERSION").into(),
        sample_sha256: hex::encode(Sha256::digest(bytes)),
        profile,
        termination: machine
            .termination
            .clone()
            .unwrap_or(Termination::InstructionLimit),
        instruction_count: machine.instruction_count,
        elapsed_ms: 0.0,
        virtual_time_ms: machine.virtual_time_ms,
        instructions: machine.instructions,
        api_calls: machine.api_calls,
        processes: machine.processes,
        filesystem: machine.filesystem,
        registry: machine.registry,
        network: machine.network,
        network_exchanges: machine.network_exchanges,
        provenance_sources,
        provenance_flows,
        provenance_stats,
        snapshots: machine.snapshots,
        snapshot_stats,
        unwind_functions: machine.unwind_functions,
        memory: machine.memory_events,
        injection: Vec::new(),
        persistence: machine.persistence,
        exceptions: machine.exceptions,
        threads: machine
            .thread_states
            .iter()
            .map(GuestThread64::summary)
            .collect(),
        thread_events: machine.thread_events,
        system: [
            vec![
                SystemEvent {
                    category: "loader".into(),
                    operation: "map_teb_peb".into(),
                    target: format!("TEB 0x{TEB64_BASE:016x} / PEB 0x{PEB64_BASE:016x}"),
                    detail: "GS:[0x30] self pointer and GS:[0x60] PEB pointer".into(),
                    result: 1,
                },
                SystemEvent {
                    category: "loader".into(),
                    operation: "map_unwind".into(),
                    target: "PE64 exception directory".into(),
                    detail: format!("{unwind_count} bounded runtime functions"),
                    result: unwind_count as u64,
                },
            ],
            machine.system,
        ]
        .concat(),
        artifacts,
        artifact_stats,
        payload_generations,
        generation_stats,
        timeline: machine.timeline,
        coverage: ExecutionCoverage {
            unique_instruction_addresses: machine.unique_instruction_addresses.len(),
            unique_api_names: machine.unique_api_names.len(),
            modeled_api_calls: machine.modeled_api_calls,
            unmodeled_api_calls: machine.unmodeled_api_calls,
            dynamic_api_resolutions: machine.dynamic_api_resolutions,
        },
        diagnostics: ExecutionDiagnostics {
            first_unsupported: machine.first_unsupported,
            invalid_instruction_count: machine.invalid_instruction_count,
        },
        findings,
        warnings: machine.warnings,
        truncated: machine.truncated,
    };
    Ok(DynamicAnalysis {
        report,
        artifacts: artifact_blobs,
    })
}

struct Machine64 {
    cpu: Cpu64,
    memory: Memory64,
    imports: BTreeMap<u64, ApiImport>,
    options: DynamicOptions,
    environment: crate::EnvironmentProfile,
    entry_point: u64,
    image_base: u64,
    tls_callbacks: VecDeque<u64>,
    instruction_count: u64,
    virtual_time_ms: u64,
    instructions: Vec<InstructionEvent>,
    api_calls: Vec<ApiEvent>,
    processes: Vec<ProcessEvent>,
    filesystem: Vec<FileEvent>,
    registry: Vec<RegistryEvent>,
    network: Vec<NetworkEvent>,
    network_exchanges: Vec<NetworkExchange>,
    memory_events: Vec<MemoryEvent>,
    persistence: Vec<PersistenceEvent>,
    exceptions: Vec<ExceptionEvent>,
    timeline: Vec<TimelineEvent>,
    warnings: Vec<String>,
    termination: Option<Termination>,
    truncated: bool,
    unique_instruction_addresses: BTreeSet<u64>,
    unique_api_names: BTreeSet<String>,
    modeled_api_calls: usize,
    unmodeled_api_calls: usize,
    first_unsupported: Option<InstructionDiagnostic>,
    invalid_instruction_count: usize,
    snapshots: Vec<ExecutionSnapshot>,
    snapshots_truncated: bool,
    heap_next: u64,
    dynamic_api_next: u64,
    dynamic_api_resolutions: usize,
    windows: VirtualWindows,
    network_runtime: NetworkRuntime,
    artifacts: ArtifactStore,
    generations: GenerationTracker,
    provenance: ProvenanceTracker,
    vectored_handlers: Vec<u64>,
    pending_exception: Option<PendingException64>,
    queued_exception: Option<(u32, String)>,
    thread_states: Vec<GuestThread64>,
    thread_events: Vec<ThreadEvent>,
    current_thread: usize,
    thread_exit_requested: Option<u32>,
    next_thread_switch: u64,
    system: Vec<SystemEvent>,
    unwind_functions: Vec<RuntimeFunction>,
}

#[derive(Clone)]
struct GuestThread64 {
    tid: u32,
    start_address: u64,
    parameter: u64,
    cpu: Cpu64,
    state: GuestThreadState64,
    instruction_count: u64,
    exit_code: Option<u32>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GuestThreadState64 {
    Runnable,
    Terminated,
}

impl GuestThread64 {
    fn summary(&self) -> ThreadSummary {
        ThreadSummary {
            tid: self.tid,
            start_address: self.start_address,
            parameter: self.parameter,
            state: if self.state == GuestThreadState64::Runnable {
                "runnable"
            } else {
                "terminated"
            }
            .into(),
            instruction_count: self.instruction_count,
            exit_code: self.exit_code,
        }
    }
}

struct PendingException64 {
    code: u32,
    name: String,
    address: u64,
    resume_rip: u64,
    depth: usize,
    fallback: Termination,
    event_index: usize,
    vectored_index: usize,
    saved_cpu: Cpu64,
}

impl Machine64 {
    fn save_current_thread(&mut self) {
        if let Some(thread) = self.thread_states.get_mut(self.current_thread) {
            thread.cpu = self.cpu.clone();
        }
    }

    fn schedule_next_thread(&mut self, record: bool) -> bool {
        self.save_current_thread();
        let count = self.thread_states.len();
        let Some(next) = (1..=count)
            .map(|offset| (self.current_thread + offset) % count)
            .find(|index| self.thread_states[*index].state == GuestThreadState64::Runnable)
        else {
            return false;
        };
        if next != self.current_thread {
            self.current_thread = next;
            self.cpu = self.thread_states[next].cpu.clone();
            if record {
                self.record_thread_event("scheduled", next);
            }
        }
        true
    }

    fn finish_current_thread(&mut self, exit_code: u32) {
        if let Some(thread) = self.thread_states.get_mut(self.current_thread) {
            thread.cpu = self.cpu.clone();
            thread.state = GuestThreadState64::Terminated;
            thread.exit_code = Some(exit_code);
        }
        self.record_thread_event("exited", self.current_thread);
    }

    fn terminate_all_threads(&mut self, exit_code: u32) {
        self.save_current_thread();
        let active: Vec<_> = self
            .thread_states
            .iter()
            .enumerate()
            .filter_map(|(index, thread)| {
                (thread.state == GuestThreadState64::Runnable).then_some(index)
            })
            .collect();
        for index in active {
            self.thread_states[index].state = GuestThreadState64::Terminated;
            self.thread_states[index].exit_code = Some(exit_code);
            self.record_thread_event("process_exit", index);
        }
    }

    fn record_thread_event(&mut self, operation: &str, index: usize) {
        if self.thread_events.len() >= MAX_THREAD_EVENTS {
            self.truncated = true;
            return;
        }
        let thread = &self.thread_states[index];
        self.thread_events.push(ThreadEvent {
            sequence: self.thread_events.len() as u64,
            tid: thread.tid,
            operation: operation.into(),
            instruction: self.instruction_count,
            virtual_time_ms: self.virtual_time_ms,
            start_address: thread.start_address,
            parameter: thread.parameter,
        });
    }

    fn create_guest_thread(&mut self, start_address: u64, parameter: u64) -> u32 {
        if self.thread_states.len() >= MAX_GUEST_THREADS
            || self.memory.fetch(start_address, 1).is_err()
        {
            return 0;
        }
        let tid = self.thread_states.len() as u32 + 1;
        let stack_base =
            0x0000_0060_0000_0000u64.saturating_add(u64::from(tid).saturating_mul(0x20_000));
        let teb_base =
            0x0000_007f_fdc0_0000u64.saturating_sub(u64::from(tid).saturating_mul(0x2000));
        if self
            .memory
            .map(
                stack_base,
                THREAD_STACK_SIZE,
                Permissions::READ_WRITE,
                format!("x64 thread {tid} stack"),
            )
            .is_err()
            || self
                .memory
                .map(
                    teb_base,
                    0x1000,
                    Permissions::READ_WRITE,
                    format!("x64 thread {tid} TEB"),
                )
                .is_err()
        {
            return 0;
        }
        let _ = self
            .memory
            .write_force(teb_base + 0x30, &teb_base.to_le_bytes());
        let _ = self
            .memory
            .write_force(teb_base + 0x60, &PEB64_BASE.to_le_bytes());
        let top = stack_base.saturating_add(THREAD_STACK_SIZE as u64);
        let mut cpu = Cpu64 {
            rip: start_address,
            gs_base: teb_base,
            ..Cpu64::default()
        };
        cpu.set_rsp(top);
        cpu.gpr[5] = top;
        cpu.gpr[1] = parameter;
        if cpu
            .push(&mut self.memory, THREAD64_RETURN_SENTINEL)
            .is_err()
        {
            return 0;
        }
        self.thread_states.push(GuestThread64 {
            tid,
            start_address,
            parameter,
            cpu,
            state: GuestThreadState64::Runnable,
            instruction_count: 0,
            exit_code: None,
        });
        let index = self.thread_states.len() - 1;
        self.record_thread_event("created", index);
        tid
    }

    fn dispatch_exception(
        &mut self,
        code: u32,
        name: &str,
        address: u64,
        resume_rip: u64,
        fallback: Termination,
    ) -> bool {
        if self.pending_exception.is_some()
            || self.exceptions.len() >= MAX_EXCEPTION_EVENTS
            || self.vectored_handlers.is_empty()
        {
            return false;
        }
        let pending = PendingException64 {
            code,
            name: name.into(),
            address,
            resume_rip,
            depth: 0,
            fallback,
            event_index: 0,
            vectored_index: 0,
            saved_cpu: self.cpu.clone(),
        };
        self.begin_exception_handler(pending)
    }

    fn begin_exception_handler(&mut self, mut pending: PendingException64) -> bool {
        if pending.depth >= MAX_EXCEPTION_DEPTH {
            return false;
        }
        let Some(handler) = self.vectored_handlers.get(pending.vectored_index).copied() else {
            return false;
        };
        if self.memory.fetch(handler, 1).is_err() {
            return false;
        }
        let pointers = EXCEPTION64_SCRATCH_BASE + 0x3e0;
        let _ = self
            .memory
            .write_force(EXCEPTION64_RECORD_BASE, &pending.code.to_le_bytes());
        let _ = self.memory.write_force(
            EXCEPTION64_RECORD_BASE + 0x10,
            &pending.address.to_le_bytes(),
        );
        let _ = self.memory.write_force(
            EXCEPTION64_CONTEXT_BASE + 0xf8,
            &pending.resume_rip.to_le_bytes(),
        );
        let _ = self.memory.write_force(
            EXCEPTION64_CONTEXT_BASE + 0x98,
            &pending.saved_cpu.rsp().to_le_bytes(),
        );
        let _ = self
            .memory
            .write_force(pointers, &EXCEPTION64_RECORD_BASE.to_le_bytes());
        let _ = self
            .memory
            .write_force(pointers + 8, &EXCEPTION64_CONTEXT_BASE.to_le_bytes());
        if self
            .cpu
            .push(&mut self.memory, EXCEPTION64_RETURN_SENTINEL)
            .is_err()
        {
            return false;
        }
        self.cpu.gpr[1] = pointers;
        let event_index = self.exceptions.len();
        let runtime = self.unwind_functions.iter().find(|entry| {
            pending.address >= entry.begin_address && pending.address < entry.end_address
        });
        self.exceptions.push(ExceptionEvent {
            sequence: event_index as u64,
            code: pending.code,
            name: pending.name.clone(),
            address: pending.address,
            handler: Some(handler),
            establisher_frame: Some(pending.saved_cpu.rsp()),
            disposition: None,
            outcome: if runtime.is_some() {
                "dispatched_via_vectored_handler_with_runtime_function".into()
            } else {
                "dispatched_via_vectored_handler".into()
            },
        });
        self.timeline.push(TimelineEvent {
            sequence: self.timeline.len() as u64,
            instruction: self.instruction_count,
            virtual_time_ms: self.virtual_time_ms,
            category: "exception".into(),
            operation: "x64_vectored_dispatch".into(),
            subject: format!(
                "{} 0x{:016x} -> 0x{handler:016x}",
                pending.name, pending.address
            ),
            source_api: "x64 exception dispatcher".into(),
        });
        if let Some(entry) = runtime {
            self.system.push(SystemEvent {
                category: "exception".into(),
                operation: "runtime_function_lookup".into(),
                target: format!("0x{:016x}", pending.address),
                detail: format!(
                    "matched 0x{:016x}-0x{:016x}, unwind info 0x{:016x}",
                    entry.begin_address, entry.end_address, entry.unwind_info_address
                ),
                result: entry.unwind_info_address,
            });
        }
        pending.event_index = event_index;
        self.cpu.rip = handler;
        self.pending_exception = Some(pending);
        true
    }

    fn complete_exception_handler(&mut self) {
        let Some(mut pending) = self.pending_exception.take() else {
            return;
        };
        let disposition = self.cpu.gpr[0] as i32;
        if let Some(event) = self.exceptions.get_mut(pending.event_index) {
            event.disposition = Some(disposition);
        }
        if disposition == -1 {
            self.cpu = pending.saved_cpu;
            self.cpu.rip = pending.resume_rip;
            if let Some(event) = self.exceptions.get_mut(pending.event_index) {
                event.outcome = "continued_execution".into();
            }
        } else if disposition == 0 && pending.vectored_index + 1 < self.vectored_handlers.len() {
            if let Some(event) = self.exceptions.get_mut(pending.event_index) {
                event.outcome = "continued_search".into();
            }
            pending.vectored_index += 1;
            pending.depth += 1;
            let fallback = pending.fallback.clone();
            if !self.begin_exception_handler(pending) {
                self.termination = Some(fallback);
            }
        } else {
            if let Some(event) = self.exceptions.get_mut(pending.event_index) {
                event.outcome = "unhandled".into();
            }
            self.termination = Some(pending.fallback);
        }
    }

    fn artifact_origin(
        &self,
        api: &str,
        trigger: &str,
        address: Option<u64>,
        path: Option<String>,
    ) -> ArtifactOrigin {
        ArtifactOrigin {
            api: api.into(),
            instruction: self.instruction_count,
            virtual_time_ms: self.virtual_time_ms,
            timeline_sequence: self.timeline.len().checked_sub(1).map(|value| value as u64),
            trigger: trigger.into(),
            address,
            path,
        }
    }

    fn capture_memory_region(&mut self, address: u64, trigger: &str, api: &str, force: bool) {
        let Some((start, name, permissions, executable, bytes, size)) = self
            .memory
            .dirty_regions()
            .find(|region| {
                address >= region.start
                    && address < region.start.saturating_add(region.data.len() as u64)
            })
            .map(|region| {
                (
                    region.start,
                    region.name.to_owned(),
                    region.permissions.display(),
                    region.permissions.execute,
                    region.data[..region.data.len().min(MAX_ARTIFACT_BYTES)].to_vec(),
                    region.data.len() as u64,
                )
            })
        else {
            return;
        };
        let origin = self.artifact_origin(api, trigger, Some(start), None);
        let kind = if executable {
            ArtifactKind::Memory
        } else {
            ArtifactKind::Configuration
        };
        let entry_point_overwrite = self.memory.was_written(self.entry_point)
            && self.entry_point >= start
            && self.entry_point < start + size;
        let executed = trigger == "dynamic_execution";
        let executable_heap = start >= HEAP64_BASE && executable;
        let generation_relevant = entry_point_overwrite
            || executable_heap
            || trigger.contains("executable_transition")
            || (executed && self.memory.was_written(address));
        if executed && !generation_relevant {
            return;
        }
        if let Some(artifact_id) = self.artifacts.capture(
            ArtifactCapture {
                kind,
                name,
                trigger,
                address: Some(start),
                path: None,
                permissions: Some(permissions.clone()),
                force,
            },
            &bytes,
            origin,
        ) && generation_relevant
        {
            self.generations.observe(GenerationObservation {
                artifact_id,
                region_base: start,
                size,
                instruction: self.instruction_count,
                virtual_time_ms: self.virtual_time_ms,
                trigger,
                permissions,
                executed,
                entry_point_overwrite,
                executable_heap,
                execution_address: (executed && self.memory.was_written(address))
                    .then_some(address),
            });
        }
    }

    fn capture_final_artifacts(&mut self) {
        let regions: Vec<_> = self
            .memory
            .dirty_regions()
            .map(|region| region.start)
            .collect();
        for address in regions {
            self.capture_memory_region(address, "final_dirty_region", "finalize", false);
        }
        let files: Vec<_> = self
            .windows
            .file_snapshots()
            .map(|(path, bytes)| (path.to_owned(), bytes.to_vec()))
            .collect();
        for (path, bytes) in files {
            let origin = self.artifact_origin(
                "virtual_filesystem",
                "virtual_file",
                None,
                Some(path.clone()),
            );
            self.artifacts.capture(
                ArtifactCapture {
                    kind: ArtifactKind::VirtualFile,
                    name: path.clone(),
                    trigger: "virtual_file",
                    address: None,
                    path: Some(path),
                    permissions: None,
                    force: true,
                },
                &bytes,
                origin,
            );
        }
    }

    fn start_next_target(&mut self) -> Result<(), DynamicError> {
        self.cpu.set_rsp(STACK64_TOP);
        self.cpu.gpr[5] = STACK64_TOP;
        if let Some(callback) = self.tls_callbacks.pop_front() {
            self.cpu.gpr[1] = self.image_base;
            self.cpu.gpr[2] = 1;
            self.cpu.gpr[8] = 0;
            self.cpu.push(&mut self.memory, TLS64_RETURN_SENTINEL)?;
            self.cpu.rip = callback;
        } else {
            self.cpu.push(&mut self.memory, ENTRY64_RETURN_SENTINEL)?;
            self.cpu.rip = self.entry_point;
        }
        Ok(())
    }

    fn execute(&mut self) {
        while self.termination.is_none() && self.instruction_count < self.options.max_instructions {
            if self.pending_exception.is_none() && self.instruction_count >= self.next_thread_switch
            {
                self.schedule_next_thread(true);
                self.next_thread_switch = self.next_thread_switch.saturating_add(THREAD_QUANTUM);
            }
            if self.cpu.rip == THREAD64_RETURN_SENTINEL {
                self.finish_current_thread(self.cpu.gpr[0] as u32);
                if !self.schedule_next_thread(false) {
                    self.termination = Some(Termination::ReturnedFromEntryPoint);
                }
                continue;
            }
            if self.cpu.rip == ENTRY64_RETURN_SENTINEL {
                self.finish_current_thread(self.cpu.gpr[0] as u32);
                if !self.schedule_next_thread(false) {
                    self.termination = Some(Termination::ReturnedFromEntryPoint);
                }
                continue;
            }
            if self.cpu.rip == TLS64_RETURN_SENTINEL {
                if let Err(error) = self.start_next_target() {
                    self.termination = Some(memory_termination(error, "TLS callback"));
                }
                continue;
            }
            if self.cpu.rip == EXCEPTION64_RETURN_SENTINEL {
                self.complete_exception_handler();
                continue;
            }
            if let Some(import) = self.imports.get(&self.cpu.rip).cloned() {
                if self.api_calls.len() >= crate::HARD_MAX_API_EVENTS {
                    self.truncated = true;
                    self.termination = Some(Termination::InstructionLimit);
                    break;
                }
                if let Err(error) = self.handle_api(import) {
                    self.termination = Some(memory_termination(error, "x64 api"));
                }
                continue;
            }
            let address = self.cpu.rip;
            self.capture_memory_region(address, "dynamic_execution", "instruction", false);
            self.unique_instruction_addresses.insert(address);
            let bytes = match self.memory.fetch(address, 15) {
                Ok(bytes) => bytes.to_vec(),
                Err(error) => {
                    let fallback = memory_termination(error, "x64 execute");
                    if !self.dispatch_exception(
                        0xc000_0005,
                        "access_violation",
                        address,
                        address,
                        fallback.clone(),
                    ) {
                        self.termination = Some(fallback);
                        break;
                    }
                    continue;
                }
            };
            let mut decoder = Decoder::with_ip(64, &bytes, address, DecoderOptions::NONE);
            let instruction = decoder.decode();
            if instruction.code() == Code::INVALID {
                self.invalid_instruction_count += 1;
                self.first_unsupported.get_or_insert(InstructionDiagnostic {
                    address,
                    instruction: "invalid x64 instruction".into(),
                    bytes: hex::encode(&bytes),
                    nearby_trace: self.instructions.iter().rev().take(4).cloned().collect(),
                });
                let fallback = Termination::InvalidInstruction { address };
                if !self.dispatch_exception(
                    0xc000_001d,
                    "illegal_instruction",
                    address,
                    address.wrapping_add(1),
                    fallback.clone(),
                ) {
                    self.termination = Some(fallback);
                    break;
                }
                continue;
            }
            let length = instruction.len().min(bytes.len());
            if self.instructions.len() < self.options.max_trace_events {
                self.instructions.push(InstructionEvent {
                    index: self.instruction_count,
                    address,
                    bytes: hex::encode(&bytes[..length]),
                    text: instruction.to_string(),
                });
            } else {
                self.truncated = true;
            }
            self.cpu.rip = instruction.next_ip();
            self.instruction_count += 1;
            if let Some(thread) = self.thread_states.get_mut(self.current_thread) {
                thread.instruction_count = thread.instruction_count.saturating_add(1);
            }
            if let Err(error) = self.execute_instruction(&instruction) {
                self.warnings.push(error.to_string());
                self.first_unsupported.get_or_insert(InstructionDiagnostic {
                    address,
                    instruction: instruction.to_string(),
                    bytes: hex::encode(&bytes[..length]),
                    nearby_trace: self.instructions.iter().rev().take(4).cloned().collect(),
                });
                let fallback = match error {
                    DynamicError::MemoryRead { .. }
                    | DynamicError::MemoryWrite { .. }
                    | DynamicError::MemoryExecute { .. } => {
                        memory_termination(error, "x64 instruction")
                    }
                    _ => Termination::UnsupportedInstruction {
                        address,
                        instruction: instruction.to_string(),
                    },
                };
                let (code, name) = if matches!(fallback, Termination::MemoryFault { .. }) {
                    (0xc000_0005, "access_violation")
                } else {
                    (0xc000_001d, "illegal_instruction")
                };
                if !self.dispatch_exception(code, name, address, self.cpu.rip, fallback.clone()) {
                    self.termination = Some(fallback);
                }
            }
        }
        if self.termination.is_none() {
            self.termination = Some(Termination::InstructionLimit);
        }
    }

    fn execute_instruction(&mut self, instruction: &Instruction) -> Result<(), DynamicError> {
        use Mnemonic::*;
        match instruction.mnemonic() {
            Mov => {
                let (value, _) = self.cpu.read_operand(&self.memory, instruction, 1)?;
                self.cpu
                    .write_operand(&mut self.memory, instruction, 0, value)?;
            }
            Lea => {
                let address = self.cpu.effective_address(instruction)?;
                self.cpu
                    .write_operand(&mut self.memory, instruction, 0, address)?;
            }
            Movzx => {
                let (value, _) = self.cpu.read_operand(&self.memory, instruction, 1)?;
                self.cpu
                    .write_operand(&mut self.memory, instruction, 0, value)?;
            }
            Movsx | Movsxd => {
                let (value, size) = self.cpu.read_operand(&self.memory, instruction, 1)?;
                let shift = 64usize.saturating_sub(size);
                let value = ((value << shift) as i64 >> shift) as u64;
                self.cpu
                    .write_operand(&mut self.memory, instruction, 0, value)?;
            }
            Push => {
                let (value, _) = self.cpu.read_operand(&self.memory, instruction, 0)?;
                self.cpu.push(&mut self.memory, value)?;
            }
            Pop => {
                let value = self.cpu.pop(&self.memory)?;
                self.cpu
                    .write_operand(&mut self.memory, instruction, 0, value)?;
            }
            Call => {
                let (target, _) = self.cpu.read_operand(&self.memory, instruction, 0)?;
                self.cpu.push(&mut self.memory, self.cpu.rip)?;
                self.cpu.rip = target;
            }
            Ret => {
                self.cpu.rip = self.cpu.pop(&self.memory)?;
                if instruction.op_count() > 0 {
                    self.cpu.set_rsp(
                        self.cpu
                            .rsp()
                            .wrapping_add(instruction.immediate16() as u64),
                    );
                }
            }
            Leave => {
                self.cpu.set_rsp(self.cpu.gpr[5]);
                self.cpu.gpr[5] = self.cpu.pop(&self.memory)?;
            }
            Add | Sub | And | Or | Xor => {
                let (left, size) = self.cpu.read_operand(&self.memory, instruction, 0)?;
                let (right, _) = self.cpu.read_operand(&self.memory, instruction, 1)?;
                let result = match instruction.mnemonic() {
                    Add => left.wrapping_add(right),
                    Sub => left.wrapping_sub(right),
                    And => left & right,
                    Or => left | right,
                    _ => left ^ right,
                };
                match instruction.mnemonic() {
                    Add => self.cpu.set_add_flags(left, right, result, size),
                    Sub => self.cpu.set_sub_flags(left, right, result, size),
                    _ => self.cpu.set_logic_flags(result, size),
                }
                self.cpu
                    .write_operand(&mut self.memory, instruction, 0, result)?;
            }
            Cmp | Test => {
                let (left, size) = self.cpu.read_operand(&self.memory, instruction, 0)?;
                let (right, _) = self.cpu.read_operand(&self.memory, instruction, 1)?;
                if instruction.mnemonic() == Cmp {
                    self.cpu
                        .set_sub_flags(left, right, left.wrapping_sub(right), size);
                } else {
                    self.cpu.set_logic_flags(left & right, size);
                }
            }
            Inc | Dec => {
                let carry = self.cpu.cf;
                let (value, size) = self.cpu.read_operand(&self.memory, instruction, 0)?;
                let result = if instruction.mnemonic() == Inc {
                    value.wrapping_add(1)
                } else {
                    value.wrapping_sub(1)
                };
                if instruction.mnemonic() == Inc {
                    self.cpu.set_add_flags(value, 1, result, size);
                } else {
                    self.cpu.set_sub_flags(value, 1, result, size);
                }
                self.cpu.cf = carry;
                self.cpu
                    .write_operand(&mut self.memory, instruction, 0, result)?;
            }
            Not | Neg => {
                let (value, size) = self.cpu.read_operand(&self.memory, instruction, 0)?;
                let result = if instruction.mnemonic() == Not {
                    !value
                } else {
                    0u64.wrapping_sub(value)
                };
                if instruction.mnemonic() == Neg {
                    self.cpu.set_sub_flags(0, value, result, size);
                }
                self.cpu
                    .write_operand(&mut self.memory, instruction, 0, result)?;
            }
            Jmp => self.cpu.rip = self.cpu.read_operand(&self.memory, instruction, 0)?.0,
            Je | Jne | Ja | Jae | Jb | Jbe | Jg | Jge | Jl | Jle | Js | Jns | Jo | Jno | Jp
            | Jnp => {
                if self.condition(instruction.mnemonic()) {
                    self.cpu.rip = instruction.near_branch_target();
                }
            }
            Cqo => {
                self.cpu.gpr[2] = if (self.cpu.gpr[0] as i64) < 0 {
                    u64::MAX
                } else {
                    0
                }
            }
            Cdq => {
                let value = if (self.cpu.gpr[0] as u32 as i32) < 0 {
                    u32::MAX
                } else {
                    0
                };
                self.cpu
                    .write_register(iced_x86::Register::EDX, value.into())?;
            }
            Nop | Endbr64 => {}
            Int3 => {
                let address = instruction.ip();
                let fallback = Termination::Halted;
                if !self.dispatch_exception(
                    0x8000_0003,
                    "breakpoint",
                    address,
                    self.cpu.rip,
                    fallback.clone(),
                ) {
                    self.termination = Some(fallback);
                }
            }
            Hlt => self.termination = Some(Termination::Halted),
            _ => {
                return Err(DynamicError::UnsupportedOperand(format!(
                    "x64 {}",
                    instruction
                )));
            }
        }
        Ok(())
    }

    fn condition(&self, mnemonic: Mnemonic) -> bool {
        match mnemonic {
            Mnemonic::Je => self.cpu.zf,
            Mnemonic::Jne => !self.cpu.zf,
            Mnemonic::Ja => !self.cpu.cf && !self.cpu.zf,
            Mnemonic::Jae => !self.cpu.cf,
            Mnemonic::Jb => self.cpu.cf,
            Mnemonic::Jbe => self.cpu.cf || self.cpu.zf,
            Mnemonic::Jg => !self.cpu.zf && self.cpu.sf == self.cpu.of,
            Mnemonic::Jge => self.cpu.sf == self.cpu.of,
            Mnemonic::Jl => self.cpu.sf != self.cpu.of,
            Mnemonic::Jle => self.cpu.zf || self.cpu.sf != self.cpu.of,
            Mnemonic::Js => self.cpu.sf,
            Mnemonic::Jns => !self.cpu.sf,
            Mnemonic::Jo => self.cpu.of,
            Mnemonic::Jno => !self.cpu.of,
            Mnemonic::Jp => self.cpu.pf,
            Mnemonic::Jnp => !self.cpu.pf,
            _ => false,
        }
    }

    fn load_module(&mut self, requested: String, source_api: &str) -> u64 {
        let module = if requested.trim().is_empty() {
            "dynamic.dll".to_owned()
        } else {
            requested.trim().to_owned()
        };
        if let Some(handle) = self.windows.module_handle(&module) {
            return u64::from(handle);
        }
        let Some(handle) = self.windows.allocate(HandleResource::Module {
            name: module.clone(),
        }) else {
            return 0;
        };
        self.system.push(SystemEvent {
            category: "loader".into(),
            operation: "load_module".into(),
            target: module,
            detail: format!("Synthetic module handle created by {source_api}"),
            result: u64::from(handle),
        });
        u64::from(handle)
    }

    fn resolve_dynamic_api(&mut self, module_handle: u64, symbol: String, source_api: &str) -> u64 {
        let module = if module_handle == self.image_base {
            "sample64.exe".to_owned()
        } else {
            self.windows
                .module_name(module_handle as u32)
                .unwrap_or("dynamic.dll")
                .to_owned()
        };
        if let Some((address, _)) = self.imports.iter().find(|(address, import)| {
            **address >= DYNAMIC_API64_BASE
                && import.module.eq_ignore_ascii_case(&module)
                && import.name == symbol
        }) {
            return *address;
        }
        if self.dynamic_api_resolutions >= MAX_DYNAMIC_API64_STUBS {
            self.truncated = true;
            return 0;
        }
        let stub = self.dynamic_api_next;
        self.dynamic_api_next = self.dynamic_api_next.saturating_add(0x100);
        let api_signature = crate::api::signature(&symbol);
        self.imports.insert(
            stub,
            ApiImport {
                module: module.clone(),
                name: symbol.clone(),
                argument_count: api_signature.argument_count,
            },
        );
        self.dynamic_api_resolutions += 1;
        self.system.push(SystemEvent {
            category: "loader".into(),
            operation: "resolve_export".into(),
            target: format!("{module}!{symbol}"),
            detail: format!("Emulator-owned x64 API stub created by {source_api}"),
            result: stub,
        });
        stub
    }

    fn read_ansi_string64(&self, descriptor: u64, maximum: usize) -> String {
        if descriptor == 0 {
            return String::new();
        }
        let length = self.memory.read_u16(descriptor).unwrap_or(0) as usize;
        let pointer = self.memory.read_u64(descriptor + 8).unwrap_or(0);
        let length = length.min(maximum);
        String::from_utf8_lossy(self.memory.read(pointer, length).unwrap_or_default()).into_owned()
    }

    fn read_unicode_string64(&self, descriptor: u64, maximum_units: usize) -> String {
        if descriptor == 0 {
            return String::new();
        }
        let byte_length = self.memory.read_u16(descriptor).unwrap_or(0) as usize;
        let pointer = self.memory.read_u64(descriptor + 8).unwrap_or(0);
        let units = (byte_length / 2).min(maximum_units);
        self.memory.read_wide_string(pointer, units)
    }

    fn handle_api(&mut self, import: ApiImport) -> Result<(), DynamicError> {
        let return_address = self.cpu.pop(&self.memory)?;
        let args = x64_api_arguments(&self.cpu, &self.memory, import.argument_count)?;
        let name = normalize_name(&import.name);
        self.generations
            .record_runtime_import(return_address, &import.module, &import.name);
        self.unique_api_names.insert(name.clone());
        let supported = matches!(
            name.as_str(),
            "gettickcount"
                | "gettickcount64"
                | "getcurrentprocess"
                | "getcurrentprocessid"
                | "getcurrentthreadid"
                | "getcommandlinea"
                | "getcommandlinew"
                | "getmodulehandlea"
                | "getmodulehandlew"
                | "loadlibrarya"
                | "loadlibraryw"
                | "getprocaddress"
                | "ldrloaddll"
                | "ldrgetprocedureaddress"
                | "rtlmovememory"
                | "rtlzeromemory"
                | "ntdelayexecution"
                | "ntqueryinformationprocess"
                | "ntallocatevirtualmemory"
                | "ntprotectvirtualmemory"
                | "ntreadvirtualmemory"
                | "ntwritevirtualmemory"
                | "isdebuggerpresent"
                | "sleep"
                | "winexec"
                | "createprocessa"
                | "virtualalloc"
                | "virtualprotect"
                | "closehandle"
                | "createfilea"
                | "writefile"
                | "readfile"
                | "regopenkeyexa"
                | "regcreatekeyexa"
                | "regsetvalueexa"
                | "regqueryvalueexa"
                | "internetopena"
                | "internetopenurla"
                | "internetreadfile"
                | "createthread"
                | "exitthread"
                | "addvectoredexceptionhandler"
                | "removevectoredexceptionhandler"
                | "raiseexception"
                | "exitprocess"
        );
        if supported {
            self.modeled_api_calls += 1;
        } else {
            self.unmodeled_api_calls += 1;
        }
        let (result, summary, category, operation, subject) = match name.as_str() {
            "gettickcount" | "gettickcount64" => (
                if name == "gettickcount" {
                    self.virtual_time_ms as u32 as u64
                } else {
                    self.virtual_time_ms
                },
                "Returned deterministic x64 virtual tick count".into(),
                "api".into(),
                "query".into(),
                "virtual time".into(),
            ),
            "getcurrentprocess" => (
                0xffff_ffff,
                "Returned synthetic current-process pseudo handle".into(),
                "process".into(),
                "query".into(),
                "current process".into(),
            ),
            "getcurrentprocessid" => (
                1337,
                "Returned synthetic process ID".into(),
                "process".into(),
                "query".into(),
                "pid 1337".into(),
            ),
            "getcurrentthreadid" => (
                u64::from(
                    self.thread_states
                        .get(self.current_thread)
                        .map_or(1, |thread| thread.tid),
                ),
                "Returned synthetic thread ID".into(),
                "thread".into(),
                "query".into(),
                "tid 1".into(),
            ),
            "getcommandlinea" => (
                COMMAND_LINE64_A,
                "Returned synthetic x64 command line".into(),
                "process".into(),
                "query".into(),
                "sample64.exe".into(),
            ),
            "getcommandlinew" => {
                let wide = COMMAND_LINE64_A + 0x400;
                let bytes: Vec<u8> = "sample64.exe\0"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect();
                let _ = self.memory.write_force(wide, &bytes);
                (
                    wide,
                    "Returned synthetic UTF-16 x64 command line".into(),
                    "process".into(),
                    "query".into(),
                    "sample64.exe".into(),
                )
            }
            "getmodulehandlea" | "getmodulehandlew" => {
                let pointer = args.first().copied().unwrap_or(0);
                let module = if pointer == 0 {
                    String::new()
                } else if name.ends_with('w') {
                    self.memory.read_wide_string(pointer, 260)
                } else {
                    self.memory.read_c_string(pointer, 260)
                };
                let handle = if pointer == 0 {
                    self.image_base
                } else {
                    self.load_module(module.clone(), &import.name)
                };
                (
                    handle,
                    if pointer == 0 {
                        "Returned PE64 image-base module handle".into()
                    } else {
                        format!("Returned synthetic module handle for {module}")
                    },
                    "loader".into(),
                    "get_module".into(),
                    if module.is_empty() {
                        "sample64.exe".into()
                    } else {
                        module
                    },
                )
            }
            "loadlibrarya" | "loadlibraryw" => {
                let pointer = args.first().copied().unwrap_or(0);
                let module = if name.ends_with('w') {
                    self.memory.read_wide_string(pointer, 260)
                } else {
                    self.memory.read_c_string(pointer, 260)
                };
                let handle = self.load_module(module.clone(), &import.name);
                (
                    handle,
                    format!("Loaded synthetic x64 module {module}"),
                    "loader".into(),
                    "load_module".into(),
                    module,
                )
            }
            "getprocaddress" => {
                let module_handle = args.first().copied().unwrap_or(0);
                let symbol_pointer = args.get(1).copied().unwrap_or(0);
                let symbol = if symbol_pointer <= 0xffff {
                    format!("ordinal:{symbol_pointer}")
                } else {
                    self.memory.read_c_string(symbol_pointer, 260)
                };
                let stub = self.resolve_dynamic_api(module_handle, symbol.clone(), &import.name);
                (
                    stub,
                    format!("Resolved synthetic x64 export {symbol}"),
                    "loader".into(),
                    "resolve_export".into(),
                    symbol,
                )
            }
            "ldrloaddll" => {
                let descriptor = args.get(2).copied().unwrap_or(0);
                let output = args.get(3).copied().unwrap_or(0);
                let module = self.read_unicode_string64(descriptor, 260);
                let handle = self.load_module(module.clone(), &import.name);
                if output != 0 {
                    let _ = self.memory.write_u64(output, handle);
                }
                (
                    if handle == 0 { 0xc000_0001 } else { 0 },
                    format!("LdrLoadDll mapped synthetic module {module}"),
                    "loader".into(),
                    "load_module".into(),
                    module,
                )
            }
            "ldrgetprocedureaddress" => {
                let module_handle = args.first().copied().unwrap_or(0);
                let descriptor = args.get(1).copied().unwrap_or(0);
                let ordinal = args.get(2).copied().unwrap_or(0);
                let output = args.get(3).copied().unwrap_or(0);
                let symbol = if descriptor == 0 {
                    format!("ordinal:{ordinal}")
                } else {
                    self.read_ansi_string64(descriptor, 260)
                };
                let stub = self.resolve_dynamic_api(module_handle, symbol.clone(), &import.name);
                if output != 0 {
                    let _ = self.memory.write_u64(output, stub);
                }
                (
                    if stub == 0 { 0xc000_0001 } else { 0 },
                    format!("LdrGetProcedureAddress resolved {symbol}"),
                    "loader".into(),
                    "resolve_export".into(),
                    symbol,
                )
            }
            "isdebuggerpresent" => (
                u64::from(self.environment.debugger_present),
                "Returned deterministic debugger state".into(),
                "environment".into(),
                "query".into(),
                "debugger".into(),
            ),
            "sleep" => {
                let delay = args.first().copied().unwrap_or(0).min(60_000);
                self.virtual_time_ms = self.virtual_time_ms.saturating_add(delay);
                (
                    0,
                    format!("Advanced virtual time by {delay} ms"),
                    "time".into(),
                    "sleep".into(),
                    format!("{delay} ms"),
                )
            }
            "winexec" => {
                let pointer = args.first().copied().unwrap_or(0);
                let command = self.memory.read_c_string(pointer, 2_048);
                self.provenance.observe(
                    pointer,
                    command.len(),
                    ProvenanceSinkKind::ProcessCommand,
                    command.clone(),
                    "WinExec",
                    self.instruction_count,
                );
                self.processes.push(ProcessEvent {
                    operation: "execute".into(),
                    command: command.clone(),
                    synthetic_result: "Captured only; no host process created".into(),
                });
                (
                    33,
                    format!("Captured x64 process execution request: {command}"),
                    "process".into(),
                    "execute".into(),
                    command,
                )
            }
            "createprocessa" => {
                let pointer = args
                    .get(1)
                    .copied()
                    .filter(|value| *value != 0)
                    .unwrap_or_else(|| args.first().copied().unwrap_or(0));
                let command = self.memory.read_c_string(pointer, 2_048);
                self.provenance.observe(
                    pointer,
                    command.len(),
                    ProvenanceSinkKind::ProcessCommand,
                    command.clone(),
                    "CreateProcessA",
                    self.instruction_count,
                );
                self.processes.push(ProcessEvent {
                    operation: "create".into(),
                    command: command.clone(),
                    synthetic_result: "Captured only; no host process created".into(),
                });
                (
                    1,
                    format!("Captured x64 process creation request: {command}"),
                    "process".into(),
                    "create".into(),
                    command,
                )
            }
            "virtualalloc" => {
                let requested = args.first().copied().unwrap_or(0);
                let size = args.get(1).copied().unwrap_or(0).clamp(1, 16 * 1024 * 1024) as usize;
                let address = if requested == 0 {
                    let value = self.heap_next;
                    self.heap_next = self
                        .heap_next
                        .saturating_add(align_page(size) as u64 + 0x1000);
                    value
                } else {
                    requested
                };
                let permissions = protection64(args.get(3).copied().unwrap_or(0x04) as u32);
                let result = if self
                    .memory
                    .map(address, align_page(size), permissions, "x64 VirtualAlloc")
                    .is_ok()
                {
                    self.memory_events.push(MemoryEvent {
                        operation: "allocate".into(),
                        address,
                        size: size as u32,
                        permissions: permissions.display(),
                    });
                    address
                } else {
                    0
                };
                (
                    result,
                    format!("Allocated {size} x64 virtual bytes"),
                    "memory".into(),
                    "allocate".into(),
                    format!("0x{address:016x}"),
                )
            }
            "virtualprotect" => {
                let address = args.first().copied().unwrap_or(0);
                let size = args.get(1).copied().unwrap_or(0).max(1) as usize;
                let permissions = protection64(args.get(2).copied().unwrap_or(0x04) as u32);
                let ok = self
                    .memory
                    .set_permissions(address, size, permissions)
                    .is_ok();
                if ok {
                    self.memory_events.push(MemoryEvent {
                        operation: "protect".into(),
                        address,
                        size: size as u32,
                        permissions: permissions.display(),
                    });
                    if permissions.execute {
                        self.provenance.observe(
                            address,
                            size,
                            ProvenanceSinkKind::ExecutableMemory,
                            format!("0x{address:016x}"),
                            "VirtualProtect",
                            self.instruction_count,
                        );
                        self.capture_memory_region(
                            address,
                            "executable_transition",
                            "VirtualProtect",
                            true,
                        );
                    }
                }
                (
                    u64::from(ok),
                    format!("Changed x64 memory protection to {}", permissions.display()),
                    "memory".into(),
                    "protect".into(),
                    format!("0x{address:016x}"),
                )
            }
            "rtlmovememory" => {
                let destination = args.first().copied().unwrap_or(0);
                let source = args.get(1).copied().unwrap_or(0);
                let length = args.get(2).copied().unwrap_or(0).min(1024 * 1024) as usize;
                let bytes = self.memory.read(source, length)?.to_vec();
                self.memory.write(destination, &bytes)?;
                self.provenance.propagate(source, destination, length);
                (
                    destination,
                    format!("Copied {length} bounded x64 memory bytes"),
                    "memory".into(),
                    "copy".into(),
                    format!("0x{source:016x} -> 0x{destination:016x}"),
                )
            }
            "rtlzeromemory" => {
                let destination = args.first().copied().unwrap_or(0);
                let length = args.get(1).copied().unwrap_or(0).min(1024 * 1024) as usize;
                self.memory.write(destination, &vec![0; length])?;
                self.provenance.clear(destination, length);
                (
                    0,
                    format!("Zeroed {length} bounded x64 memory bytes"),
                    "memory".into(),
                    "zero".into(),
                    format!("0x{destination:016x}"),
                )
            }
            "ntdelayexecution" => {
                let interval = args.get(1).copied().unwrap_or(0);
                let ticks = self.memory.read_u64(interval).unwrap_or(0) as i64;
                let delay = ticks.unsigned_abs().saturating_div(10_000).min(86_400_000);
                self.virtual_time_ms = self.virtual_time_ms.saturating_add(delay);
                (
                    0,
                    format!("Advanced deterministic x64 clock by {delay} ms"),
                    "time".into(),
                    "native_delay".into(),
                    format!("{delay} ms"),
                )
            }
            "ntqueryinformationprocess" => {
                let output = args.get(2).copied().unwrap_or(0);
                let length = args.get(3).copied().unwrap_or(0).min(256) as usize;
                if output != 0 && length != 0 {
                    self.memory.write(output, &vec![0; length])?;
                }
                if let Some(return_length) = args.get(4).copied().filter(|value| *value != 0) {
                    self.memory.write_u32(return_length, length as u32)?;
                }
                (
                    0,
                    "Returned deterministic x64 process information".into(),
                    "process".into(),
                    "native_query".into(),
                    "current process".into(),
                )
            }
            "ntallocatevirtualmemory" => {
                let base_pointer = args.get(1).copied().unwrap_or(0);
                let size_pointer = args.get(3).copied().unwrap_or(0);
                let requested = self.memory.read_u64(base_pointer).unwrap_or(0);
                let size = self
                    .memory
                    .read_u64(size_pointer)
                    .unwrap_or(0)
                    .clamp(1, 16 * 1024 * 1024) as usize;
                let address = if requested == 0 {
                    let value = self.heap_next;
                    self.heap_next = self
                        .heap_next
                        .saturating_add(align_page(size) as u64 + 0x1000);
                    value
                } else {
                    requested
                };
                let permissions = protection64(args.get(5).copied().unwrap_or(0x04) as u32);
                let ok = self
                    .memory
                    .map(
                        address,
                        align_page(size),
                        permissions,
                        "x64 NtAllocateVirtualMemory",
                    )
                    .is_ok();
                if ok {
                    self.memory.write_u64(base_pointer, address)?;
                    self.memory
                        .write_u64(size_pointer, align_page(size) as u64)?;
                    self.memory_events.push(MemoryEvent {
                        operation: "native_allocate".into(),
                        address,
                        size: size as u32,
                        permissions: permissions.display(),
                    });
                }
                (
                    if ok { 0 } else { 0xc000_0017 },
                    format!("NtAllocateVirtualMemory reserved {size} synthetic bytes"),
                    "memory".into(),
                    "native_allocate".into(),
                    format!("0x{address:016x}"),
                )
            }
            "ntprotectvirtualmemory" => {
                let base_pointer = args.get(1).copied().unwrap_or(0);
                let size_pointer = args.get(2).copied().unwrap_or(0);
                let address = self.memory.read_u64(base_pointer).unwrap_or(0);
                let size = self.memory.read_u64(size_pointer).unwrap_or(0).max(1) as usize;
                let permissions = protection64(args.get(3).copied().unwrap_or(0x04) as u32);
                let ok = self
                    .memory
                    .set_permissions(address, size, permissions)
                    .is_ok();
                if let Some(old) = args.get(4).copied().filter(|value| *value != 0) {
                    self.memory.write_u32(old, 0x04)?;
                }
                if ok {
                    self.memory_events.push(MemoryEvent {
                        operation: "native_protect".into(),
                        address,
                        size: size as u32,
                        permissions: permissions.display(),
                    });
                    if permissions.execute {
                        self.capture_memory_region(
                            address,
                            "native_executable_transition",
                            "NtProtectVirtualMemory",
                            true,
                        );
                    }
                }
                (
                    if ok { 0 } else { 0xc000_0005 },
                    format!("NtProtectVirtualMemory set {}", permissions.display()),
                    "memory".into(),
                    "native_protect".into(),
                    format!("0x{address:016x}"),
                )
            }
            "ntreadvirtualmemory" | "ntwritevirtualmemory" => {
                let base = args.get(1).copied().unwrap_or(0);
                let buffer = args.get(2).copied().unwrap_or(0);
                let length = args.get(3).copied().unwrap_or(0).min(1024 * 1024) as usize;
                let (source, destination) = if name == "ntreadvirtualmemory" {
                    (base, buffer)
                } else {
                    (buffer, base)
                };
                let bytes = self.memory.read(source, length)?.to_vec();
                self.memory.write(destination, &bytes)?;
                self.provenance.propagate(source, destination, length);
                if let Some(written) = args.get(4).copied().filter(|value| *value != 0) {
                    self.memory.write_u64(written, length as u64)?;
                }
                (
                    0,
                    format!("Copied {length} bytes through {name}"),
                    "memory".into(),
                    if name == "ntreadvirtualmemory" {
                        "native_read"
                    } else {
                        "native_write"
                    }
                    .into(),
                    format!("0x{source:016x} -> 0x{destination:016x}"),
                )
            }
            "closehandle" => {
                let handle = args.first().copied().unwrap_or(0) as u32;
                self.network_runtime.close(handle);
                let closed = self.windows.close(handle);
                (
                    u64::from(closed),
                    format!("Closed synthetic handle 0x{handle:08x}"),
                    "handle".into(),
                    "close".into(),
                    format!("0x{handle:08x}"),
                )
            }
            "createfilea" => {
                let path = self
                    .memory
                    .read_c_string(args.first().copied().unwrap_or(0), 1_024);
                let handle = self.windows.open_file(path.clone()).unwrap_or(0);
                self.filesystem.push(FileEvent {
                    operation: "open".into(),
                    path: path.clone(),
                    size: None,
                    preview: None,
                });
                (
                    u64::from(handle),
                    format!("Opened virtual file {path}"),
                    "filesystem".into(),
                    "open".into(),
                    path,
                )
            }
            "writefile" => {
                let handle = args.first().copied().unwrap_or(0) as u32;
                let pointer = args.get(1).copied().unwrap_or(0);
                let requested = args.get(2).copied().unwrap_or(0).min(1024 * 1024) as usize;
                let bytes = self
                    .memory
                    .read(pointer, requested)
                    .unwrap_or_default()
                    .to_vec();
                let path = self
                    .windows
                    .file_path(handle)
                    .unwrap_or("unknown")
                    .to_owned();
                let written = self.windows.write_file(handle, &bytes);
                if let Some(output) = args.get(3).copied().filter(|value| *value != 0) {
                    let _ = self.memory.write(output, &(written as u32).to_le_bytes());
                }
                self.provenance.observe(
                    pointer,
                    written,
                    ProvenanceSinkKind::VirtualFile,
                    path.clone(),
                    "WriteFile",
                    self.instruction_count,
                );
                self.filesystem.push(FileEvent {
                    operation: "write".into(),
                    path: path.clone(),
                    size: Some(written as u32),
                    preview: Some(preview_bytes(&bytes[..written.min(bytes.len())])),
                });
                (
                    u64::from(written != 0),
                    format!("Wrote {written} bytes to virtual file {path}"),
                    "filesystem".into(),
                    "write".into(),
                    path,
                )
            }
            "readfile" => {
                let handle = args.first().copied().unwrap_or(0) as u32;
                let output = args.get(1).copied().unwrap_or(0);
                let requested = args.get(2).copied().unwrap_or(0).min(1024 * 1024) as usize;
                let path = self
                    .windows
                    .file_path(handle)
                    .unwrap_or("unknown")
                    .to_owned();
                let bytes = self.windows.read_file(handle, requested);
                let _ = self.memory.write(output, &bytes);
                if let Some(count) = args.get(3).copied().filter(|value| *value != 0) {
                    let _ = self
                        .memory
                        .write(count, &(bytes.len() as u32).to_le_bytes());
                }
                if !bytes.is_empty() {
                    self.provenance.source(
                        ProvenanceSourceKind::VirtualFile,
                        path.clone(),
                        output,
                        bytes.len(),
                        "ReadFile",
                        self.instruction_count,
                    );
                }
                self.filesystem.push(FileEvent {
                    operation: "read".into(),
                    path: path.clone(),
                    size: Some(bytes.len() as u32),
                    preview: Some(preview_bytes(&bytes)),
                });
                (
                    1,
                    format!("Read {} bytes from virtual file {path}", bytes.len()),
                    "filesystem".into(),
                    "read".into(),
                    path,
                )
            }
            "regopenkeyexa" | "regcreatekeyexa" => {
                let subkey = self
                    .memory
                    .read_c_string(args.get(1).copied().unwrap_or(0), 1_024);
                let key = format!("HKCU\\{subkey}");
                let handle = self
                    .windows
                    .allocate(HandleResource::Registry { key: key.clone() })
                    .unwrap_or(0);
                let output_index = if name == "regcreatekeyexa" { 7 } else { 4 };
                if let Some(output) = args.get(output_index).copied().filter(|value| *value != 0) {
                    let _ = self.memory.write(output, &handle.to_le_bytes());
                }
                self.registry.push(RegistryEvent {
                    operation: "open".into(),
                    key: key.clone(),
                    value: None,
                });
                (
                    0,
                    format!("Opened synthetic registry key {key}"),
                    "registry".into(),
                    "open".into(),
                    key,
                )
            }
            "regsetvalueexa" => {
                let handle = args.first().copied().unwrap_or(0) as u32;
                let value_name = self
                    .memory
                    .read_c_string(args.get(1).copied().unwrap_or(0), 512);
                let pointer = args.get(4).copied().unwrap_or(0);
                let size = args.get(5).copied().unwrap_or(0).min(1024 * 1024) as usize;
                let bytes = self.memory.read(pointer, size).unwrap_or_default().to_vec();
                let key = self
                    .windows
                    .registry_path(handle)
                    .unwrap_or("unknown")
                    .to_owned();
                let ok = self.windows.set_registry_value(handle, &value_name, &bytes);
                let target = format!("{key}\\{value_name}");
                self.provenance.observe(
                    pointer,
                    bytes.len(),
                    ProvenanceSinkKind::Persistence,
                    target.clone(),
                    "RegSetValueExA",
                    self.instruction_count,
                );
                self.registry.push(RegistryEvent {
                    operation: "set".into(),
                    key: target.clone(),
                    value: Some(preview_bytes(&bytes)),
                });
                if key.to_ascii_lowercase().contains("currentversion\\run") {
                    self.persistence.push(PersistenceEvent {
                        mechanism: "registry_run_key".into(),
                        operation: "set".into(),
                        target: target.clone(),
                        value: Some(preview_bytes(&bytes)),
                    });
                }
                (
                    if ok { 0 } else { 6 },
                    format!("Set synthetic registry value {target}"),
                    "registry".into(),
                    "set".into(),
                    target,
                )
            }
            "regqueryvalueexa" => {
                let handle = args.first().copied().unwrap_or(0) as u32;
                let value_name = self
                    .memory
                    .read_c_string(args.get(1).copied().unwrap_or(0), 512);
                let output = args.get(4).copied().unwrap_or(0);
                let size_pointer = args.get(5).copied().unwrap_or(0);
                let bytes = self
                    .windows
                    .registry_value(handle, &value_name)
                    .unwrap_or_default()
                    .to_vec();
                let _ = self.memory.write(output, &bytes);
                if size_pointer != 0 {
                    let _ = self
                        .memory
                        .write(size_pointer, &(bytes.len() as u32).to_le_bytes());
                }
                let key = self
                    .windows
                    .registry_path(handle)
                    .unwrap_or("unknown")
                    .to_owned();
                if !bytes.is_empty() {
                    self.provenance.source(
                        ProvenanceSourceKind::Registry,
                        format!("{key}\\{value_name}"),
                        output,
                        bytes.len(),
                        "RegQueryValueExA",
                        self.instruction_count,
                    );
                }
                self.registry.push(RegistryEvent {
                    operation: "query".into(),
                    key: key.clone(),
                    value: Some(value_name.clone()),
                });
                (
                    if bytes.is_empty() { 2 } else { 0 },
                    format!("Queried synthetic registry value {key}\\{value_name}"),
                    "registry".into(),
                    "query".into(),
                    key,
                )
            }
            "internetopena" => {
                let handle = self
                    .windows
                    .allocate(HandleResource::Internet {
                        label: "WinINet session".into(),
                    })
                    .unwrap_or(0);
                self.network_runtime.register_session(handle);
                (
                    u64::from(handle),
                    "Opened deterministic WinINet session".into(),
                    "network".into(),
                    "session".into(),
                    self.network_runtime.scenario_id().into(),
                )
            }
            "internetopenurla" => {
                let url = self
                    .memory
                    .read_c_string(args.get(1).copied().unwrap_or(0), 2_048);
                if self.environment.network_mode == NetworkMode::Offline {
                    (
                        0,
                        format!("Blocked synthetic request to {url} in offline profile"),
                        "network".into(),
                        "blocked".into(),
                        url,
                    )
                } else {
                    let handle = self
                        .windows
                        .allocate(HandleResource::Internet { label: url.clone() })
                        .unwrap_or(0);
                    self.network_runtime
                        .register_request(handle, "GET".into(), url.clone());
                    let hops = self.network_runtime.resolve_request(handle);
                    for hop in hops {
                        self.network_exchanges.push(NetworkExchange {
                            sequence: self.network_exchanges.len() as u64,
                            protocol: "http".into(),
                            operation: "GET".into(),
                            destination: hop.url,
                            request_headers: Vec::new(),
                            request_preview: None,
                            request_size: 0,
                            request_sha256: None,
                            response_status: Some(hop.status),
                            response_headers: hop.headers,
                            response_size: hop.body.len() as u64,
                            response_sha256: Some(hex::encode(Sha256::digest(&hop.body))),
                            artifact_id: None,
                            outcome: if hop.redirected {
                                "redirect"
                            } else {
                                "scripted"
                            }
                            .into(),
                        });
                    }
                    self.network.push(NetworkEvent {
                        operation: "request".into(),
                        destination: url.clone(),
                        size: None,
                        preview: None,
                        synthetic_result:
                            "Resolved from deterministic scenario; no host network used".into(),
                    });
                    (
                        u64::from(handle),
                        format!("Opened deterministic URL {url}"),
                        "network".into(),
                        "request".into(),
                        url,
                    )
                }
            }
            "internetreadfile" => {
                let handle = args.first().copied().unwrap_or(0) as u32;
                let output = args.get(1).copied().unwrap_or(0);
                let maximum = args.get(2).copied().unwrap_or(0).min(1024 * 1024) as usize;
                let bytes = self
                    .network_runtime
                    .read_response(handle, maximum)
                    .unwrap_or_default();
                let _ = self.memory.write(output, &bytes);
                if let Some(count) = args.get(3).copied().filter(|value| *value != 0) {
                    let _ = self
                        .memory
                        .write(count, &(bytes.len() as u32).to_le_bytes());
                }
                let destination = self
                    .windows
                    .describe(handle)
                    .unwrap_or_else(|| "scripted response".into());
                if !bytes.is_empty() {
                    self.provenance.source(
                        ProvenanceSourceKind::Network,
                        destination.clone(),
                        output,
                        bytes.len(),
                        "InternetReadFile",
                        self.instruction_count,
                    );
                    let origin = self.artifact_origin(
                        "InternetReadFile",
                        "network_download",
                        Some(output),
                        None,
                    );
                    let artifact_id = self.artifacts.capture(
                        ArtifactCapture {
                            kind: ArtifactKind::NetworkDownload,
                            name: "wininet-response.bin".into(),
                            trigger: "network_download",
                            address: Some(output),
                            path: None,
                            permissions: None,
                            force: true,
                        },
                        &bytes,
                        origin,
                    );
                    if let Some(exchange) = self.network_exchanges.last_mut() {
                        exchange.artifact_id = artifact_id;
                    }
                }
                self.network.push(NetworkEvent {
                    operation: "read".into(),
                    destination: destination.clone(),
                    size: Some(bytes.len() as u32),
                    preview: Some(preview_bytes(&bytes)),
                    synthetic_result: "Returned scripted bytes only".into(),
                });
                (
                    1,
                    format!("Read {} deterministic network bytes", bytes.len()),
                    "network".into(),
                    "read".into(),
                    destination,
                )
            }
            "createthread" => {
                let start = args.get(2).copied().unwrap_or(0);
                let parameter = args.get(3).copied().unwrap_or(0);
                let tid = self.create_guest_thread(start, parameter);
                if let Some(pointer) = args.get(5).copied().filter(|value| *value != 0) {
                    let _ = self.memory.write(pointer, &tid.to_le_bytes());
                }
                let handle = if tid == 0 {
                    0
                } else {
                    self.windows
                        .allocate(HandleResource::Thread { tid })
                        .unwrap_or(0)
                };
                (
                    u64::from(handle),
                    format!("Created deterministic x64 guest thread {tid} at 0x{start:016x}"),
                    "thread".into(),
                    "create".into(),
                    tid.to_string(),
                )
            }
            "exitthread" => {
                let code = args.first().copied().unwrap_or(0) as u32;
                self.thread_exit_requested = Some(code);
                (
                    0,
                    format!("Thread requested exit with code {code}"),
                    "thread".into(),
                    "exit".into(),
                    code.to_string(),
                )
            }
            "addvectoredexceptionhandler" => {
                let first = args.first().copied().unwrap_or(0) != 0;
                let handler = args.get(1).copied().unwrap_or(0);
                let valid = handler != 0
                    && self.memory.fetch(handler, 1).is_ok()
                    && self.vectored_handlers.len() < MAX_EXCEPTION_DEPTH;
                if valid {
                    if first {
                        self.vectored_handlers.insert(0, handler);
                    } else {
                        self.vectored_handlers.push(handler);
                    }
                }
                (
                    if valid { handler } else { 0 },
                    format!(
                        "{} x64 vectored handler 0x{handler:016x}",
                        if valid { "Registered" } else { "Rejected" }
                    ),
                    "exception".into(),
                    "register_handler".into(),
                    format!("0x{handler:016x}"),
                )
            }
            "removevectoredexceptionhandler" => {
                let handler = args.first().copied().unwrap_or(0);
                let removed = self
                    .vectored_handlers
                    .iter()
                    .position(|value| *value == handler)
                    .map(|index| self.vectored_handlers.remove(index))
                    .is_some();
                (
                    u64::from(removed),
                    format!(
                        "{} x64 vectored handler 0x{handler:016x}",
                        if removed { "Removed" } else { "Did not find" }
                    ),
                    "exception".into(),
                    "remove_handler".into(),
                    format!("0x{handler:016x}"),
                )
            }
            "raiseexception" => {
                let code = args.first().copied().unwrap_or(0xe000_0001) as u32;
                self.queued_exception = Some((code, "raised_exception".into()));
                (
                    0,
                    format!("Queued deterministic x64 exception 0x{code:08x}"),
                    "exception".into(),
                    "raise".into(),
                    format!("0x{code:08x}"),
                )
            }
            "exitprocess" => {
                let code = args.first().copied().unwrap_or(0) as u32;
                self.terminate_all_threads(code);
                self.termination = Some(Termination::ExitProcess { code });
                (
                    0,
                    format!("Captured x64 ExitProcess({code})"),
                    "process".into(),
                    "exit".into(),
                    code.to_string(),
                )
            }
            _ => (
                0,
                format!("Conservative x64 fallback for {}", import.name),
                "api".into(),
                "fallback".into(),
                import.name.clone(),
            ),
        };
        self.cpu.gpr[0] = result;
        self.cpu.rip = return_address;
        self.api_calls.push(ApiEvent {
            index: self.api_calls.len() as u64,
            instruction: self.instruction_count,
            module: import.module,
            name: import.name.clone(),
            arguments: args.iter().map(|value| format!("0x{value:016x}")).collect(),
            result,
            summary,
        });
        self.timeline.push(TimelineEvent {
            sequence: self.timeline.len() as u64,
            instruction: self.instruction_count,
            virtual_time_ms: self.virtual_time_ms,
            category,
            operation,
            subject,
            source_api: import.name.clone(),
        });
        self.record_snapshot(format!("api:{}", import.name), false);
        if let Some(code) = self.thread_exit_requested.take() {
            self.finish_current_thread(code);
            if !self.schedule_next_thread(false) {
                self.termination = Some(Termination::ReturnedFromEntryPoint);
            }
        }
        if let Some((code, exception_name)) = self.queued_exception.take() {
            let fallback = Termination::MemoryFault {
                address: return_address,
                operation: format!("unhandled x64 exception 0x{code:08x}"),
            };
            if !self.dispatch_exception(
                code,
                &exception_name,
                return_address,
                self.cpu.rip,
                fallback.clone(),
            ) {
                self.termination = Some(fallback);
            }
        }
        Ok(())
    }

    fn record_snapshot(&mut self, trigger: impl Into<String>, final_snapshot: bool) {
        if !final_snapshot && self.snapshots.len() >= MAX_SNAPSHOTS - 1 {
            self.snapshots_truncated = true;
            return;
        }
        if final_snapshot && self.snapshots.len() >= MAX_SNAPSHOTS {
            self.snapshots.pop();
            self.snapshots_truncated = true;
        }
        let behavior = self.processes.len()
            + self.filesystem.len()
            + self.registry.len()
            + self.network.len()
            + self.memory_events.len()
            + self.persistence.len();
        let events = SnapshotEventCounts {
            api_calls: self.api_calls.len(),
            processes: self.processes.len(),
            filesystem: self.filesystem.len(),
            registry: self.registry.len(),
            network: self.network.len(),
            memory: self.memory_events.len(),
            injection: 0,
            persistence: self.persistence.len(),
            provenance_flows: self.provenance.flow_count(),
        };
        let registers = SnapshotRegisters {
            rax: self.cpu.gpr[0],
            rbx: self.cpu.gpr[3],
            rcx: self.cpu.gpr[1],
            rdx: self.cpu.gpr[2],
            rsi: self.cpu.gpr[6],
            rdi: self.cpu.gpr[7],
            rbp: self.cpu.gpr[5],
            rsp: self.cpu.gpr[4],
            r8: self.cpu.gpr[8],
            r9: self.cpu.gpr[9],
            r10: self.cpu.gpr[10],
            r11: self.cpu.gpr[11],
            r12: self.cpu.gpr[12],
            r13: self.cpu.gpr[13],
            r14: self.cpu.gpr[14],
            r15: self.cpu.gpr[15],
            rip: self.cpu.rip,
            rflags: self.cpu.flags_value(),
        };
        let dirty_memory_regions = self.memory.dirty_regions().count();
        let mut hasher = Sha256::new();
        for value in [
            registers.rax,
            registers.rbx,
            registers.rcx,
            registers.rdx,
            registers.rsi,
            registers.rdi,
            registers.rbp,
            registers.rsp,
            registers.r8,
            registers.r9,
            registers.r10,
            registers.r11,
            registers.r12,
            registers.r13,
            registers.r14,
            registers.r15,
            registers.rip,
            registers.rflags,
            events.api_calls as u64,
            behavior as u64,
            dirty_memory_regions as u64,
        ] {
            hasher.update(value.to_le_bytes());
        }
        for region in self.memory.dirty_regions().take(MAX_DIRTY_REGIONS) {
            hasher.update(region.start.to_le_bytes());
            hasher.update(region.name.as_bytes());
            hasher.update(region.permissions.display().as_bytes());
            let head = region.data.len().min(SNAPSHOT_SAMPLE);
            hasher.update(&region.data[..head]);
            if region.data.len() > head {
                hasher.update(&region.data[region.data.len().saturating_sub(SNAPSHOT_SAMPLE)..]);
            }
        }
        self.snapshots.push(ExecutionSnapshot {
            sequence: self.snapshots.len() as u64,
            trigger: trigger.into(),
            instruction: self.instruction_count,
            virtual_time_ms: self.virtual_time_ms,
            registers,
            events,
            dirty_memory_regions,
            state_sha256: hex::encode(hasher.finalize()),
        });
    }

    fn build_findings(&self) -> Vec<DynamicFinding> {
        let mut findings = Vec::new();
        if !self.processes.is_empty() {
            findings.push(DynamicFinding {
                id: "process-execution".into(),
                title: "Process execution requested".into(),
                severity: DynamicSeverity::High,
                rationale: "The x64 sample requested a process operation; it was captured without host execution.".into(),
                evidence: self.processes.iter().map(|event| event.command.clone()).collect(),
            });
        }
        if findings.is_empty() {
            findings.push(DynamicFinding {
                id: "no-modeled-behavior".into(),
                title: "No modeled high-level behavior observed".into(),
                severity: DynamicSeverity::Info,
                rationale: "The bounded x64 path completed without a modeled behavior event."
                    .into(),
                evidence: vec![format!("{} instructions emulated", self.instruction_count)],
            });
        }
        findings
    }
}

fn align_page(size: usize) -> usize {
    size.saturating_add(0xfff) & !0xfff
}

fn protection64(value: u32) -> Permissions {
    Permissions {
        read: value != 0x01,
        write: matches!(value, 0x04 | 0x08 | 0x40 | 0x80),
        execute: matches!(value, 0x10 | 0x20 | 0x40 | 0x80),
    }
}

fn preview_bytes(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(160)])
        .chars()
        .map(|character| {
            if character.is_control() && !matches!(character, '\n' | '\r' | '\t') {
                '.'
            } else {
                character
            }
        })
        .collect()
}

fn memory_termination(error: DynamicError, operation: &str) -> Termination {
    match error {
        DynamicError::MemoryRead { address } => Termination::MemoryFault {
            address,
            operation: format!("{operation}: read"),
        },
        DynamicError::MemoryWrite { address } => Termination::MemoryFault {
            address,
            operation: format!("{operation}: write"),
        },
        DynamicError::MemoryExecute { address } => Termination::MemoryFault {
            address,
            operation: format!("{operation}: execute"),
        },
        _ => Termination::MemoryFault {
            address: 0,
            operation: error.to_string(),
        },
    }
}

fn x64_api_arguments(
    cpu: &Cpu64,
    memory: &Memory64,
    count: usize,
) -> Result<Vec<u64>, DynamicError> {
    let mut args = Vec::with_capacity(count);
    for index in 0..count {
        args.push(match index {
            0 => cpu.gpr[1],
            1 => cpu.gpr[2],
            2 => cpu.gpr[8],
            3 => cpu.gpr[9],
            // The return address has already been popped. RSP therefore points
            // at the caller's 32-byte shadow space; stack argument five is +0x20.
            _ => memory.read_u64(cpu.rsp().wrapping_add(0x20 + ((index - 4) * 8) as u64))?,
        });
    }
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_register_and_stack_arguments_with_the_microsoft_x64_abi() {
        let mut memory = Memory64::default();
        memory
            .map(0x1000, 0x1000, Permissions::READ_WRITE, "ABI stack")
            .unwrap();
        let mut cpu = Cpu64::default();
        cpu.gpr[1] = 1;
        cpu.gpr[2] = 2;
        cpu.gpr[8] = 3;
        cpu.gpr[9] = 4;
        cpu.set_rsp(0x1100);
        memory.write_u64(0x1120, 5).unwrap();
        memory.write_u64(0x1128, 6).unwrap();
        assert_eq!(
            x64_api_arguments(&cpu, &memory, 6).unwrap(),
            [1, 2, 3, 4, 5, 6]
        );
    }
}
