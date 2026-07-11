use crate::{
    ApiEvent, ArtifactKind, ArtifactOrigin, DynamicAnalysis, DynamicError, DynamicFinding,
    DynamicOptions, DynamicReport, DynamicSeverity, ExceptionEvent, ExecutionCoverage,
    ExecutionDiagnostics, ExecutionProfile, FileEvent, HARD_MAX_API_EVENTS, InjectionEvent,
    InstructionDiagnostic, InstructionEvent, MemoryEvent, NetworkEvent, NetworkMode,
    PersistenceEvent, ProcessEvent, RegistryEvent, Termination, ThreadEvent, ThreadSummary,
    TimelineEvent,
    api::{CallingConvention, normalize_name, signature},
    artifact::{ArtifactCapture, ArtifactStore, MAX_ARTIFACT_BYTES},
    cpu::Cpu,
    generation::{GenerationObservation, GenerationTracker},
    loader::{self, ApiImport, STACK_TOP},
    memory::{Memory, Permissions},
    windows::{HandleResource, VirtualWindows},
};
use iced_x86::{Code, Decoder, DecoderOptions, Instruction, Mnemonic, OpKind};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const ENTRY_RETURN_SENTINEL: u32 = 0xffff_fff0;
const TLS_RETURN_SENTINEL: u32 = 0xffff_ffe0;
const EXCEPTION_RETURN_SENTINEL: u32 = 0xffff_ffd0;
const THREAD_RETURN_SENTINEL: u32 = 0xffff_ffc0;
const HEAP_BASE: u32 = 0x1000_0000;
const DYNAMIC_API_BASE: u32 = 0x7100_0000;
const PROCESS_ENV_BASE: u32 = 0x2000_0000;
const COMMAND_LINE_A: u32 = PROCESS_ENV_BASE;
const COMMAND_LINE_W: u32 = PROCESS_ENV_BASE + 0x400;
const NETWORK_RESULT_BASE: u32 = PROCESS_ENV_BASE + 0x800;
const TEB_BASE: u32 = 0x7ffde000;
const PEB_BASE: u32 = 0x7ffdf000;
const EXCEPTION_SCRATCH_BASE: u32 = PROCESS_ENV_BASE + 0x1000;
const EXCEPTION_RECORD_BASE: u32 = EXCEPTION_SCRATCH_BASE;
const EXCEPTION_CONTEXT_BASE: u32 = EXCEPTION_SCRATCH_BASE + 0x100;
const MAX_EXCEPTION_EVENTS: usize = 128;
const MAX_SEH_DEPTH: usize = 16;
const MAX_GUEST_THREADS: usize = 64;
const MAX_THREAD_EVENTS: usize = 4_096;
const THREAD_QUANTUM: u64 = 100;
const THREAD_STACK_SIZE: usize = 64 * 1024;

pub(crate) fn run(
    _name: String,
    bytes: &[u8],
    options: DynamicOptions,
) -> Result<DynamicAnalysis, DynamicError> {
    let environment = options.environment.clone();
    let mut loaded = loader::load(bytes)?;
    loaded.memory.map(
        PROCESS_ENV_BASE,
        0x1000,
        Permissions::READ_WRITE,
        "synthetic process environment",
    )?;
    loaded.memory.write_force(COMMAND_LINE_A, b"sample.exe\0")?;
    let wide_command: Vec<u8> = "sample.exe\0"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    loaded.memory.write_force(COMMAND_LINE_W, &wide_command)?;
    loaded
        .memory
        .map(TEB_BASE, 0x1000, Permissions::READ_WRITE, "synthetic TEB")?;
    loaded
        .memory
        .map(PEB_BASE, 0x1000, Permissions::READ_WRITE, "synthetic PEB")?;
    loaded.memory.map(
        EXCEPTION_SCRATCH_BASE,
        0x1000,
        Permissions::READ_WRITE,
        "synthetic exception scratch",
    )?;
    loaded
        .memory
        .write_force(TEB_BASE, &u32::MAX.to_le_bytes())?;
    loaded
        .memory
        .write_force(TEB_BASE + 0x18, &TEB_BASE.to_le_bytes())?;
    loaded
        .memory
        .write_force(TEB_BASE + 0x30, &PEB_BASE.to_le_bytes())?;
    loaded
        .memory
        .write_force(PEB_BASE + 0x08, &loaded.image_base.to_le_bytes())?;
    loaded
        .memory
        .write_force(PEB_BASE + 0x10, &PROCESS_ENV_BASE.to_le_bytes())?;
    let profile = ExecutionProfile {
        architecture: "x86 (32-bit)".into(),
        operating_system: environment.windows_version.clone(),
        image_base: loaded.image_base,
        entry_point: loaded.entry_point,
        instruction_limit: options.max_instructions,
        trace_limit: options.max_trace_events,
        network_mode: environment.network_mode.description().into(),
        environment: environment.clone(),
    };
    let main_cpu = Cpu {
        eip: loaded.entry_point,
        esp: STACK_TOP,
        ebp: STACK_TOP,
        fs_base: TEB_BASE,
        ..Cpu::default()
    };
    let mut machine = Machine {
        cpu: main_cpu.clone(),
        memory: loaded.memory,
        imports: loaded.imports,
        options,
        instruction_count: 0,
        virtual_time_ms: environment.initial_virtual_time_ms,
        instructions: Vec::new(),
        api_calls: Vec::new(),
        processes: Vec::new(),
        filesystem: Vec::new(),
        registry: Vec::new(),
        network: Vec::new(),
        memory_events: Vec::new(),
        injection: Vec::new(),
        persistence: Vec::new(),
        exceptions: Vec::new(),
        warnings: loaded.warnings,
        termination: None,
        truncated: false,
        windows: VirtualWindows::default(),
        heap_next: HEAP_BASE,
        dynamic_api_next: DYNAMIC_API_BASE,
        timeline: Vec::new(),
        unique_instruction_addresses: BTreeSet::new(),
        unique_api_names: BTreeSet::new(),
        modeled_api_calls: 0,
        unmodeled_api_calls: 0,
        dynamic_api_resolutions: 0,
        entry_point: loaded.entry_point,
        tls_callbacks: loaded.tls_callbacks.into(),
        artifacts: ArtifactStore::default(),
        generations: GenerationTracker::default(),
        environment,
        pending_exception: None,
        vectored_handlers: Vec::new(),
        queued_exception: None,
        thread_states: vec![GuestThread {
            tid: 1,
            start_address: loaded.entry_point,
            parameter: 0,
            cpu: main_cpu,
            state: GuestThreadState::Runnable,
            instruction_count: 0,
            exit_code: None,
        }],
        thread_events: Vec::new(),
        current_thread: 0,
        thread_exit_requested: None,
        next_thread_switch: THREAD_QUANTUM,
        first_unsupported: None,
        invalid_instruction_count: 0,
    };
    machine.start_execution()?;
    machine.execute();
    machine.capture_final_artifacts();
    machine.save_current_thread();

    let mut findings = machine.build_findings();
    let termination = machine
        .termination
        .clone()
        .unwrap_or(Termination::InstructionLimit);
    let (artifact_summaries, artifact_stats, artifact_blobs) = machine.artifacts.finish();
    let (payload_generations, generation_stats) = machine.generations.finish();
    for artifact in &artifact_summaries {
        if artifact.detected_format != "unknown"
            || artifact
                .permissions
                .as_deref()
                .is_some_and(|value| value.contains('x'))
        {
            findings.push(DynamicFinding {
                id: format!("runtime-artifact-{}", &artifact.id[..12]),
                title: if artifact.kind == ArtifactKind::VirtualFile { "Executable artifact dropped".into() } else { "Runtime payload captured".into() },
                severity: DynamicSeverity::High,
                rationale: "Runtime-generated bytes matched an executable format or executable-memory trigger.".into(),
                evidence: vec![format!("{} · {} · {} bytes", artifact.name, artifact.detected_format, artifact.captured_size)],
            });
        }
    }
    if generation_stats.count > 0 {
        let evidence = payload_generations
            .iter()
            .map(|generation| {
                format!(
                    "{} · 0x{:08x} · {}{}{}",
                    generation.id,
                    generation.region_base,
                    generation.trigger,
                    if generation.executed {
                        " · executed"
                    } else {
                        ""
                    },
                    if generation.entry_point_overwrite {
                        " · entry point overwritten"
                    } else {
                        ""
                    }
                )
            })
            .collect();
        findings.push(DynamicFinding { id: "payload-generations".into(), title: "Runtime payload generations observed".into(), severity: DynamicSeverity::High, rationale: "Written memory produced one or more distinct executable payload versions during emulation.".into(), evidence });
    }
    let report = DynamicReport {
        schema_version: crate::DYNAMIC_SCHEMA_VERSION,
        engine_version: env!("CARGO_PKG_VERSION").into(),
        sample_sha256: hex::encode(Sha256::digest(bytes)),
        profile,
        termination,
        instruction_count: machine.instruction_count,
        elapsed_ms: 0.0,
        virtual_time_ms: machine.virtual_time_ms,
        instructions: machine.instructions,
        api_calls: machine.api_calls,
        processes: machine.processes,
        filesystem: machine.filesystem,
        registry: machine.registry,
        network: machine.network,
        memory: machine.memory_events,
        injection: machine.injection,
        persistence: machine.persistence,
        exceptions: machine.exceptions,
        threads: machine
            .thread_states
            .iter()
            .map(GuestThread::summary)
            .collect(),
        thread_events: machine.thread_events,
        artifacts: artifact_summaries,
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

struct Machine {
    cpu: Cpu,
    memory: Memory,
    imports: BTreeMap<u32, ApiImport>,
    options: DynamicOptions,
    instruction_count: u64,
    virtual_time_ms: u64,
    instructions: Vec<InstructionEvent>,
    api_calls: Vec<ApiEvent>,
    processes: Vec<ProcessEvent>,
    filesystem: Vec<FileEvent>,
    registry: Vec<RegistryEvent>,
    network: Vec<NetworkEvent>,
    memory_events: Vec<MemoryEvent>,
    injection: Vec<InjectionEvent>,
    persistence: Vec<PersistenceEvent>,
    exceptions: Vec<ExceptionEvent>,
    warnings: Vec<String>,
    termination: Option<Termination>,
    truncated: bool,
    windows: VirtualWindows,
    heap_next: u32,
    dynamic_api_next: u32,
    timeline: Vec<TimelineEvent>,
    unique_instruction_addresses: BTreeSet<u32>,
    unique_api_names: BTreeSet<String>,
    modeled_api_calls: usize,
    unmodeled_api_calls: usize,
    dynamic_api_resolutions: usize,
    entry_point: u32,
    tls_callbacks: VecDeque<u32>,
    artifacts: ArtifactStore,
    generations: GenerationTracker,
    environment: crate::EnvironmentProfile,
    pending_exception: Option<PendingException>,
    vectored_handlers: Vec<u32>,
    queued_exception: Option<(u32, String)>,
    thread_states: Vec<GuestThread>,
    thread_events: Vec<ThreadEvent>,
    current_thread: usize,
    thread_exit_requested: Option<u32>,
    next_thread_switch: u64,
    first_unsupported: Option<InstructionDiagnostic>,
    invalid_instruction_count: usize,
}

#[derive(Clone)]
struct GuestThread {
    tid: u32,
    start_address: u32,
    parameter: u32,
    cpu: Cpu,
    state: GuestThreadState,
    instruction_count: u64,
    exit_code: Option<u32>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GuestThreadState {
    Runnable,
    Terminated,
}

impl GuestThread {
    fn summary(&self) -> ThreadSummary {
        ThreadSummary {
            tid: self.tid,
            start_address: self.start_address,
            parameter: self.parameter,
            state: if self.state == GuestThreadState::Runnable {
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

struct PendingException {
    code: u32,
    name: String,
    address: u32,
    resume_eip: u32,
    frame: u32,
    depth: usize,
    fallback: Termination,
    event_index: usize,
    vectored_index: Option<usize>,
}

impl Machine {
    fn execute(&mut self) {
        while self.termination.is_none() && self.instruction_count < self.options.max_instructions {
            if self.pending_exception.is_none() && self.instruction_count >= self.next_thread_switch
            {
                self.schedule_next_thread(true);
                self.next_thread_switch = self.next_thread_switch.saturating_add(THREAD_QUANTUM);
            }
            if self.cpu.eip == THREAD_RETURN_SENTINEL {
                self.finish_current_thread(self.cpu.eax);
                if !self.schedule_next_thread(false) {
                    self.termination = Some(Termination::ReturnedFromEntryPoint);
                }
                continue;
            }
            if self.cpu.eip == ENTRY_RETURN_SENTINEL {
                self.termination = Some(Termination::ReturnedFromEntryPoint);
                break;
            }
            if self.cpu.eip == TLS_RETURN_SENTINEL {
                if let Err(error) = self.start_next_target() {
                    self.termination = Some(memory_termination(error, "TLS callback"));
                }
                continue;
            }
            if self.cpu.eip == EXCEPTION_RETURN_SENTINEL {
                self.complete_exception_handler();
                continue;
            }
            if let Some(import) = self.imports.get(&self.cpu.eip).cloned() {
                if self.api_calls.len() >= HARD_MAX_API_EVENTS {
                    self.truncated = true;
                    self.termination = Some(Termination::InstructionLimit);
                    break;
                }
                if let Err(error) = self.handle_api(import) {
                    self.termination = Some(memory_termination(error, "api"));
                }
                continue;
            }

            let address = self.cpu.eip;
            self.capture_memory_region(address, "dynamic_execution", "instruction", false);
            self.unique_instruction_addresses.insert(address);
            let bytes = match self.memory.fetch(address, 15) {
                Ok(bytes) => bytes,
                Err(error) => {
                    let fallback = memory_termination(error, "execute");
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
            let mut decoder = Decoder::with_ip(32, bytes, address as u64, DecoderOptions::NONE);
            let instruction = decoder.decode();
            if instruction.code() == Code::INVALID {
                self.invalid_instruction_count = self.invalid_instruction_count.saturating_add(1);
                self.record_instruction_diagnostic(
                    address,
                    "invalid or malformed instruction encoding".into(),
                    hex::encode(bytes),
                );
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
            let length = instruction.len();
            if self.instructions.len() < self.options.max_trace_events {
                self.instructions.push(InstructionEvent {
                    index: self.instruction_count,
                    address,
                    bytes: hex::encode(&bytes[..length.min(bytes.len())]),
                    text: instruction.to_string(),
                });
            } else {
                self.truncated = true;
            }
            self.cpu.eip = instruction.next_ip32();
            self.instruction_count += 1;
            if let Some(thread) = self.thread_states.get_mut(self.current_thread) {
                thread.instruction_count = thread.instruction_count.saturating_add(1);
            }
            if let Err(error) = self.execute_instruction(&instruction) {
                let fallback = match error {
                    DynamicError::MemoryRead { .. }
                    | DynamicError::MemoryWrite { .. }
                    | DynamicError::MemoryExecute { .. } => {
                        memory_termination(error, "instruction")
                    }
                    _ => {
                        self.warnings.push(error.to_string());
                        let bytes = self
                            .instructions
                            .last()
                            .map_or_else(String::new, |event| event.bytes.clone());
                        self.record_instruction_diagnostic(address, instruction.to_string(), bytes);
                        Termination::UnsupportedInstruction {
                            address,
                            instruction: instruction.to_string(),
                        }
                    }
                };
                let (code, name) = if matches!(fallback, Termination::MemoryFault { .. }) {
                    (0xc000_0005, "access_violation")
                } else {
                    (0xc000_001d, "illegal_instruction")
                };
                if !self.dispatch_exception(code, name, address, self.cpu.eip, fallback.clone()) {
                    self.termination = Some(fallback);
                }
            }
        }
        if self.termination.is_none() {
            self.termination = Some(Termination::InstructionLimit);
        }
    }

    fn dispatch_exception(
        &mut self,
        code: u32,
        name: &str,
        address: u32,
        resume_eip: u32,
        fallback: Termination,
    ) -> bool {
        if self.pending_exception.is_some() || self.exceptions.len() >= MAX_EXCEPTION_EVENTS {
            return false;
        }
        let frame = self.memory.read_u32(TEB_BASE).unwrap_or(u32::MAX);
        let pending = PendingException {
            code,
            name: name.into(),
            address,
            resume_eip,
            frame,
            depth: 0,
            fallback,
            event_index: 0,
            vectored_index: (!self.vectored_handlers.is_empty()).then_some(0),
        };
        self.begin_exception_handler(pending)
    }

    fn record_instruction_diagnostic(&mut self, address: u32, instruction: String, bytes: String) {
        if self.first_unsupported.is_some() {
            return;
        }
        let nearby_trace = self
            .instructions
            .iter()
            .rev()
            .take(4)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        self.first_unsupported = Some(InstructionDiagnostic {
            address,
            instruction,
            bytes,
            nearby_trace,
        });
    }

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
            .find(|index| self.thread_states[*index].state == GuestThreadState::Runnable)
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
            thread.state = GuestThreadState::Terminated;
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
                (thread.state == GuestThreadState::Runnable).then_some(index)
            })
            .collect();
        for index in active {
            self.thread_states[index].state = GuestThreadState::Terminated;
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

    fn create_guest_thread(&mut self, start_address: u32, parameter: u32) -> u32 {
        if self.thread_states.len() >= MAX_GUEST_THREADS
            || self.memory.fetch(start_address, 1).is_err()
        {
            return 0;
        }
        let tid = self.thread_states.len() as u32 + 1;
        let stack_base = 0x6000_0000u32.saturating_add(tid.saturating_mul(0x20_000));
        let teb_base = 0x7ffd_0000u32.saturating_sub(tid.saturating_mul(0x2000));
        if self
            .memory
            .map(
                stack_base,
                THREAD_STACK_SIZE,
                Permissions::READ_WRITE,
                format!("thread {tid} stack"),
            )
            .is_err()
            || self
                .memory
                .map(
                    teb_base,
                    0x1000,
                    Permissions::READ_WRITE,
                    format!("thread {tid} TEB"),
                )
                .is_err()
        {
            return 0;
        }
        let _ = self.memory.write_force(teb_base, &u32::MAX.to_le_bytes());
        let _ = self
            .memory
            .write_force(teb_base + 0x18, &teb_base.to_le_bytes());
        let _ = self
            .memory
            .write_force(teb_base + 0x30, &PEB_BASE.to_le_bytes());
        let top = stack_base
            .saturating_add(THREAD_STACK_SIZE as u32)
            .saturating_sub(16);
        let mut cpu = Cpu {
            eip: start_address,
            esp: top,
            ebp: top,
            fs_base: teb_base,
            ..Cpu::default()
        };
        if cpu.push(&mut self.memory, parameter).is_err()
            || cpu.push(&mut self.memory, THREAD_RETURN_SENTINEL).is_err()
        {
            return 0;
        }
        self.thread_states.push(GuestThread {
            tid,
            start_address,
            parameter,
            cpu,
            state: GuestThreadState::Runnable,
            instruction_count: 0,
            exit_code: None,
        });
        let index = self.thread_states.len() - 1;
        self.record_thread_event("created", index);
        tid
    }

    fn begin_exception_handler(&mut self, mut pending: PendingException) -> bool {
        if pending.depth >= MAX_SEH_DEPTH {
            return false;
        }
        let handler = if let Some(index) = pending.vectored_index {
            let Some(handler) = self.vectored_handlers.get(index).copied() else {
                return false;
            };
            handler
        } else {
            if matches!(pending.frame, 0 | u32::MAX) {
                return false;
            }
            let Ok(handler) = self.memory.read_u32(pending.frame.wrapping_add(4)) else {
                return false;
            };
            handler
        };
        if self.memory.fetch(handler, 1).is_err() {
            return false;
        }
        self.write_exception_context(&pending);
        let stack_ready = if pending.vectored_index.is_some() {
            let pointers = EXCEPTION_SCRATCH_BASE + 0x3e0;
            let _ = self
                .memory
                .write_force(pointers, &EXCEPTION_RECORD_BASE.to_le_bytes());
            let _ = self
                .memory
                .write_force(pointers + 4, &EXCEPTION_CONTEXT_BASE.to_le_bytes());
            self.cpu.push(&mut self.memory, pointers).is_ok()
                && self
                    .cpu
                    .push(&mut self.memory, EXCEPTION_RETURN_SENTINEL)
                    .is_ok()
        } else {
            self.cpu.push(&mut self.memory, 0).is_ok()
                && self
                    .cpu
                    .push(&mut self.memory, EXCEPTION_CONTEXT_BASE)
                    .is_ok()
                && self.cpu.push(&mut self.memory, pending.frame).is_ok()
                && self
                    .cpu
                    .push(&mut self.memory, EXCEPTION_RECORD_BASE)
                    .is_ok()
                && self
                    .cpu
                    .push(&mut self.memory, EXCEPTION_RETURN_SENTINEL)
                    .is_ok()
        };
        if !stack_ready {
            return false;
        }
        let event_index = self.exceptions.len();
        self.exceptions.push(ExceptionEvent {
            sequence: event_index as u64,
            code: pending.code,
            name: pending.name.clone(),
            address: pending.address,
            handler: Some(handler),
            establisher_frame: pending.vectored_index.is_none().then_some(pending.frame),
            disposition: None,
            outcome: "dispatched".into(),
        });
        self.timeline.push(TimelineEvent {
            sequence: self.timeline.len() as u64,
            instruction: self.instruction_count,
            virtual_time_ms: self.virtual_time_ms,
            category: "exception".into(),
            operation: "seh_dispatch".into(),
            subject: format!(
                "{} 0x{:08x} -> 0x{handler:08x}",
                pending.name, pending.address
            ),
            source_api: "SEH".into(),
        });
        pending.event_index = event_index;
        self.cpu.eip = handler;
        self.pending_exception = Some(pending);
        true
    }

    fn write_exception_context(&mut self, pending: &PendingException) {
        let _ = self
            .memory
            .write_force(EXCEPTION_RECORD_BASE, &pending.code.to_le_bytes());
        let _ = self
            .memory
            .write_force(EXCEPTION_RECORD_BASE + 12, &pending.address.to_le_bytes());
        for (offset, value) in [
            (0x9c, self.cpu.edi),
            (0xa0, self.cpu.esi),
            (0xa4, self.cpu.ebx),
            (0xa8, self.cpu.edx),
            (0xac, self.cpu.ecx),
            (0xb0, self.cpu.eax),
            (0xb4, self.cpu.ebp),
            (0xb8, pending.resume_eip),
            (0xc0, self.cpu.flags_value()),
            (0xc4, self.cpu.esp),
        ] {
            let _ = self
                .memory
                .write_force(EXCEPTION_CONTEXT_BASE + offset, &value.to_le_bytes());
        }
    }

    fn complete_exception_handler(&mut self) {
        let Some(mut pending) = self.pending_exception.take() else {
            self.termination = Some(Termination::MemoryFault {
                address: EXCEPTION_RETURN_SENTINEL,
                operation: "exception return without pending handler".into(),
            });
            return;
        };
        let disposition = self.cpu.eax as i32;
        if let Some(event) = self.exceptions.get_mut(pending.event_index) {
            event.disposition = Some(disposition);
        }
        match disposition {
            -1 => {
                for (offset, target) in [
                    (0x9c, &mut self.cpu.edi),
                    (0xa0, &mut self.cpu.esi),
                    (0xa4, &mut self.cpu.ebx),
                    (0xa8, &mut self.cpu.edx),
                    (0xac, &mut self.cpu.ecx),
                    (0xb0, &mut self.cpu.eax),
                    (0xb4, &mut self.cpu.ebp),
                    (0xc4, &mut self.cpu.esp),
                ] {
                    if let Ok(value) = self.memory.read_u32(EXCEPTION_CONTEXT_BASE + offset) {
                        *target = value;
                    }
                }
                self.cpu.eip = self
                    .memory
                    .read_u32(EXCEPTION_CONTEXT_BASE + 0xb8)
                    .unwrap_or(pending.resume_eip);
                if let Ok(flags) = self.memory.read_u32(EXCEPTION_CONTEXT_BASE + 0xc0) {
                    self.cpu.set_flags_value(flags);
                }
                if let Some(event) = self.exceptions.get_mut(pending.event_index) {
                    event.outcome = "continued_execution".into();
                }
            }
            0 => {
                if let Some(event) = self.exceptions.get_mut(pending.event_index) {
                    event.outcome = "continued_search".into();
                }
                if let Some(index) = pending.vectored_index {
                    if index + 1 < self.vectored_handlers.len() {
                        pending.vectored_index = Some(index + 1);
                    } else {
                        pending.vectored_index = None;
                        pending.frame = self.memory.read_u32(TEB_BASE).unwrap_or(u32::MAX);
                    }
                } else {
                    pending.frame = self.memory.read_u32(pending.frame).unwrap_or(u32::MAX);
                }
                pending.depth += 1;
                let fallback = pending.fallback.clone();
                if !self.begin_exception_handler(pending) {
                    self.termination = Some(fallback);
                }
            }
            _ => {
                if let Some(event) = self.exceptions.get_mut(pending.event_index) {
                    event.outcome = "unhandled_disposition".into();
                }
                self.termination = Some(pending.fallback);
            }
        }
    }

    fn artifact_origin(
        &self,
        api: &str,
        trigger: &str,
        address: Option<u32>,
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

    fn capture_memory_region(&mut self, address: u32, trigger: &str, api: &str, force: bool) {
        let Some(region) = self.memory.snapshot(address) else {
            return;
        };
        if !region.dirty {
            return;
        }
        let start = region.start;
        let name = region.name.to_owned();
        let permissions = region.permissions.display();
        let bytes = region.data[..region.data.len().min(MAX_ARTIFACT_BYTES)].to_vec();
        let origin = self.artifact_origin(api, trigger, Some(start), None);
        let kind = if region.permissions.execute {
            ArtifactKind::Memory
        } else {
            ArtifactKind::Configuration
        };
        let entry_point_overwrite = self.memory.was_written(self.entry_point)
            && self.entry_point >= start
            && self.entry_point < start.saturating_add(region.data.len() as u32);
        let executed = trigger == "dynamic_execution";
        let executable_heap = start >= HEAP_BASE && region.permissions.execute;
        let size = region.data.len() as u64;
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
        ) && (permissions.contains('x') || entry_point_overwrite)
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
            });
        }
    }

    fn capture_final_artifacts(&mut self) {
        let memory: Vec<_> = self
            .memory
            .dirty_regions()
            .map(|region| region.start)
            .collect();
        for address in memory {
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
        let remote: Vec<_> = self
            .windows
            .remote_snapshots()
            .map(|(process, address, bytes)| (process, address, bytes.to_vec()))
            .collect();
        for (process, address, bytes) in remote {
            let origin =
                self.artifact_origin("remote_process", "remote_write", Some(address), None);
            self.artifacts.capture(
                ArtifactCapture {
                    kind: ArtifactKind::RemoteMemory,
                    name: format!("process-{process:08x}-{address:08x}.bin"),
                    trigger: "remote_write",
                    address: Some(address),
                    path: None,
                    permissions: None,
                    force: true,
                },
                &bytes,
                origin,
            );
        }
    }

    fn start_execution(&mut self) -> Result<(), DynamicError> {
        self.start_next_target()
    }

    fn start_next_target(&mut self) -> Result<(), DynamicError> {
        self.cpu.esp = STACK_TOP;
        self.cpu.ebp = STACK_TOP;
        if let Some(callback) = self.tls_callbacks.pop_front() {
            self.cpu.push(&mut self.memory, 0)?;
            self.cpu.push(&mut self.memory, 1)?;
            self.cpu.push(&mut self.memory, 0x0040_0000)?;
            self.cpu.push(&mut self.memory, TLS_RETURN_SENTINEL)?;
            self.cpu.eip = callback;
        } else {
            self.cpu.push(&mut self.memory, ENTRY_RETURN_SENTINEL)?;
            self.cpu.eip = self.entry_point;
        }
        Ok(())
    }

    fn execute_instruction(&mut self, instruction: &Instruction) -> Result<(), DynamicError> {
        use Mnemonic::*;
        match instruction.mnemonic() {
            Mov => {
                let (value, _) = self.cpu.read_operand(&self.memory, instruction, 1)?;
                self.cpu
                    .write_operand(&mut self.memory, instruction, 0, value)?;
            }
            Movzx => {
                let (value, _) = self.cpu.read_operand(&self.memory, instruction, 1)?;
                self.cpu
                    .write_operand(&mut self.memory, instruction, 0, value)?;
            }
            Movsx => {
                let (value, source_size) = self.cpu.read_operand(&self.memory, instruction, 1)?;
                let value = match source_size {
                    8 => value as i8 as i32 as u32,
                    16 => value as i16 as i32 as u32,
                    _ => value,
                };
                self.cpu
                    .write_operand(&mut self.memory, instruction, 0, value)?;
            }
            Lea => {
                let address = self.cpu.effective_address(instruction)?;
                self.cpu
                    .write_operand(&mut self.memory, instruction, 0, address)?;
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
            Pushad => {
                let original_esp = self.cpu.esp;
                for value in [
                    self.cpu.eax,
                    self.cpu.ecx,
                    self.cpu.edx,
                    self.cpu.ebx,
                    original_esp,
                    self.cpu.ebp,
                    self.cpu.esi,
                    self.cpu.edi,
                ] {
                    self.cpu.push(&mut self.memory, value)?;
                }
            }
            Popad => {
                self.cpu.edi = self.cpu.pop(&self.memory)?;
                self.cpu.esi = self.cpu.pop(&self.memory)?;
                self.cpu.ebp = self.cpu.pop(&self.memory)?;
                let _ignored_esp = self.cpu.pop(&self.memory)?;
                self.cpu.ebx = self.cpu.pop(&self.memory)?;
                self.cpu.edx = self.cpu.pop(&self.memory)?;
                self.cpu.ecx = self.cpu.pop(&self.memory)?;
                self.cpu.eax = self.cpu.pop(&self.memory)?;
            }
            Pushfd => {
                self.cpu.push(&mut self.memory, self.cpu.flags_value())?;
            }
            Popfd => {
                let value = self.cpu.pop(&self.memory)?;
                self.cpu.set_flags_value(value);
            }
            Call => {
                let target = self.branch_target(instruction, 0)?;
                self.cpu.push(&mut self.memory, self.cpu.eip)?;
                self.cpu.eip = target;
            }
            Ret => {
                self.cpu.eip = self.cpu.pop(&self.memory)?;
                if instruction.op_count() > 0 {
                    self.cpu.esp = self.cpu.esp.wrapping_add(instruction.immediate16() as u32);
                }
            }
            Leave => {
                self.cpu.esp = self.cpu.ebp;
                self.cpu.ebp = self.cpu.pop(&self.memory)?;
            }
            Enter => {
                if instruction.immediate8_2nd() != 0 {
                    return Err(DynamicError::UnsupportedOperand(
                        "ENTER nesting levels are not supported".into(),
                    ));
                }
                self.cpu.push(&mut self.memory, self.cpu.ebp)?;
                self.cpu.ebp = self.cpu.esp;
                self.cpu.esp = self.cpu.esp.wrapping_sub(instruction.immediate16() as u32);
            }
            Add | Adc | Sub | Sbb | Xor | And | Or => self.binary_operation(instruction)?,
            Cmp | Test => self.comparison(instruction)?,
            Inc | Dec => self.increment(instruction)?,
            Neg | Not => self.unary(instruction)?,
            Shl | Sal | Shr | Sar | Rol | Ror => self.shift(instruction)?,
            Shld | Shrd => self.double_shift(instruction)?,
            Imul => self.imul(instruction)?,
            Mul => self.mul(instruction)?,
            Div | Idiv => self.divide(instruction)?,
            Xchg => {
                let (left, _) = self.cpu.read_operand(&self.memory, instruction, 0)?;
                let (right, _) = self.cpu.read_operand(&self.memory, instruction, 1)?;
                self.cpu
                    .write_operand(&mut self.memory, instruction, 0, right)?;
                self.cpu
                    .write_operand(&mut self.memory, instruction, 1, left)?;
            }
            Bt | Btc | Btr | Bts => self.bit_operation(instruction)?,
            Bsf | Bsr => self.bit_scan(instruction)?,
            Cmpxchg => self.compare_exchange(instruction)?,
            Xadd => self.exchange_add(instruction)?,
            Lahf => self
                .cpu
                .write_register(iced_x86::Register::AH, self.cpu.flags_value() & 0xff)?,
            Sahf => {
                let ah = self.cpu.read_register(iced_x86::Register::AH)?;
                self.cpu
                    .set_flags_value((self.cpu.flags_value() & !0xff) | ah);
            }
            Movdqu | Movdqa | Movups | Movaps => self.vector_move(instruction, 16)?,
            Movq => self.vector_move(instruction, 8)?,
            Movd => self.movd(instruction)?,
            Pxor | Xorps | Xorpd | Pand | Andps | Andpd | Por | Orps | Orpd => {
                self.vector_logic(instruction)?
            }
            Addss | Subss | Mulss | Divss | Sqrtss => self.scalar_float(instruction, false)?,
            Addsd | Subsd | Mulsd | Divsd | Sqrtsd => self.scalar_float(instruction, true)?,
            Fld1 => self.cpu.x87_push(1.0)?,
            Fldz => self.cpu.x87_push(0.0)?,
            Fld | Fild => self.x87_load(instruction)?,
            Fst | Fstp => self.x87_store(instruction, instruction.mnemonic() == Fstp)?,
            Fadd | Faddp | Fsub | Fsubp | Fmul | Fmulp | Fdiv | Fdivp => {
                self.x87_arithmetic(instruction)?
            }
            Jmp => self.cpu.eip = self.branch_target(instruction, 0)?,
            Je | Jne | Ja | Jae | Jb | Jbe | Jg | Jge | Jl | Jle | Js | Jns | Jo | Jno | Jp
            | Jnp => {
                if self.condition(instruction.mnemonic()) {
                    self.cpu.eip = self.branch_target(instruction, 0)?;
                }
            }
            Jecxz => {
                if self.cpu.ecx == 0 {
                    self.cpu.eip = self.branch_target(instruction, 0)?;
                }
            }
            Loop | Loope | Loopne => {
                self.cpu.ecx = self.cpu.ecx.wrapping_sub(1);
                let take = match instruction.mnemonic() {
                    Loop => self.cpu.ecx != 0,
                    Loope => self.cpu.ecx != 0 && self.cpu.zf,
                    Loopne => self.cpu.ecx != 0 && !self.cpu.zf,
                    _ => false,
                };
                if take {
                    self.cpu.eip = self.branch_target(instruction, 0)?;
                }
            }
            Cdq => {
                self.cpu.edx = if self.cpu.eax & 0x8000_0000 != 0 {
                    u32::MAX
                } else {
                    0
                }
            }
            Cwde => self.cpu.eax = self.cpu.eax as i16 as i32 as u32,
            Sete | Setne | Seta | Setae | Setb | Setbe | Setg | Setge | Setl | Setle | Sets
            | Setns | Seto | Setno | Setp | Setnp => {
                let value = u32::from(self.condition(set_to_jump(instruction.mnemonic())));
                self.cpu
                    .write_operand(&mut self.memory, instruction, 0, value)?;
            }
            Cmove | Cmovne | Cmova | Cmovae | Cmovb | Cmovbe | Cmovg | Cmovge | Cmovl | Cmovle
            | Cmovs | Cmovns | Cmovo | Cmovno | Cmovp | Cmovnp => {
                if self.condition(cmov_to_jump(instruction.mnemonic())) {
                    let (value, _) = self.cpu.read_operand(&self.memory, instruction, 1)?;
                    self.cpu
                        .write_operand(&mut self.memory, instruction, 0, value)?;
                }
            }
            Movsb | Movsw | Movsd | Stosb | Stosw | Stosd | Lodsb | Lodsw | Lodsd | Cmpsb
            | Cmpsw | Cmpsd | Scasb | Scasw | Scasd => {
                self.string_operation(instruction)?;
            }
            Bswap => {
                let register = instruction.op0_register();
                let value = self.cpu.read_register(register)?.swap_bytes();
                self.cpu.write_register(register, value)?;
            }
            Clc => self.cpu.cf = false,
            Stc => self.cpu.cf = true,
            Cmc => self.cpu.cf = !self.cpu.cf,
            Cpuid => match self.cpu.eax {
                0 => {
                    self.cpu.eax = 1;
                    self.cpu.ebx = 0x756e_6547;
                    self.cpu.edx = 0x4965_6e69;
                    self.cpu.ecx = 0x6c65_746e;
                }
                1 => {
                    self.cpu.eax = 0x0000_06a0;
                    self.cpu.ebx = 0;
                    self.cpu.ecx = 0;
                    self.cpu.edx = 1 << 4;
                }
                _ => {
                    self.cpu.eax = 0;
                    self.cpu.ebx = 0;
                    self.cpu.ecx = 0;
                    self.cpu.edx = 0;
                }
            },
            Rdtsc => {
                let ticks = self.virtual_time_ms.saturating_mul(3_000_000);
                self.cpu.eax = ticks as u32;
                self.cpu.edx = (ticks >> 32) as u32;
            }
            Pause => {}
            Cld => self.cpu.direction = false,
            Std => self.cpu.direction = true,
            Nop => {}
            Int3 => {
                let fallback = Termination::Halted;
                if !self.dispatch_exception(
                    0x8000_0003,
                    "breakpoint",
                    instruction.ip32(),
                    self.cpu.eip,
                    fallback.clone(),
                ) {
                    self.termination = Some(fallback);
                }
            }
            Hlt => self.termination = Some(Termination::Halted),
            _ => {
                return Err(DynamicError::UnsupportedOperand(format!(
                    "mnemonic {:?}",
                    instruction.mnemonic()
                )));
            }
        }
        Ok(())
    }

    fn binary_operation(&mut self, instruction: &Instruction) -> Result<(), DynamicError> {
        let (left, size) = self.cpu.read_operand(&self.memory, instruction, 0)?;
        let (right, _) = self.cpu.read_operand(&self.memory, instruction, 1)?;
        let result = match instruction.mnemonic() {
            Mnemonic::Add => left.wrapping_add(right),
            Mnemonic::Adc => left
                .wrapping_add(right)
                .wrapping_add(u32::from(self.cpu.cf)),
            Mnemonic::Sub => left.wrapping_sub(right),
            Mnemonic::Sbb => left
                .wrapping_sub(right)
                .wrapping_sub(u32::from(self.cpu.cf)),
            Mnemonic::Xor => left ^ right,
            Mnemonic::And => left & right,
            Mnemonic::Or => left | right,
            _ => unreachable!(),
        };
        let old_cf = self.cpu.cf;
        match instruction.mnemonic() {
            Mnemonic::Add => self.cpu.set_add_flags(left, right, result, size),
            Mnemonic::Adc => self.cpu.set_adc_flags(left, right, old_cf, result, size),
            Mnemonic::Sub => self.cpu.set_sub_flags(left, right, result, size),
            Mnemonic::Sbb => self.cpu.set_sbb_flags(left, right, old_cf, result, size),
            _ => self.cpu.set_logic_flags(result, size),
        }
        self.cpu
            .write_operand(&mut self.memory, instruction, 0, result)?;
        Ok(())
    }

    fn bit_operation(&mut self, instruction: &Instruction) -> Result<(), DynamicError> {
        let (value, size) = self.cpu.read_operand(&self.memory, instruction, 0)?;
        let (index, _) = self.cpu.read_operand(&self.memory, instruction, 1)?;
        let bit = index % size;
        let mask = 1u32 << bit;
        self.cpu.cf = value & mask != 0;
        let result = match instruction.mnemonic() {
            Mnemonic::Btc => value ^ mask,
            Mnemonic::Btr => value & !mask,
            Mnemonic::Bts => value | mask,
            _ => return Ok(()),
        };
        self.cpu
            .write_operand(&mut self.memory, instruction, 0, result)?;
        Ok(())
    }

    fn bit_scan(&mut self, instruction: &Instruction) -> Result<(), DynamicError> {
        let (source, size) = self.cpu.read_operand(&self.memory, instruction, 1)?;
        let source = source & crate::cpu::bit_mask(size);
        self.cpu.zf = source == 0;
        if source != 0 {
            let index = if instruction.mnemonic() == Mnemonic::Bsf {
                source.trailing_zeros()
            } else {
                31 - source.leading_zeros()
            };
            self.cpu
                .write_operand(&mut self.memory, instruction, 0, index)?;
        }
        Ok(())
    }

    fn double_shift(&mut self, instruction: &Instruction) -> Result<(), DynamicError> {
        let (destination, size) = self.cpu.read_operand(&self.memory, instruction, 0)?;
        let (source, _) = self.cpu.read_operand(&self.memory, instruction, 1)?;
        let (count, _) = self.cpu.read_operand(&self.memory, instruction, 2)?;
        let count = count & 0x1f;
        if count == 0 {
            return Ok(());
        }
        let width = size.min(32);
        if count >= width {
            return Err(DynamicError::UnsupportedOperand(format!(
                "double shift count {count} for {width}-bit operand"
            )));
        }
        let result = if instruction.mnemonic() == Mnemonic::Shld {
            destination.wrapping_shl(count) | source.wrapping_shr(width - count)
        } else {
            destination.wrapping_shr(count) | source.wrapping_shl(width - count)
        };
        let carry = if instruction.mnemonic() == Mnemonic::Shld {
            destination & (1 << (width - count)) != 0
        } else {
            destination & (1 << (count - 1)) != 0
        };
        self.cpu
            .write_operand(&mut self.memory, instruction, 0, result)?;
        self.cpu.set_logic_flags(result, size);
        self.cpu.cf = carry;
        Ok(())
    }

    fn compare_exchange(&mut self, instruction: &Instruction) -> Result<(), DynamicError> {
        let (destination, size) = self.cpu.read_operand(&self.memory, instruction, 0)?;
        let (source, _) = self.cpu.read_operand(&self.memory, instruction, 1)?;
        let accumulator = self.cpu.eax & crate::cpu::bit_mask(size);
        self.cpu.set_sub_flags(
            accumulator,
            destination,
            accumulator.wrapping_sub(destination),
            size,
        );
        if accumulator == destination {
            self.cpu
                .write_operand(&mut self.memory, instruction, 0, source)?;
        } else {
            match size {
                8 => self
                    .cpu
                    .write_register(iced_x86::Register::AL, destination)?,
                16 => self
                    .cpu
                    .write_register(iced_x86::Register::AX, destination)?,
                _ => self.cpu.eax = destination,
            }
        }
        Ok(())
    }

    fn exchange_add(&mut self, instruction: &Instruction) -> Result<(), DynamicError> {
        let (destination, size) = self.cpu.read_operand(&self.memory, instruction, 0)?;
        let (source, _) = self.cpu.read_operand(&self.memory, instruction, 1)?;
        let result = destination.wrapping_add(source);
        self.cpu
            .write_operand(&mut self.memory, instruction, 0, result)?;
        self.cpu
            .write_operand(&mut self.memory, instruction, 1, destination)?;
        self.cpu.set_add_flags(destination, source, result, size);
        Ok(())
    }

    fn vector_move(&mut self, instruction: &Instruction, width: usize) -> Result<(), DynamicError> {
        let value = self
            .cpu
            .read_vector_operand(&self.memory, instruction, 1, width)?;
        self.cpu
            .write_vector_operand(&mut self.memory, instruction, 0, &value[..width])
    }

    fn movd(&mut self, instruction: &Instruction) -> Result<(), DynamicError> {
        if matches!(
            instruction.op0_register(),
            iced_x86::Register::XMM0
                | iced_x86::Register::XMM1
                | iced_x86::Register::XMM2
                | iced_x86::Register::XMM3
                | iced_x86::Register::XMM4
                | iced_x86::Register::XMM5
                | iced_x86::Register::XMM6
                | iced_x86::Register::XMM7
        ) {
            let (value, _) = self.cpu.read_operand(&self.memory, instruction, 1)?;
            let mut bytes = [0u8; 16];
            bytes[..4].copy_from_slice(&value.to_le_bytes());
            self.cpu
                .write_vector_operand(&mut self.memory, instruction, 0, &bytes)
        } else {
            let value = self
                .cpu
                .read_vector_operand(&self.memory, instruction, 1, 4)?;
            self.cpu.write_operand(
                &mut self.memory,
                instruction,
                0,
                u32::from_le_bytes(value[..4].try_into().unwrap()),
            )?;
            Ok(())
        }
    }

    fn vector_logic(&mut self, instruction: &Instruction) -> Result<(), DynamicError> {
        let left = self
            .cpu
            .read_vector_operand(&self.memory, instruction, 0, 16)?;
        let right = self
            .cpu
            .read_vector_operand(&self.memory, instruction, 1, 16)?;
        let mut result = [0u8; 16];
        for index in 0..16 {
            result[index] = match instruction.mnemonic() {
                Mnemonic::Pxor | Mnemonic::Xorps | Mnemonic::Xorpd => left[index] ^ right[index],
                Mnemonic::Pand | Mnemonic::Andps | Mnemonic::Andpd => left[index] & right[index],
                _ => left[index] | right[index],
            };
        }
        self.cpu
            .write_vector_operand(&mut self.memory, instruction, 0, &result)
    }

    fn scalar_float(
        &mut self,
        instruction: &Instruction,
        double: bool,
    ) -> Result<(), DynamicError> {
        let width = if double { 8 } else { 4 };
        let mut destination = self
            .cpu
            .read_vector_operand(&self.memory, instruction, 0, 16)?;
        let source = self
            .cpu
            .read_vector_operand(&self.memory, instruction, 1, width)?;
        if double {
            let left = f64::from_le_bytes(destination[..8].try_into().unwrap());
            let right = f64::from_le_bytes(source[..8].try_into().unwrap());
            let value = match instruction.mnemonic() {
                Mnemonic::Addsd => left + right,
                Mnemonic::Subsd => left - right,
                Mnemonic::Mulsd => left * right,
                Mnemonic::Divsd => left / right,
                Mnemonic::Sqrtsd => right.sqrt(),
                _ => unreachable!(),
            };
            destination[..8].copy_from_slice(&value.to_le_bytes());
        } else {
            let left = f32::from_le_bytes(destination[..4].try_into().unwrap());
            let right = f32::from_le_bytes(source[..4].try_into().unwrap());
            let value = match instruction.mnemonic() {
                Mnemonic::Addss => left + right,
                Mnemonic::Subss => left - right,
                Mnemonic::Mulss => left * right,
                Mnemonic::Divss => left / right,
                Mnemonic::Sqrtss => right.sqrt(),
                _ => unreachable!(),
            };
            destination[..4].copy_from_slice(&value.to_le_bytes());
        }
        self.cpu
            .write_vector_operand(&mut self.memory, instruction, 0, &destination)
    }

    fn x87_load(&mut self, instruction: &Instruction) -> Result<(), DynamicError> {
        let address = self.cpu.effective_address(instruction)?;
        let size = instruction.memory_size().size();
        let value = if instruction.mnemonic() == Mnemonic::Fild {
            match size {
                2 => self.memory.read_u16(address)? as i16 as f64,
                4 => self.memory.read_u32(address)? as i32 as f64,
                _ => {
                    return Err(DynamicError::UnsupportedOperand(format!(
                        "FILD {size} bytes"
                    )));
                }
            }
        } else {
            match size {
                4 => f32::from_le_bytes(self.memory.read(address, 4)?.try_into().unwrap()) as f64,
                8 => f64::from_le_bytes(self.memory.read(address, 8)?.try_into().unwrap()),
                _ => {
                    return Err(DynamicError::UnsupportedOperand(format!(
                        "FLD {size} bytes"
                    )));
                }
            }
        };
        self.cpu.x87_push(value)
    }

    fn x87_store(&mut self, instruction: &Instruction, pop: bool) -> Result<(), DynamicError> {
        if self.cpu.x87_depth == 0 {
            return Err(DynamicError::UnsupportedOperand(
                "x87 stack underflow".into(),
            ));
        }
        let value = self.cpu.x87[0];
        let address = self.cpu.effective_address(instruction)?;
        match instruction.memory_size().size() {
            4 => self.memory.write(address, &(value as f32).to_le_bytes())?,
            8 => self.memory.write(address, &value.to_le_bytes())?,
            size => {
                return Err(DynamicError::UnsupportedOperand(format!(
                    "FST {size} bytes"
                )));
            }
        }
        if pop {
            let _ = self.cpu.x87_pop()?;
        }
        Ok(())
    }

    fn x87_arithmetic(&mut self, instruction: &Instruction) -> Result<(), DynamicError> {
        if self.cpu.x87_depth < 2 {
            return Err(DynamicError::UnsupportedOperand(
                "x87 arithmetic requires two stack values".into(),
            ));
        }
        let left = self.cpu.x87[1];
        let right = self.cpu.x87[0];
        let value = match instruction.mnemonic() {
            Mnemonic::Fadd | Mnemonic::Faddp => left + right,
            Mnemonic::Fsub | Mnemonic::Fsubp => left - right,
            Mnemonic::Fmul | Mnemonic::Fmulp => left * right,
            Mnemonic::Fdiv | Mnemonic::Fdivp => left / right,
            _ => unreachable!(),
        };
        self.cpu.x87[1] = value;
        if matches!(
            instruction.mnemonic(),
            Mnemonic::Faddp | Mnemonic::Fsubp | Mnemonic::Fmulp | Mnemonic::Fdivp
        ) {
            let _ = self.cpu.x87_pop()?;
        }
        Ok(())
    }

    fn comparison(&mut self, instruction: &Instruction) -> Result<(), DynamicError> {
        let (left, size) = self.cpu.read_operand(&self.memory, instruction, 0)?;
        let (right, _) = self.cpu.read_operand(&self.memory, instruction, 1)?;
        if instruction.mnemonic() == Mnemonic::Cmp {
            self.cpu
                .set_sub_flags(left, right, left.wrapping_sub(right), size);
        } else {
            self.cpu.set_logic_flags(left & right, size);
        }
        Ok(())
    }

    fn increment(&mut self, instruction: &Instruction) -> Result<(), DynamicError> {
        let (value, size) = self.cpu.read_operand(&self.memory, instruction, 0)?;
        let old_cf = self.cpu.cf;
        let result = if instruction.mnemonic() == Mnemonic::Inc {
            value.wrapping_add(1)
        } else {
            value.wrapping_sub(1)
        };
        if instruction.mnemonic() == Mnemonic::Inc {
            self.cpu.set_add_flags(value, 1, result, size);
        } else {
            self.cpu.set_sub_flags(value, 1, result, size);
        }
        self.cpu.cf = old_cf;
        self.cpu
            .write_operand(&mut self.memory, instruction, 0, result)?;
        Ok(())
    }

    fn unary(&mut self, instruction: &Instruction) -> Result<(), DynamicError> {
        let (value, size) = self.cpu.read_operand(&self.memory, instruction, 0)?;
        let result = if instruction.mnemonic() == Mnemonic::Neg {
            0u32.wrapping_sub(value)
        } else {
            !value
        };
        if instruction.mnemonic() == Mnemonic::Neg {
            self.cpu.set_sub_flags(0, value, result, size);
        }
        self.cpu
            .write_operand(&mut self.memory, instruction, 0, result)?;
        Ok(())
    }

    fn shift(&mut self, instruction: &Instruction) -> Result<(), DynamicError> {
        let (value, size) = self.cpu.read_operand(&self.memory, instruction, 0)?;
        let (count, _) = self.cpu.read_operand(&self.memory, instruction, 1)?;
        let count = count & 0x1f;
        let result = match instruction.mnemonic() {
            Mnemonic::Shl | Mnemonic::Sal => value.wrapping_shl(count),
            Mnemonic::Shr => value.wrapping_shr(count),
            Mnemonic::Sar => (value as i32).wrapping_shr(count) as u32,
            Mnemonic::Rol => value.rotate_left(count),
            Mnemonic::Ror => value.rotate_right(count),
            _ => unreachable!(),
        };
        self.cpu.set_logic_flags(result, size);
        self.cpu
            .write_operand(&mut self.memory, instruction, 0, result)?;
        Ok(())
    }

    fn imul(&mut self, instruction: &Instruction) -> Result<(), DynamicError> {
        if instruction.op_count() == 1 {
            let (operand, size) = self.cpu.read_operand(&self.memory, instruction, 0)?;
            match size {
                8 => {
                    let product =
                        (self.cpu.eax as u8 as i8 as i16).wrapping_mul(operand as u8 as i8 as i16);
                    self.cpu
                        .write_register(iced_x86::Register::AX, product as u32)?;
                    self.cpu.cf = product < i8::MIN as i16 || product > i8::MAX as i16;
                }
                16 => {
                    let product = (self.cpu.eax as u16 as i16 as i32)
                        .wrapping_mul(operand as u16 as i16 as i32);
                    self.cpu.eax = (self.cpu.eax & 0xffff_0000) | product as u16 as u32;
                    self.cpu.edx = (self.cpu.edx & 0xffff_0000) | ((product >> 16) as u16 as u32);
                    self.cpu.cf = product < i16::MIN as i32 || product > i16::MAX as i32;
                }
                _ => {
                    let product = (self.cpu.eax as i32 as i64).wrapping_mul(operand as i32 as i64);
                    self.cpu.eax = product as u32;
                    self.cpu.edx = (product >> 32) as u32;
                    self.cpu.cf = product < i32::MIN as i64 || product > i32::MAX as i64;
                }
            }
            self.cpu.of = self.cpu.cf;
            return Ok(());
        }
        let (left, _) = self.cpu.read_operand(
            &self.memory,
            instruction,
            if instruction.op_count() == 2 { 0 } else { 1 },
        )?;
        let (right, _) =
            self.cpu
                .read_operand(&self.memory, instruction, instruction.op_count() - 1)?;
        let result = (left as i32).wrapping_mul(right as i32) as u32;
        self.cpu
            .write_operand(&mut self.memory, instruction, 0, result)?;
        self.cpu.set_logic_flags(result, 32);
        Ok(())
    }

    fn mul(&mut self, instruction: &Instruction) -> Result<(), DynamicError> {
        let (operand, size) = self.cpu.read_operand(&self.memory, instruction, 0)?;
        match size {
            8 => {
                let product = (self.cpu.eax & 0xff) * (operand & 0xff);
                self.cpu.write_register(iced_x86::Register::AX, product)?;
                self.cpu.cf = product > 0xff;
            }
            16 => {
                let product = (self.cpu.eax & 0xffff) * (operand & 0xffff);
                self.cpu.eax = (self.cpu.eax & 0xffff_0000) | (product & 0xffff);
                self.cpu.edx = (self.cpu.edx & 0xffff_0000) | (product >> 16);
                self.cpu.cf = product > 0xffff;
            }
            _ => {
                let product = self.cpu.eax as u64 * operand as u64;
                self.cpu.eax = product as u32;
                self.cpu.edx = (product >> 32) as u32;
                self.cpu.cf = self.cpu.edx != 0;
            }
        }
        self.cpu.of = self.cpu.cf;
        Ok(())
    }

    fn divide(&mut self, instruction: &Instruction) -> Result<(), DynamicError> {
        let (operand, size) = self.cpu.read_operand(&self.memory, instruction, 0)?;
        if operand == 0 {
            return Err(DynamicError::UnsupportedOperand("division by zero".into()));
        }
        let signed = instruction.mnemonic() == Mnemonic::Idiv;
        match (size, signed) {
            (8, false) => {
                let numerator = self.cpu.eax & 0xffff;
                let quotient = numerator / (operand & 0xff);
                if quotient > 0xff {
                    return Err(DynamicError::UnsupportedOperand(
                        "division quotient overflow".into(),
                    ));
                }
                let remainder = numerator % (operand & 0xff);
                self.cpu
                    .write_register(iced_x86::Register::AX, quotient | (remainder << 8))?;
            }
            (16, false) => {
                let numerator =
                    ((self.cpu.edx & 0xffff) as u64) << 16 | (self.cpu.eax & 0xffff) as u64;
                let divisor = (operand & 0xffff) as u64;
                let quotient = numerator / divisor;
                if quotient > 0xffff {
                    return Err(DynamicError::UnsupportedOperand(
                        "division quotient overflow".into(),
                    ));
                }
                self.cpu
                    .write_register(iced_x86::Register::AX, quotient as u32)?;
                self.cpu
                    .write_register(iced_x86::Register::DX, (numerator % divisor) as u32)?;
            }
            (32, false) => {
                let numerator = (self.cpu.edx as u64) << 32 | self.cpu.eax as u64;
                let quotient = numerator / operand as u64;
                if quotient > u32::MAX as u64 {
                    return Err(DynamicError::UnsupportedOperand(
                        "division quotient overflow".into(),
                    ));
                }
                self.cpu.eax = quotient as u32;
                self.cpu.edx = (numerator % operand as u64) as u32;
            }
            (8, true) => {
                let numerator = self.cpu.eax as u16 as i16;
                let divisor = operand as u8 as i8 as i16;
                let quotient = numerator.checked_div(divisor).ok_or_else(|| {
                    DynamicError::UnsupportedOperand("signed division overflow".into())
                })?;
                if !(i8::MIN as i16..=i8::MAX as i16).contains(&quotient) {
                    return Err(DynamicError::UnsupportedOperand(
                        "division quotient overflow".into(),
                    ));
                }
                let remainder = numerator % divisor;
                self.cpu.write_register(
                    iced_x86::Register::AX,
                    quotient as u8 as u32 | ((remainder as u8 as u32) << 8),
                )?;
            }
            (16, true) => {
                let numerator = (((self.cpu.edx & 0xffff) << 16) | (self.cpu.eax & 0xffff)) as i32;
                let divisor = operand as u16 as i16 as i32;
                let quotient = numerator.checked_div(divisor).ok_or_else(|| {
                    DynamicError::UnsupportedOperand("signed division overflow".into())
                })?;
                if !(i16::MIN as i32..=i16::MAX as i32).contains(&quotient) {
                    return Err(DynamicError::UnsupportedOperand(
                        "division quotient overflow".into(),
                    ));
                }
                self.cpu
                    .write_register(iced_x86::Register::AX, quotient as u16 as u32)?;
                self.cpu
                    .write_register(iced_x86::Register::DX, (numerator % divisor) as u16 as u32)?;
            }
            (_, true) => {
                let numerator = ((self.cpu.edx as u64) << 32 | self.cpu.eax as u64) as i64;
                let divisor = operand as i32 as i64;
                let quotient = numerator.checked_div(divisor).ok_or_else(|| {
                    DynamicError::UnsupportedOperand("signed division overflow".into())
                })?;
                if !(i32::MIN as i64..=i32::MAX as i64).contains(&quotient) {
                    return Err(DynamicError::UnsupportedOperand(
                        "division quotient overflow".into(),
                    ));
                }
                self.cpu.eax = quotient as u32;
                self.cpu.edx = (numerator % divisor) as u32;
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    fn branch_target(&self, instruction: &Instruction, operand: u32) -> Result<u32, DynamicError> {
        match instruction.op_kind(operand) {
            OpKind::NearBranch16 | OpKind::NearBranch32 => {
                Ok(instruction.near_branch_target() as u32)
            }
            _ => Ok(self.cpu.read_operand(&self.memory, instruction, operand)?.0),
        }
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

    fn string_operation(&mut self, instruction: &Instruction) -> Result<(), DynamicError> {
        let width = match instruction.mnemonic() {
            Mnemonic::Movsb
            | Mnemonic::Stosb
            | Mnemonic::Lodsb
            | Mnemonic::Cmpsb
            | Mnemonic::Scasb => 1usize,
            Mnemonic::Movsw
            | Mnemonic::Stosw
            | Mnemonic::Lodsw
            | Mnemonic::Cmpsw
            | Mnemonic::Scasw => 2usize,
            _ => 4usize,
        };
        let requested = if instruction.has_rep_prefix() || instruction.has_repne_prefix() {
            self.cpu.ecx
        } else {
            1
        };
        let available = self
            .options
            .max_instructions
            .saturating_sub(self.instruction_count)
            .saturating_add(1)
            .min(u32::MAX as u64) as u32;
        let repetitions = requested.min(available);
        let delta = if self.cpu.direction {
            0u32.wrapping_sub(width as u32)
        } else {
            width as u32
        };
        let mut completed = 0u32;
        for _ in 0..repetitions {
            match instruction.mnemonic() {
                Mnemonic::Movsb | Mnemonic::Movsw | Mnemonic::Movsd => {
                    let data = self.memory.read(self.cpu.esi, width)?.to_vec();
                    self.memory.write(self.cpu.edi, &data)?;
                    self.cpu.esi = self.cpu.esi.wrapping_add(delta);
                    self.cpu.edi = self.cpu.edi.wrapping_add(delta);
                }
                Mnemonic::Stosb | Mnemonic::Stosw | Mnemonic::Stosd => {
                    let bytes = self.cpu.eax.to_le_bytes();
                    self.memory.write(self.cpu.edi, &bytes[..width])?;
                    self.cpu.edi = self.cpu.edi.wrapping_add(delta);
                }
                Mnemonic::Lodsb => {
                    let value = self.memory.read_u8(self.cpu.esi)? as u32;
                    self.cpu.write_register(iced_x86::Register::AL, value)?;
                    self.cpu.esi = self.cpu.esi.wrapping_add(delta);
                }
                Mnemonic::Lodsw => {
                    let value = self.memory.read_u16(self.cpu.esi)? as u32;
                    self.cpu.write_register(iced_x86::Register::AX, value)?;
                    self.cpu.esi = self.cpu.esi.wrapping_add(delta);
                }
                Mnemonic::Lodsd => {
                    self.cpu.eax = self.memory.read_u32(self.cpu.esi)?;
                    self.cpu.esi = self.cpu.esi.wrapping_add(delta);
                }
                Mnemonic::Cmpsb | Mnemonic::Cmpsw | Mnemonic::Cmpsd => {
                    let left = match width {
                        1 => self.memory.read_u8(self.cpu.esi)? as u32,
                        2 => self.memory.read_u16(self.cpu.esi)? as u32,
                        _ => self.memory.read_u32(self.cpu.esi)?,
                    };
                    let right = match width {
                        1 => self.memory.read_u8(self.cpu.edi)? as u32,
                        2 => self.memory.read_u16(self.cpu.edi)? as u32,
                        _ => self.memory.read_u32(self.cpu.edi)?,
                    };
                    self.cpu.set_sub_flags(
                        left,
                        right,
                        left.wrapping_sub(right),
                        (width * 8) as u32,
                    );
                    self.cpu.esi = self.cpu.esi.wrapping_add(delta);
                    self.cpu.edi = self.cpu.edi.wrapping_add(delta);
                }
                Mnemonic::Scasb | Mnemonic::Scasw | Mnemonic::Scasd => {
                    let left = self.cpu.eax & crate::cpu::bit_mask((width * 8) as u32);
                    let right = match width {
                        1 => self.memory.read_u8(self.cpu.edi)? as u32,
                        2 => self.memory.read_u16(self.cpu.edi)? as u32,
                        _ => self.memory.read_u32(self.cpu.edi)?,
                    };
                    self.cpu.set_sub_flags(
                        left,
                        right,
                        left.wrapping_sub(right),
                        (width * 8) as u32,
                    );
                    self.cpu.edi = self.cpu.edi.wrapping_add(delta);
                }
                _ => unreachable!(),
            }
            completed += 1;
            if instruction.has_rep_prefix()
                && matches!(
                    instruction.mnemonic(),
                    Mnemonic::Cmpsb
                        | Mnemonic::Cmpsw
                        | Mnemonic::Cmpsd
                        | Mnemonic::Scasb
                        | Mnemonic::Scasw
                        | Mnemonic::Scasd
                )
                && !self.cpu.zf
            {
                break;
            }
            if instruction.has_repne_prefix()
                && matches!(
                    instruction.mnemonic(),
                    Mnemonic::Cmpsb
                        | Mnemonic::Cmpsw
                        | Mnemonic::Cmpsd
                        | Mnemonic::Scasb
                        | Mnemonic::Scasw
                        | Mnemonic::Scasd
                )
                && self.cpu.zf
            {
                break;
            }
        }
        if instruction.has_rep_prefix() || instruction.has_repne_prefix() {
            self.cpu.ecx = requested.saturating_sub(completed);
        }
        self.instruction_count = self
            .instruction_count
            .saturating_add(completed.saturating_sub(1) as u64);
        if completed == available && completed < requested {
            self.truncated = true;
            self.termination = Some(Termination::InstructionLimit);
        }
        Ok(())
    }

    fn handle_api(&mut self, import: ApiImport) -> Result<(), DynamicError> {
        let return_address = self.cpu.pop(&self.memory)?;
        let api_signature = signature(&import.name);
        let mut args = Vec::with_capacity(import.argument_count);
        for index in 0..import.argument_count {
            args.push(
                self.memory
                    .read_u32(self.cpu.esp.wrapping_add((index * 4) as u32))?,
            );
        }
        if api_signature.convention == CallingConvention::Stdcall {
            self.cpu.esp = self
                .cpu
                .esp
                .wrapping_add((import.argument_count * 4) as u32);
        }
        let lower = normalize_name(&import.name);
        self.unique_api_names.insert(lower.clone());
        if api_signature.modeled {
            self.modeled_api_calls += 1;
        } else {
            self.unmodeled_api_calls += 1;
        }
        let event_counts = (
            self.processes.len(),
            self.filesystem.len(),
            self.registry.len(),
            self.network.len(),
            self.memory_events.len(),
            self.injection.len(),
            self.persistence.len(),
        );
        let (result, summary, display_args) = self.emulate_api(&lower, &args)?;
        self.cpu.eax = result;
        self.cpu.eip = return_address;
        self.api_calls.push(ApiEvent {
            index: self.api_calls.len() as u64,
            instruction: self.instruction_count,
            module: import.module,
            name: import.name.clone(),
            arguments: display_args,
            result,
            summary: summary.clone(),
        });
        let (category, operation, subject) =
            self.timeline_details(&import.name, &summary, event_counts);
        self.timeline.push(TimelineEvent {
            sequence: self.timeline.len() as u64,
            instruction: self.instruction_count,
            virtual_time_ms: self.virtual_time_ms,
            category,
            operation,
            subject,
            source_api: import.name,
        });
        if let Some((code, name)) = self.queued_exception.take()
            && !self.dispatch_exception(
                code,
                &name,
                return_address,
                return_address,
                Termination::Halted,
            )
        {
            self.termination = Some(Termination::Halted);
        }
        if let Some(code) = self.thread_exit_requested.take() {
            self.finish_current_thread(code);
            if !self.schedule_next_thread(false) {
                self.termination = Some(Termination::ReturnedFromEntryPoint);
            }
        }
        Ok(())
    }

    fn timeline_details(
        &self,
        api: &str,
        summary: &str,
        before: (usize, usize, usize, usize, usize, usize, usize),
    ) -> (String, String, String) {
        if self.processes.len() > before.0 {
            let event = self.processes.last().expect("process event was appended");
            return (
                "process".into(),
                event.operation.clone(),
                event.command.clone(),
            );
        }
        if self.filesystem.len() > before.1 {
            let event = self.filesystem.last().expect("file event was appended");
            return (
                "filesystem".into(),
                event.operation.clone(),
                event.path.clone(),
            );
        }
        if self.registry.len() > before.2 {
            let event = self.registry.last().expect("registry event was appended");
            return (
                "registry".into(),
                event.operation.clone(),
                event.key.clone(),
            );
        }
        if self.network.len() > before.3 {
            let event = self.network.last().expect("network event was appended");
            return (
                "network".into(),
                event.operation.clone(),
                event.destination.clone(),
            );
        }
        if self.memory_events.len() > before.4 {
            let event = self
                .memory_events
                .last()
                .expect("memory event was appended");
            return (
                "memory".into(),
                event.operation.clone(),
                format!("0x{:08x}", event.address),
            );
        }
        if self.injection.len() > before.5 {
            let event = self.injection.last().expect("injection event was appended");
            return (
                "injection".into(),
                event.operation.clone(),
                format!(
                    "process 0x{:08x} at 0x{:08x}",
                    event.process_handle, event.address
                ),
            );
        }
        if self.persistence.len() > before.6 {
            let event = self
                .persistence
                .last()
                .expect("persistence event was appended");
            return (
                "persistence".into(),
                event.operation.clone(),
                event.target.clone(),
            );
        }
        ("api".into(), normalize_name(api), summary.into())
    }

    fn emulate_api(
        &mut self,
        name: &str,
        args: &[u32],
    ) -> Result<(u32, String, Vec<String>), DynamicError> {
        let hex_args = || {
            args.iter()
                .map(|value| format!("0x{value:08x}"))
                .collect::<Vec<_>>()
        };
        match name {
            "exitprocess" => {
                let code = args.first().copied().unwrap_or(0);
                self.terminate_all_threads(code);
                self.termination = Some(Termination::ExitProcess { code });
                Ok((
                    0,
                    format!("Process exited with code {code}"),
                    vec![code.to_string()],
                ))
            }
            "exitthread" => {
                let code = args.first().copied().unwrap_or(0);
                self.thread_exit_requested = Some(code);
                Ok((
                    0,
                    format!("Thread requested exit with code {code}"),
                    vec![code.to_string()],
                ))
            }
            "gettickcount" => Ok((
                self.virtual_time_ms as u32,
                "Returned deterministic virtual time".into(),
                Vec::new(),
            )),
            "sleep" => {
                let milliseconds = args.first().copied().unwrap_or(0).min(86_400_000);
                self.virtual_time_ms = self.virtual_time_ms.saturating_add(milliseconds as u64);
                Ok((
                    0,
                    format!("Advanced virtual clock by {milliseconds} ms"),
                    vec![milliseconds.to_string()],
                ))
            }
            "queryperformancecounter" => {
                let value = self.virtual_time_ms.saturating_mul(10_000);
                if let Some(pointer) = args.first().copied().filter(|pointer| *pointer != 0) {
                    let _ = self.memory.write(pointer, &value.to_le_bytes());
                }
                Ok((
                    1,
                    "Returned deterministic performance counter".into(),
                    vec![value.to_string()],
                ))
            }
            "getsysteminfo" => {
                if let Some(pointer) = args.first().copied().filter(|pointer| *pointer != 0) {
                    let mut info = [0u8; 36];
                    info[0..2].copy_from_slice(&0u16.to_le_bytes());
                    info[4..8].copy_from_slice(&4096u32.to_le_bytes());
                    info[20..24].copy_from_slice(&self.environment.cpu_count.to_le_bytes());
                    info[24..28].copy_from_slice(&586u32.to_le_bytes());
                    let _ = self.memory.write(pointer, &info);
                }
                Ok((
                    0,
                    "Returned deterministic x86 system profile".into(),
                    hex_args(),
                ))
            }
            "globalmemorystatusex" => {
                if let Some(pointer) = args.first().copied().filter(|pointer| *pointer != 0) {
                    let mut status = [0u8; 64];
                    status[0..4].copy_from_slice(&64u32.to_le_bytes());
                    status[4..8].copy_from_slice(&42u32.to_le_bytes());
                    let total = self.environment.memory_mb as u64 * 1024 * 1024;
                    status[8..16].copy_from_slice(&total.to_le_bytes());
                    status[16..24].copy_from_slice(&(total * 5 / 8).to_le_bytes());
                    let _ = self.memory.write(pointer, &status);
                }
                Ok((
                    1,
                    format!(
                        "Returned deterministic {} MiB memory profile",
                        self.environment.memory_mb
                    ),
                    hex_args(),
                ))
            }
            "getcomputernamea" | "getcomputernamew" | "getusernamea" | "getusernamew" => {
                let wide = name.ends_with('w');
                let value = if name.starts_with("getcomputer") {
                    self.environment.computer_name.clone()
                } else {
                    self.environment.user_name.clone()
                };
                let size_pointer = args.get(1).copied().unwrap_or(0);
                let capacity = self.memory.read_u32(size_pointer).unwrap_or(0) as usize;
                let written = self.write_guest_string(
                    args.first().copied().unwrap_or(0),
                    capacity,
                    &value,
                    wide,
                );
                if size_pointer != 0 {
                    let _ = self.memory.write_u32(size_pointer, written as u32);
                }
                Ok((
                    1,
                    format!("Returned synthetic identity {value}"),
                    vec![value],
                ))
            }
            "gettemppatha"
            | "gettemppathw"
            | "getwindowsdirectorya"
            | "getwindowsdirectoryw"
            | "getsystemdirectorya"
            | "getsystemdirectoryw" => {
                let wide = name.ends_with('w');
                let temp = format!(
                    "C:\\Users\\{}\\AppData\\Local\\Temp\\",
                    self.environment.user_name
                );
                let value = if name.starts_with("gettemp") {
                    temp.as_str()
                } else if name.starts_with("getsystem") {
                    "C:\\Windows\\System32"
                } else {
                    "C:\\Windows"
                };
                let written = self.write_guest_string(
                    args.get(1).copied().unwrap_or(0),
                    args.first().copied().unwrap_or(0) as usize,
                    value,
                    wide,
                );
                Ok((
                    written as u32,
                    format!("Returned synthetic directory {value}"),
                    vec![value.into()],
                ))
            }
            "gettempfilenamea" | "gettempfilenamew" => {
                let wide = name.ends_with('w');
                let path_pointer = args.first().copied().unwrap_or(0);
                let prefix_pointer = args.get(1).copied().unwrap_or(0);
                let path = if wide {
                    self.memory.read_wide_string(path_pointer, 512)
                } else {
                    self.memory.read_c_string(path_pointer, 512)
                };
                let prefix = if wide {
                    self.memory.read_wide_string(prefix_pointer, 16)
                } else {
                    self.memory.read_c_string(prefix_pointer, 16)
                };
                let value = format!("{}\\{}1337.tmp", path.trim_end_matches(['\\', '/']), prefix);
                self.write_guest_string(args.get(3).copied().unwrap_or(0), 260, &value, wide);
                Ok((
                    1337,
                    format!("Created synthetic temporary filename {value}"),
                    vec![value],
                ))
            }
            "getcurrentprocessid" => Ok((1337, "Returned synthetic process ID".into(), Vec::new())),
            "getcurrentthreadid" => {
                let tid = self
                    .thread_states
                    .get(self.current_thread)
                    .map_or(1, |thread| thread.tid);
                Ok((tid, "Returned synthetic thread ID".into(), Vec::new()))
            }
            "createthread" => {
                let start = args.get(2).copied().unwrap_or(0);
                let parameter = args.get(3).copied().unwrap_or(0);
                let tid = self.create_guest_thread(start, parameter);
                if let Some(pointer) = args.get(5).copied().filter(|pointer| *pointer != 0) {
                    let _ = self.memory.write_u32(pointer, tid);
                }
                let handle = if tid == 0 {
                    0
                } else {
                    self.windows
                        .allocate(HandleResource::Thread { tid })
                        .unwrap_or(0)
                };
                Ok((
                    handle,
                    if tid == 0 {
                        "CreateThread failed safely".into()
                    } else {
                        format!("Created runnable guest thread {tid} at 0x{start:08x}")
                    },
                    vec![
                        format!("0x{start:08x}"),
                        format!("0x{parameter:08x}"),
                        tid.to_string(),
                    ],
                ))
            }
            "getprocessheap" => Ok((0x50, "Returned synthetic process heap".into(), Vec::new())),
            "getcommandlinea" => Ok((
                COMMAND_LINE_A,
                "Returned synthetic ANSI command line".into(),
                Vec::new(),
            )),
            "getcommandlinew" => Ok((
                COMMAND_LINE_W,
                "Returned synthetic UTF-16 command line".into(),
                Vec::new(),
            )),
            "getlasterror" => Ok((
                self.windows.last_error(),
                "Returned synthetic last-error value".into(),
                Vec::new(),
            )),
            "setlasterror" => {
                let value = args.first().copied().unwrap_or(0);
                self.windows.set_last_error(value);
                Ok((
                    0,
                    format!("Set synthetic last-error value to {value}"),
                    vec![value.to_string()],
                ))
            }
            "getmodulehandlea" | "getmodulehandlew" => Ok((
                0x0040_0000,
                "Returned synthetic main-module handle".into(),
                hex_args(),
            )),
            "loadlibrarya" | "loadlibraryw" => {
                let pointer = args.first().copied().unwrap_or(0);
                let library = if name.ends_with('w') {
                    self.memory.read_wide_string(pointer, 260)
                } else {
                    self.memory.read_c_string(pointer, 260)
                };
                let handle = self
                    .windows
                    .allocate(HandleResource::Module {
                        name: library.clone(),
                    })
                    .unwrap_or(0);
                Ok((handle, format!("Modeled loading {library}"), vec![library]))
            }
            "getprocaddress" => {
                let module_handle = args.first().copied().unwrap_or(0);
                let symbol_pointer = args.get(1).copied().unwrap_or(0);
                let symbol = if symbol_pointer <= 0xffff {
                    format!("ordinal:{symbol_pointer}")
                } else {
                    self.memory.read_c_string(symbol_pointer, 260)
                };
                let module = self
                    .windows
                    .module_name(module_handle)
                    .unwrap_or("dynamic.dll")
                    .to_owned();
                let stub = self.dynamic_api_next;
                self.dynamic_api_next = self.dynamic_api_next.saturating_add(0x100);
                let api_signature = signature(&symbol);
                self.imports.insert(
                    stub,
                    ApiImport {
                        module: module.clone(),
                        name: symbol.clone(),
                        argument_count: api_signature.argument_count,
                    },
                );
                self.dynamic_api_resolutions += 1;
                Ok((
                    stub,
                    format!("Resolved dynamic symbol {module}!{symbol}"),
                    vec![module, symbol],
                ))
            }
            "winexec" => {
                let command = self
                    .memory
                    .read_c_string(args.first().copied().unwrap_or(0), 2_048);
                self.processes.push(ProcessEvent {
                    operation: "execute".into(),
                    command: command.clone(),
                    synthetic_result: "Captured only; no host process created".into(),
                });
                Ok((
                    33,
                    format!("Captured process execution request: {command}"),
                    vec![command, args.get(1).copied().unwrap_or(0).to_string()],
                ))
            }
            "createprocessa" | "createprocessw" => {
                let application_pointer = args.first().copied().unwrap_or(0);
                let command_pointer = args.get(1).copied().unwrap_or(0);
                let pointer = if command_pointer != 0 {
                    command_pointer
                } else {
                    application_pointer
                };
                let command = if name.ends_with('w') {
                    self.memory.read_wide_string(pointer, 2_048)
                } else {
                    self.memory.read_c_string(pointer, 2_048)
                };
                self.processes.push(ProcessEvent {
                    operation: "create".into(),
                    command: command.clone(),
                    synthetic_result: "Captured only; no host process created".into(),
                });
                Ok((
                    1,
                    format!("Captured process creation request: {command}"),
                    vec![command],
                ))
            }
            "shellexecutea" | "shellexecutew" => {
                let wide = name.ends_with('w');
                let file_pointer = args.get(2).copied().unwrap_or(0);
                let parameters_pointer = args.get(3).copied().unwrap_or(0);
                let file = if wide {
                    self.memory.read_wide_string(file_pointer, 1_024)
                } else {
                    self.memory.read_c_string(file_pointer, 1_024)
                };
                let parameters = if wide {
                    self.memory.read_wide_string(parameters_pointer, 2_048)
                } else {
                    self.memory.read_c_string(parameters_pointer, 2_048)
                };
                let command = format!("{file} {parameters}").trim().to_owned();
                self.processes.push(ProcessEvent {
                    operation: "shell_execute".into(),
                    command: command.clone(),
                    synthetic_result: "Captured only; no host process created".into(),
                });
                Ok((
                    33,
                    format!("Captured shell execution request: {command}"),
                    vec![command],
                ))
            }
            "openscmanagera" | "openscmanagerw" => {
                let handle = self
                    .windows
                    .allocate(HandleResource::Service {
                        name: "Service Control Manager".into(),
                    })
                    .unwrap_or(0);
                Ok((
                    handle,
                    "Opened synthetic Service Control Manager".into(),
                    vec![format!("0x{handle:08x}")],
                ))
            }
            "openservicea" | "openservicew" => {
                let pointer = args.get(1).copied().unwrap_or(0);
                let service = if name.ends_with('w') {
                    self.memory.read_wide_string(pointer, 512)
                } else {
                    self.memory.read_c_string(pointer, 512)
                };
                let handle = self
                    .windows
                    .allocate(HandleResource::Service {
                        name: service.clone(),
                    })
                    .unwrap_or(0);
                Ok((
                    handle,
                    format!("Opened synthetic service {service}"),
                    vec![service],
                ))
            }
            "createservicea" | "createservicew" => {
                let wide = name.ends_with('w');
                let service_pointer = args.get(1).copied().unwrap_or(0);
                let binary_pointer = args.get(7).copied().unwrap_or(0);
                let service = if wide {
                    self.memory.read_wide_string(service_pointer, 512)
                } else {
                    self.memory.read_c_string(service_pointer, 512)
                };
                let binary = if wide {
                    self.memory.read_wide_string(binary_pointer, 2_048)
                } else {
                    self.memory.read_c_string(binary_pointer, 2_048)
                };
                let handle = self
                    .windows
                    .allocate(HandleResource::Service {
                        name: service.clone(),
                    })
                    .unwrap_or(0);
                self.persistence.push(PersistenceEvent {
                    mechanism: "service".into(),
                    operation: "create".into(),
                    target: service.clone(),
                    value: Some(binary.clone()),
                });
                Ok((
                    handle,
                    format!("Created synthetic service {service} for {binary}"),
                    vec![service, binary],
                ))
            }
            "startservicea" | "startservicew" => {
                let handle = args.first().copied().unwrap_or(0);
                let service = self
                    .windows
                    .describe(handle)
                    .unwrap_or_else(|| format!("handle:0x{handle:08x}"));
                self.persistence.push(PersistenceEvent {
                    mechanism: "service".into(),
                    operation: "start".into(),
                    target: service.clone(),
                    value: None,
                });
                Ok((
                    1,
                    format!("Started synthetic service {service}"),
                    vec![service],
                ))
            }
            "deleteservice" => {
                let handle = args.first().copied().unwrap_or(0);
                let service = self
                    .windows
                    .describe(handle)
                    .unwrap_or_else(|| format!("handle:0x{handle:08x}"));
                self.persistence.push(PersistenceEvent {
                    mechanism: "service".into(),
                    operation: "delete".into(),
                    target: service.clone(),
                    value: None,
                });
                Ok((
                    1,
                    format!("Deleted synthetic service {service}"),
                    vec![service],
                ))
            }
            "heapalloc" => self.heap_alloc(args.get(2).copied().unwrap_or(0), "HeapAlloc"),
            "localalloc" => self.heap_alloc(args.get(1).copied().unwrap_or(0), "LocalAlloc"),
            "globalalloc" => self.heap_alloc(args.get(1).copied().unwrap_or(0), "GlobalAlloc"),
            "heapcreate" => {
                let handle = self
                    .windows
                    .allocate(HandleResource::Heap {
                        label: "private heap".into(),
                    })
                    .unwrap_or(0);
                Ok((
                    handle,
                    "Created synthetic private heap".into(),
                    vec![format!("0x{handle:08x}")],
                ))
            }
            "heaprealloc" => {
                let old = args.get(2).copied().unwrap_or(0);
                let _ = self.memory.unmap(old);
                self.heap_alloc(args.get(3).copied().unwrap_or(0), "HeapReAlloc")
            }
            "heapfree" => self.heap_free(args.get(2).copied().unwrap_or(0), "HeapFree"),
            "localfree" => self.heap_free(args.first().copied().unwrap_or(0), "LocalFree"),
            "globalfree" => self.heap_free(args.first().copied().unwrap_or(0), "GlobalFree"),
            "heapdestroy" => {
                let handle = args.first().copied().unwrap_or(0);
                let closed = self.windows.close(handle);
                Ok((
                    u32::from(closed),
                    "Released synthetic heap handle".into(),
                    hex_args(),
                ))
            }
            "virtualfree" => self.heap_free(args.first().copied().unwrap_or(0), "VirtualFree"),
            "getenvironmentvariablea" | "getenvironmentvariablew" => {
                let wide = name.ends_with('w');
                let name_pointer = args.first().copied().unwrap_or(0);
                let variable = if wide {
                    self.memory.read_wide_string(name_pointer, 256)
                } else {
                    self.memory.read_c_string(name_pointer, 256)
                };
                let value = match variable.to_ascii_uppercase().as_str() {
                    "TEMP" | "TMP" => format!(
                        "C:\\Users\\{}\\AppData\\Local\\Temp",
                        self.environment.user_name
                    ),
                    "USERNAME" => self.environment.user_name.clone(),
                    "COMPUTERNAME" => self.environment.computer_name.clone(),
                    "WINDIR" => "C:\\Windows".into(),
                    _ => String::new(),
                };
                let destination = args.get(1).copied().unwrap_or(0);
                let capacity = args.get(2).copied().unwrap_or(0) as usize;
                let written = self.write_guest_string(destination, capacity, &value, wide);
                Ok((
                    written as u32,
                    format!("Returned synthetic environment variable {variable}"),
                    vec![variable, value],
                ))
            }
            "lstrlena" | "lstrlenw" | "strlen" => {
                let pointer = args.first().copied().unwrap_or(0);
                let length = if name.ends_with('w') {
                    self.memory
                        .read_wide_string(pointer, 4_096)
                        .encode_utf16()
                        .count()
                } else {
                    self.memory.read_c_string(pointer, 4_096).len()
                };
                Ok((
                    length as u32,
                    format!("Measured bounded string length {length}"),
                    vec![length.to_string()],
                ))
            }
            "lstrcpya" | "lstrcpyw" | "lstrcata" | "lstrcatw" => {
                let destination = args.first().copied().unwrap_or(0);
                let source = args.get(1).copied().unwrap_or(0);
                let wide = name.ends_with('w');
                let source_value = if wide {
                    self.memory.read_wide_string(source, 4_096)
                } else {
                    self.memory.read_c_string(source, 4_096)
                };
                let value = if name.starts_with("lstrcat") {
                    let current = if wide {
                        self.memory.read_wide_string(destination, 4_096)
                    } else {
                        self.memory.read_c_string(destination, 4_096)
                    };
                    format!("{current}{source_value}")
                } else {
                    source_value
                };
                self.write_guest_string(destination, 4_096, &value, wide);
                Ok((
                    destination,
                    "Copied bounded synthetic string".into(),
                    vec![value],
                ))
            }
            "multibytetowidechar" => {
                let source = self
                    .memory
                    .read_c_string(args.get(2).copied().unwrap_or(0), 4_096);
                let destination = args.get(4).copied().unwrap_or(0);
                let capacity = args.get(5).copied().unwrap_or(0) as usize;
                let written = self.write_guest_string(destination, capacity, &source, true);
                Ok((
                    written as u32,
                    "Converted bounded ANSI string to UTF-16".into(),
                    vec![source],
                ))
            }
            "widechartomultibyte" => {
                let source = self
                    .memory
                    .read_wide_string(args.get(2).copied().unwrap_or(0), 4_096);
                let destination = args.get(4).copied().unwrap_or(0);
                let capacity = args.get(5).copied().unwrap_or(0) as usize;
                let written = self.write_guest_string(destination, capacity, &source, false);
                Ok((
                    written as u32,
                    "Converted bounded UTF-16 string to ANSI".into(),
                    vec![source],
                ))
            }
            "rtlmovememory" | "memcpy" | "memmove" => {
                let destination = args.first().copied().unwrap_or(0);
                let source = args.get(1).copied().unwrap_or(0);
                let length = args.get(2).copied().unwrap_or(0).min(1024 * 1024) as usize;
                let data = self.memory.read(source, length)?.to_vec();
                self.memory.write(destination, &data)?;
                Ok((
                    destination,
                    format!("Copied {length} bounded memory bytes"),
                    vec![format!("0x{source:08x}"), format!("0x{destination:08x}")],
                ))
            }
            "rtlzeromemory" => {
                let destination = args.first().copied().unwrap_or(0);
                let length = args.get(1).copied().unwrap_or(0).min(1024 * 1024) as usize;
                self.memory.write(destination, &vec![0; length])?;
                Ok((
                    0,
                    format!("Zeroed {length} bounded memory bytes"),
                    vec![format!("0x{destination:08x}")],
                ))
            }
            "memset" => {
                let destination = args.first().copied().unwrap_or(0);
                let value = args.get(1).copied().unwrap_or(0) as u8;
                let length = args.get(2).copied().unwrap_or(0).min(1024 * 1024) as usize;
                self.memory.write(destination, &vec![value; length])?;
                Ok((
                    destination,
                    format!("Set {length} bounded memory bytes"),
                    vec![format!("0x{destination:08x}")],
                ))
            }
            "strcmp" => {
                let left = self
                    .memory
                    .read_c_string(args.first().copied().unwrap_or(0), 4_096);
                let right = self
                    .memory
                    .read_c_string(args.get(1).copied().unwrap_or(0), 4_096);
                let result = match left.as_bytes().cmp(right.as_bytes()) {
                    std::cmp::Ordering::Less => -1i32,
                    std::cmp::Ordering::Equal => 0,
                    std::cmp::Ordering::Greater => 1,
                };
                Ok((
                    result as u32,
                    "Compared two bounded strings".into(),
                    vec![left, right],
                ))
            }
            "interlockedincrement" | "interlockeddecrement" => {
                let pointer = args.first().copied().unwrap_or(0);
                let current = self.memory.read_u32(pointer)?;
                let result = if name.ends_with("increment") {
                    current.wrapping_add(1)
                } else {
                    current.wrapping_sub(1)
                };
                self.memory.write_u32(pointer, result)?;
                Ok((
                    result,
                    "Updated synthetic interlocked value".into(),
                    vec![result.to_string()],
                ))
            }
            "interlockedexchange" => {
                let pointer = args.first().copied().unwrap_or(0);
                let current = self.memory.read_u32(pointer)?;
                self.memory
                    .write_u32(pointer, args.get(1).copied().unwrap_or(0))?;
                Ok((
                    current,
                    "Exchanged synthetic interlocked value".into(),
                    hex_args(),
                ))
            }
            "interlockedcompareexchange" => {
                let pointer = args.first().copied().unwrap_or(0);
                let current = self.memory.read_u32(pointer)?;
                if current == args.get(2).copied().unwrap_or(0) {
                    self.memory
                        .write_u32(pointer, args.get(1).copied().unwrap_or(0))?;
                }
                Ok((
                    current,
                    "Compared and exchanged synthetic interlocked value".into(),
                    hex_args(),
                ))
            }
            "isdebuggerpresent" => Ok((
                u32::from(self.environment.debugger_present),
                format!(
                    "Returned deterministic debugger state: {}",
                    self.environment.debugger_present
                ),
                Vec::new(),
            )),
            "addvectoredexceptionhandler" => {
                let first = args.first().copied().unwrap_or(0) != 0;
                let handler = args.get(1).copied().unwrap_or(0);
                if handler == 0
                    || self.memory.fetch(handler, 1).is_err()
                    || self.vectored_handlers.len() >= MAX_SEH_DEPTH
                {
                    return Ok((
                        0,
                        "Rejected invalid vectored exception handler".into(),
                        hex_args(),
                    ));
                }
                if first {
                    self.vectored_handlers.insert(0, handler);
                } else {
                    self.vectored_handlers.push(handler);
                }
                Ok((
                    handler,
                    format!("Registered synthetic vectored handler 0x{handler:08x}"),
                    vec![format!("0x{handler:08x}")],
                ))
            }
            "removevectoredexceptionhandler" => {
                let handler = args.first().copied().unwrap_or(0);
                let removed = self
                    .vectored_handlers
                    .iter()
                    .position(|value| *value == handler)
                    .map(|index| self.vectored_handlers.remove(index))
                    .is_some();
                Ok((
                    u32::from(removed),
                    format!(
                        "{} synthetic vectored handler 0x{handler:08x}",
                        if removed { "Removed" } else { "Did not find" }
                    ),
                    vec![format!("0x{handler:08x}")],
                ))
            }
            "raiseexception" => {
                let code = args.first().copied().unwrap_or(0xe000_0001);
                self.queued_exception = Some((code, "raised_exception".into()));
                Ok((
                    0,
                    format!("Queued synthetic exception 0x{code:08x}"),
                    hex_args(),
                ))
            }
            "checkremotedebuggerpresent" => {
                if let Some(pointer) = args.get(1).copied().filter(|pointer| *pointer != 0) {
                    let _ = self
                        .memory
                        .write_u32(pointer, u32::from(self.environment.debugger_present));
                }
                Ok((
                    1,
                    format!(
                        "Returned deterministic debugger state: {}",
                        self.environment.debugger_present
                    ),
                    hex_args(),
                ))
            }
            "ntqueryinformationprocess" => {
                let output = args.get(2).copied().unwrap_or(0);
                let length = args.get(3).copied().unwrap_or(0).min(64);
                if output != 0 && length != 0 {
                    let zeroes = vec![0; length as usize];
                    let _ = self.memory.write(output, &zeroes);
                }
                Ok((
                    0,
                    "Returned deterministic synthetic process information".into(),
                    hex_args(),
                ))
            }
            "openprocess" => {
                let pid = args.get(2).copied().unwrap_or(0);
                let handle = self.windows.open_process(pid).unwrap_or(0);
                self.processes.push(ProcessEvent {
                    operation: "open".into(),
                    command: format!("pid:{pid}"),
                    synthetic_result: "Synthetic process handle only".into(),
                });
                Ok((
                    handle,
                    format!("Opened synthetic process {pid}"),
                    vec![pid.to_string()],
                ))
            }
            "virtualallocex" => {
                let process_handle = args.first().copied().unwrap_or(0);
                let requested = args.get(1).copied().unwrap_or(0);
                let size = align_page(args.get(2).copied().unwrap_or(0).max(1) as usize) as u32;
                let address = if requested == 0 {
                    let value = self.heap_next;
                    self.heap_next = self.heap_next.saturating_add(size + 0x1000);
                    value
                } else {
                    requested
                };
                let allocated =
                    self.windows
                        .allocate_remote(process_handle, address, size as usize);
                self.injection.push(InjectionEvent {
                    operation: "allocate_remote".into(),
                    process_handle,
                    address,
                    size,
                    preview: None,
                });
                Ok((
                    if allocated { address } else { 0 },
                    format!(
                        "Allocated {size} synthetic remote bytes in process 0x{process_handle:08x}"
                    ),
                    vec![
                        format!("0x{process_handle:08x}"),
                        format!("0x{address:08x}"),
                        size.to_string(),
                    ],
                ))
            }
            "writeprocessmemory" => {
                let process_handle = args.first().copied().unwrap_or(0);
                let address = args.get(1).copied().unwrap_or(0);
                let length = args.get(3).copied().unwrap_or(0).min(65_536);
                let data = self
                    .memory
                    .read(args.get(2).copied().unwrap_or(0), length as usize)
                    .unwrap_or_default();
                let written = self.windows.write_remote(process_handle, address, data) as u32;
                let preview = printable_preview(&data[..written as usize]);
                if let Some(pointer) = args.get(4).copied().filter(|pointer| *pointer != 0) {
                    let _ = self.memory.write_u32(pointer, written);
                }
                self.injection.push(InjectionEvent {
                    operation: "write_remote".into(),
                    process_handle,
                    address,
                    size: written,
                    preview: Some(preview.clone()),
                });
                Ok((
                    u32::from(written == length),
                    format!(
                        "Captured {written} bytes written to remote process 0x{process_handle:08x}"
                    ),
                    vec![format!("0x{address:08x}"), preview],
                ))
            }
            "virtualprotectex" => {
                let process_handle = args.first().copied().unwrap_or(0);
                let address = args.get(1).copied().unwrap_or(0);
                let size = args.get(2).copied().unwrap_or(0);
                self.injection.push(InjectionEvent {
                    operation: "protect_remote".into(),
                    process_handle,
                    address,
                    size,
                    preview: Some(protection(args.get(3).copied().unwrap_or(0)).display()),
                });
                Ok((
                    1,
                    format!(
                        "Changed synthetic remote protection in process 0x{process_handle:08x}"
                    ),
                    vec![format!("0x{address:08x}"), size.to_string()],
                ))
            }
            "createremotethread" => {
                let process_handle = args.first().copied().unwrap_or(0);
                let address = args.get(3).copied().unwrap_or(0);
                let handle = self
                    .windows
                    .allocate(HandleResource::Thread { tid: 2001 })
                    .unwrap_or(0);
                if let Some(pointer) = args.get(6).copied().filter(|pointer| *pointer != 0) {
                    let _ = self.memory.write_u32(pointer, 2001);
                }
                self.injection.push(InjectionEvent {
                    operation: "execute_remote".into(),
                    process_handle,
                    address,
                    size: 0,
                    preview: Some("CreateRemoteThread".into()),
                });
                Ok((
                    handle,
                    format!("Captured remote thread creation in process 0x{process_handle:08x}"),
                    vec![format!("0x{address:08x}")],
                ))
            }
            "queueuserapc" => {
                let address = args.first().copied().unwrap_or(0);
                let thread_handle = args.get(1).copied().unwrap_or(0);
                self.injection.push(InjectionEvent {
                    operation: "queue_apc".into(),
                    process_handle: thread_handle,
                    address,
                    size: 0,
                    preview: None,
                });
                Ok((
                    1,
                    format!("Queued synthetic APC on thread 0x{thread_handle:08x}"),
                    vec![format!("0x{address:08x}")],
                ))
            }
            "resumethread" => {
                let handle = args.first().copied().unwrap_or(0);
                self.injection.push(InjectionEvent {
                    operation: "resume_thread".into(),
                    process_handle: handle,
                    address: 0,
                    size: 0,
                    preview: None,
                });
                Ok((
                    1,
                    format!("Resumed synthetic thread 0x{handle:08x}"),
                    vec![format!("0x{handle:08x}")],
                ))
            }
            "virtualalloc" => self.virtual_alloc(args),
            "virtualprotect" => self.virtual_protect(args),
            "createfilea" | "createfilew" => {
                let pointer = args.first().copied().unwrap_or(0);
                let path = if name.ends_with('w') {
                    self.memory.read_wide_string(pointer, 1_024)
                } else {
                    self.memory.read_c_string(pointer, 1_024)
                };
                let handle = self.windows.open_file(path.clone()).unwrap_or(u32::MAX);
                self.filesystem.push(FileEvent {
                    operation: "open".into(),
                    path: path.clone(),
                    size: None,
                    preview: None,
                });
                Ok((handle, format!("Opened virtual file {path}"), vec![path]))
            }
            "writefile" => {
                let file_handle = args.first().copied().unwrap_or(0);
                let requested = args.get(2).copied().unwrap_or(0).min(65_536);
                let data = self
                    .memory
                    .read(args.get(1).copied().unwrap_or(0), requested as usize)
                    .unwrap_or_default();
                let length = self.windows.write_file(file_handle, data) as u32;
                let preview = printable_preview(&data[..length as usize]);
                if let Some(pointer) = args.get(3).copied().filter(|pointer| *pointer != 0) {
                    let _ = self.memory.write_u32(pointer, length);
                }
                self.filesystem.push(FileEvent {
                    operation: "write".into(),
                    path: self
                        .windows
                        .file_path(file_handle)
                        .map(str::to_owned)
                        .unwrap_or_else(|| format!("handle:0x{file_handle:x}")),
                    size: Some(length),
                    preview: Some(preview.clone()),
                });
                Ok((
                    1,
                    format!("Captured {length} bytes written to a virtual file"),
                    vec![
                        self.windows
                            .file_path(file_handle)
                            .map(str::to_owned)
                            .unwrap_or_else(|| format!("handle:0x{file_handle:x}")),
                        preview,
                    ],
                ))
            }
            "readfile" => {
                let handle = args.first().copied().unwrap_or(0);
                let requested = args.get(2).copied().unwrap_or(0).min(65_536) as usize;
                let data = self.windows.read_file(handle, requested);
                if !data.is_empty() {
                    let _ = self.memory.write(args.get(1).copied().unwrap_or(0), &data);
                }
                if let Some(pointer) = args.get(3).copied().filter(|pointer| *pointer != 0) {
                    let _ = self.memory.write_u32(pointer, data.len() as u32);
                }
                let path = self
                    .windows
                    .file_path(handle)
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("handle:0x{handle:x}"));
                self.filesystem.push(FileEvent {
                    operation: "read".into(),
                    path: path.clone(),
                    size: Some(data.len() as u32),
                    preview: Some(printable_preview(&data)),
                });
                Ok((
                    1,
                    format!("Read {} bytes from virtual file {path}", data.len()),
                    vec![path],
                ))
            }
            "setfilepointer" => {
                let handle = args.first().copied().unwrap_or(0);
                let distance = args.get(1).copied().unwrap_or(0) as i32;
                let method = args.get(3).copied().unwrap_or(0);
                let offset = self
                    .windows
                    .set_file_offset(handle, distance, method)
                    .map(|value| value as u32)
                    .unwrap_or(u32::MAX);
                Ok((
                    offset,
                    format!("Moved virtual file pointer to {offset}"),
                    vec![format!("0x{handle:08x}")],
                ))
            }
            "getfilesize" => {
                let handle = args.first().copied().unwrap_or(0);
                let size = self
                    .windows
                    .file_size(handle)
                    .map(|value| value as u32)
                    .unwrap_or(u32::MAX);
                if let Some(high) = args.get(1).copied().filter(|pointer| *pointer != 0) {
                    let _ = self.memory.write_u32(high, 0);
                }
                Ok((
                    size,
                    format!("Returned virtual file size {size}"),
                    vec![format!("0x{handle:08x}")],
                ))
            }
            "deletefilea" | "deletefilew" => {
                let pointer = args.first().copied().unwrap_or(0);
                let path = if name.ends_with('w') {
                    self.memory.read_wide_string(pointer, 1_024)
                } else {
                    self.memory.read_c_string(pointer, 1_024)
                };
                let removed = self.windows.delete_file(&path);
                self.filesystem.push(FileEvent {
                    operation: "delete".into(),
                    path: path.clone(),
                    size: None,
                    preview: None,
                });
                Ok((
                    u32::from(removed),
                    format!("Deleted virtual file {path}"),
                    vec![path],
                ))
            }
            "copyfilea" | "copyfilew" | "movefilea" | "movefilew" => {
                let wide = name.ends_with('w');
                let source_pointer = args.first().copied().unwrap_or(0);
                let destination_pointer = args.get(1).copied().unwrap_or(0);
                let source = if wide {
                    self.memory.read_wide_string(source_pointer, 1_024)
                } else {
                    self.memory.read_c_string(source_pointer, 1_024)
                };
                let destination = if wide {
                    self.memory.read_wide_string(destination_pointer, 1_024)
                } else {
                    self.memory.read_c_string(destination_pointer, 1_024)
                };
                let moved = name.starts_with("move");
                let success = if moved {
                    self.windows.move_file(&source, &destination)
                } else {
                    self.windows.copy_file(&source, &destination)
                };
                self.filesystem.push(FileEvent {
                    operation: if moved { "move".into() } else { "copy".into() },
                    path: format!("{source} -> {destination}"),
                    size: None,
                    preview: None,
                });
                Ok((
                    u32::from(success),
                    format!(
                        "{} virtual file {source} to {destination}",
                        if moved { "Moved" } else { "Copied" }
                    ),
                    vec![source, destination],
                ))
            }
            "createdirectorya" | "createdirectoryw" | "removedirectorya" | "removedirectoryw" => {
                let pointer = args.first().copied().unwrap_or(0);
                let path = if name.ends_with('w') {
                    self.memory.read_wide_string(pointer, 1_024)
                } else {
                    self.memory.read_c_string(pointer, 1_024)
                };
                let create = name.starts_with("create");
                self.filesystem.push(FileEvent {
                    operation: if create {
                        "create_directory".into()
                    } else {
                        "remove_directory".into()
                    },
                    path: path.clone(),
                    size: None,
                    preview: None,
                });
                Ok((
                    1,
                    format!(
                        "{} virtual directory {path}",
                        if create { "Created" } else { "Removed" }
                    ),
                    vec![path],
                ))
            }
            "getfileattributesa" | "getfileattributesw" => {
                let pointer = args.first().copied().unwrap_or(0);
                let path = if name.ends_with('w') {
                    self.memory.read_wide_string(pointer, 1_024)
                } else {
                    self.memory.read_c_string(pointer, 1_024)
                };
                Ok((
                    0x80,
                    format!("Returned synthetic normal-file attributes for {path}"),
                    vec![path],
                ))
            }
            "regopenkeyexa" | "regopenkeyexw" => {
                let pointer = args.get(1).copied().unwrap_or(0);
                let key = if name.ends_with('w') {
                    self.memory.read_wide_string(pointer, 1_024)
                } else {
                    self.memory.read_c_string(pointer, 1_024)
                };
                let handle = self
                    .windows
                    .allocate(HandleResource::Registry { key: key.clone() })
                    .unwrap_or(0);
                if let Some(output) = args.get(4).copied().filter(|pointer| *pointer != 0) {
                    let _ = self.memory.write_u32(output, handle);
                }
                self.registry.push(RegistryEvent {
                    operation: "open".into(),
                    key: key.clone(),
                    value: None,
                });
                Ok((0, format!("Opened synthetic registry key {key}"), vec![key]))
            }
            "regcreatekeyexa" | "regcreatekeyexw" => {
                let pointer = args.get(1).copied().unwrap_or(0);
                let key = if name.ends_with('w') {
                    self.memory.read_wide_string(pointer, 1_024)
                } else {
                    self.memory.read_c_string(pointer, 1_024)
                };
                let handle = self
                    .windows
                    .allocate(HandleResource::Registry { key: key.clone() })
                    .unwrap_or(0);
                if let Some(output) = args.get(7).copied().filter(|pointer| *pointer != 0) {
                    let _ = self.memory.write_u32(output, handle);
                }
                if let Some(disposition) = args.get(8).copied().filter(|pointer| *pointer != 0) {
                    let _ = self.memory.write_u32(disposition, 1);
                }
                self.registry.push(RegistryEvent {
                    operation: "create".into(),
                    key: key.clone(),
                    value: None,
                });
                Ok((
                    0,
                    format!("Created synthetic registry key {key}"),
                    vec![key],
                ))
            }
            "regsetvalueexa" | "regsetvalueexw" => {
                let pointer = args.get(1).copied().unwrap_or(0);
                let value_name = if name.ends_with('w') {
                    self.memory.read_wide_string(pointer, 512)
                } else {
                    self.memory.read_c_string(pointer, 512)
                };
                let length = args.get(5).copied().unwrap_or(0).min(4_096);
                let data = self
                    .memory
                    .read(args.get(4).copied().unwrap_or(0), length as usize)
                    .unwrap_or_default();
                let preview = printable_preview(data);
                let handle = args.first().copied().unwrap_or(0);
                let _ = self.windows.set_registry_value(handle, &value_name, data);
                self.registry.push(RegistryEvent {
                    operation: "set".into(),
                    key: format!(
                        "{}\\{value_name}",
                        self.windows
                            .describe(handle)
                            .unwrap_or_else(|| format!("handle:0x{:x}", handle))
                    ),
                    value: Some(preview.clone()),
                });
                Ok((
                    0,
                    format!("Set synthetic registry value {value_name}"),
                    vec![value_name, preview],
                ))
            }
            "regqueryvalueexa" | "regqueryvalueexw" => {
                let handle = args.first().copied().unwrap_or(0);
                let pointer = args.get(1).copied().unwrap_or(0);
                let value_name = if name.ends_with('w') {
                    self.memory.read_wide_string(pointer, 512)
                } else {
                    self.memory.read_c_string(pointer, 512)
                };
                let data = self
                    .windows
                    .registry_value(handle, &value_name)
                    .unwrap_or_default()
                    .to_vec();
                if let Some(kind_pointer) = args.get(3).copied().filter(|pointer| *pointer != 0) {
                    let _ = self.memory.write_u32(kind_pointer, 1);
                }
                let size_pointer = args.get(5).copied().unwrap_or(0);
                let capacity = self.memory.read_u32(size_pointer).unwrap_or(0) as usize;
                let written = data.len().min(capacity);
                if let Some(data_pointer) = args.get(4).copied().filter(|pointer| *pointer != 0) {
                    let _ = self.memory.write(data_pointer, &data[..written]);
                }
                if size_pointer != 0 {
                    let _ = self.memory.write_u32(size_pointer, data.len() as u32);
                }
                let key = format!(
                    "{}\\{value_name}",
                    self.windows.registry_path(handle).unwrap_or("<invalid>")
                );
                self.registry.push(RegistryEvent {
                    operation: "query".into(),
                    key: key.clone(),
                    value: Some(printable_preview(&data)),
                });
                Ok((
                    if data.is_empty() { 2 } else { 0 },
                    format!("Queried synthetic registry value {key}"),
                    vec![key],
                ))
            }
            "regdeletevaluea" | "regdeletevaluew" => {
                let handle = args.first().copied().unwrap_or(0);
                let pointer = args.get(1).copied().unwrap_or(0);
                let value_name = if name.ends_with('w') {
                    self.memory.read_wide_string(pointer, 512)
                } else {
                    self.memory.read_c_string(pointer, 512)
                };
                let key = format!(
                    "{}\\{value_name}",
                    self.windows.registry_path(handle).unwrap_or("<invalid>")
                );
                let removed = self.windows.delete_registry_value(handle, &value_name);
                self.registry.push(RegistryEvent {
                    operation: "delete_value".into(),
                    key: key.clone(),
                    value: None,
                });
                Ok((
                    if removed { 0 } else { 2 },
                    format!("Deleted synthetic registry value {key}"),
                    vec![key],
                ))
            }
            "regdeletekeya" | "regdeletekeyw" => {
                let pointer = args.get(1).copied().unwrap_or(0);
                let key = if name.ends_with('w') {
                    self.memory.read_wide_string(pointer, 1_024)
                } else {
                    self.memory.read_c_string(pointer, 1_024)
                };
                self.registry.push(RegistryEvent {
                    operation: "delete_key".into(),
                    key: key.clone(),
                    value: None,
                });
                Ok((
                    0,
                    format!("Deleted synthetic registry key {key}"),
                    vec![key],
                ))
            }
            "internetopena" | "internetopenw" => {
                let pointer = args.first().copied().unwrap_or(0);
                let agent = if name.ends_with('w') {
                    self.memory.read_wide_string(pointer, 512)
                } else {
                    self.memory.read_c_string(pointer, 512)
                };
                let handle = self
                    .windows
                    .allocate(HandleResource::Internet {
                        label: agent.clone(),
                    })
                    .unwrap_or(0);
                Ok((
                    handle,
                    format!("Created synthetic internet session for {agent}"),
                    vec![agent],
                ))
            }
            "internetopenurla" | "internetopenurlw" => {
                let pointer = args.get(1).copied().unwrap_or(0);
                let url = if name.ends_with('w') {
                    self.memory.read_wide_string(pointer, 2_048)
                } else {
                    self.memory.read_c_string(pointer, 2_048)
                };
                let offline = self.environment.network_mode == NetworkMode::Offline;
                self.network.push(NetworkEvent {
                    operation: "http_open".into(),
                    destination: url.clone(),
                    size: None,
                    preview: None,
                    synthetic_result: if offline {
                        "offline profile rejected request".into()
                    } else {
                        "HTTP 404 from local sink".into()
                    },
                });
                if offline {
                    return Ok((
                        0,
                        format!("Synthetic offline profile rejected {url}"),
                        vec![url],
                    ));
                }
                let handle = self
                    .windows
                    .allocate(HandleResource::Internet { label: url.clone() })
                    .unwrap_or(0);
                Ok((handle, format!("Captured HTTP request to {url}"), vec![url]))
            }
            "wsastartup" => {
                if let Some(pointer) = args.get(1).copied().filter(|pointer| *pointer != 0) {
                    let mut data = [0u8; 64];
                    data[0..2].copy_from_slice(&0x0202u16.to_le_bytes());
                    data[2..4].copy_from_slice(&0x0202u16.to_le_bytes());
                    let _ = self.memory.write(pointer, &data);
                }
                Ok((0, "Initialized synthetic Winsock 2.2".into(), hex_args()))
            }
            "socket" => {
                let handle = self
                    .windows
                    .allocate(HandleResource::Internet {
                        label: "winsock socket".into(),
                    })
                    .unwrap_or(u32::MAX);
                Ok((
                    handle,
                    "Created synthetic network socket".into(),
                    hex_args(),
                ))
            }
            "closesocket" => {
                let handle = args.first().copied().unwrap_or(0);
                let closed = self.windows.close(handle);
                Ok((
                    if closed { 0 } else { u32::MAX },
                    "Closed synthetic network socket".into(),
                    vec![format!("0x{handle:08x}")],
                ))
            }
            "gethostbyname" => {
                let query = self
                    .memory
                    .read_c_string(args.first().copied().unwrap_or(0), 512);
                if self.environment.network_mode == NetworkMode::Offline {
                    self.network.push(NetworkEvent {
                        operation: "dns".into(),
                        destination: query.clone(),
                        size: None,
                        preview: None,
                        synthetic_result: "offline profile returned host-not-found".into(),
                    });
                    return Ok((
                        0,
                        format!("Synthetic offline DNS failure for {query}"),
                        vec![query],
                    ));
                }
                let name_address = NETWORK_RESULT_BASE + 0x40;
                let ip_address = NETWORK_RESULT_BASE + 0x80;
                let list_address = NETWORK_RESULT_BASE + 0x90;
                let aliases_address = NETWORK_RESULT_BASE + 0xa0;
                let _ = self
                    .memory
                    .write(name_address, &[query.as_bytes(), &[0]].concat());
                let _ = self.memory.write(ip_address, &[10, 20, 30, 40]);
                let _ = self.memory.write_u32(list_address, ip_address);
                let _ = self.memory.write_u32(list_address + 4, 0);
                let _ = self.memory.write_u32(aliases_address, 0);
                let _ = self.memory.write_u32(NETWORK_RESULT_BASE, name_address);
                let _ = self
                    .memory
                    .write_u32(NETWORK_RESULT_BASE + 4, aliases_address);
                let _ = self.memory.write_u16(NETWORK_RESULT_BASE + 8, 2);
                let _ = self.memory.write_u16(NETWORK_RESULT_BASE + 10, 4);
                let _ = self
                    .memory
                    .write_u32(NETWORK_RESULT_BASE + 12, list_address);
                self.network.push(NetworkEvent {
                    operation: "dns".into(),
                    destination: query.clone(),
                    size: None,
                    preview: None,
                    synthetic_result: "10.20.30.40 from local resolver".into(),
                });
                Ok((
                    NETWORK_RESULT_BASE,
                    format!("Resolved {query} to synthetic address 10.20.30.40"),
                    vec![query],
                ))
            }
            "getaddrinfo" => {
                let query = self
                    .memory
                    .read_c_string(args.first().copied().unwrap_or(0), 512);
                if self.environment.network_mode == NetworkMode::Offline {
                    if let Some(output) = args.get(3).copied().filter(|pointer| *pointer != 0) {
                        let _ = self.memory.write_u32(output, 0);
                    }
                    self.network.push(NetworkEvent {
                        operation: "dns".into(),
                        destination: query.clone(),
                        size: None,
                        preview: None,
                        synthetic_result: "offline profile returned host-not-found".into(),
                    });
                    return Ok((
                        11_001,
                        format!("Synthetic offline DNS failure for {query}"),
                        vec![query],
                    ));
                }
                let result_address = NETWORK_RESULT_BASE + 0x100;
                let socket_address = NETWORK_RESULT_BASE + 0x140;
                let mut info = [0u8; 32];
                info[4..8].copy_from_slice(&2u32.to_le_bytes());
                info[8..12].copy_from_slice(&1u32.to_le_bytes());
                info[12..16].copy_from_slice(&6u32.to_le_bytes());
                info[16..20].copy_from_slice(&16u32.to_le_bytes());
                info[24..28].copy_from_slice(&socket_address.to_le_bytes());
                let _ = self.memory.write(result_address, &info);
                let mut sockaddr = [0u8; 16];
                sockaddr[0..2].copy_from_slice(&2u16.to_le_bytes());
                sockaddr[4..8].copy_from_slice(&[10, 20, 30, 40]);
                let _ = self.memory.write(socket_address, &sockaddr);
                if let Some(output) = args.get(3).copied().filter(|pointer| *pointer != 0) {
                    let _ = self.memory.write_u32(output, result_address);
                }
                self.network.push(NetworkEvent {
                    operation: "dns".into(),
                    destination: query.clone(),
                    size: None,
                    preview: None,
                    synthetic_result: "10.20.30.40 from local resolver".into(),
                });
                Ok((
                    0,
                    format!("Resolved {query} to synthetic address 10.20.30.40"),
                    vec![query],
                ))
            }
            "freeaddrinfo" => Ok((
                0,
                "Released synthetic address information".into(),
                hex_args(),
            )),
            "connect" => {
                let destination = self.read_sockaddr(args.get(1).copied().unwrap_or(0));
                let offline = self.environment.network_mode == NetworkMode::Offline;
                self.network.push(NetworkEvent {
                    operation: "connect".into(),
                    destination: destination.clone(),
                    size: None,
                    preview: None,
                    synthetic_result: if offline {
                        "offline profile rejected connection".into()
                    } else {
                        "connected to local sink".into()
                    },
                });
                Ok((
                    if offline { u32::MAX } else { 0 },
                    if offline {
                        format!("Synthetic offline connection failure to {destination}")
                    } else {
                        format!("Captured connection to {destination}")
                    },
                    vec![destination],
                ))
            }
            "send" => {
                let length = args.get(2).copied().unwrap_or(0).min(65_536);
                let data = self
                    .memory
                    .read(args.get(1).copied().unwrap_or(0), length as usize)
                    .unwrap_or_default();
                let preview = printable_preview(data);
                let offline = self.environment.network_mode == NetworkMode::Offline;
                self.network.push(NetworkEvent {
                    operation: "send".into(),
                    destination: format!("socket:0x{:x}", args.first().copied().unwrap_or(0)),
                    size: Some(length),
                    preview: Some(preview.clone()),
                    synthetic_result: if offline {
                        "offline profile rejected send".into()
                    } else {
                        "accepted by local sink".into()
                    },
                });
                Ok((
                    if offline { u32::MAX } else { length },
                    if offline {
                        "Synthetic offline send failure".into()
                    } else {
                        format!("Captured {length} outbound bytes")
                    },
                    vec![preview],
                ))
            }
            "recv" => Ok((
                if self.environment.network_mode == NetworkMode::Offline {
                    u32::MAX
                } else {
                    0
                },
                if self.environment.network_mode == NetworkMode::Offline {
                    "Synthetic offline receive failure".into()
                } else {
                    "Synthetic network sink returned EOF".into()
                },
                hex_args(),
            )),
            "closehandle" | "regclosekey" | "internetclosehandle" => {
                let handle = args.first().copied().unwrap_or(0);
                let description = self
                    .windows
                    .describe(handle)
                    .unwrap_or_else(|| format!("0x{handle:08x}"));
                let closed = self.windows.close(handle);
                Ok((
                    u32::from(closed),
                    if closed {
                        format!("Closed synthetic handle {description}")
                    } else {
                        "Synthetic handle was invalid".into()
                    },
                    vec![description],
                ))
            }
            _ => {
                self.warnings.push(format!(
                    "{} returned a conservative synthetic failure",
                    name
                ));
                Ok((
                    0,
                    format!("Unimplemented API {name} returned 0"),
                    hex_args(),
                ))
            }
        }
    }

    fn virtual_alloc(&mut self, args: &[u32]) -> Result<(u32, String, Vec<String>), DynamicError> {
        let requested = args.first().copied().unwrap_or(0);
        let size = align_page(args.get(1).copied().unwrap_or(0).max(0x1000) as usize);
        let address = if requested == 0 {
            let value = self.heap_next;
            self.heap_next = self.heap_next.saturating_add(size as u32 + 0x1000);
            value
        } else {
            requested
        };
        let permissions = protection(args.get(3).copied().unwrap_or(0x04));
        match self.memory.map(address, size, permissions, "VirtualAlloc") {
            Ok(()) => {
                self.memory_events.push(MemoryEvent {
                    operation: "allocate".into(),
                    address,
                    size: size as u32,
                    permissions: permissions.display(),
                });
                if permissions.execute {
                    self.capture_memory_region(
                        address,
                        "executable_allocation",
                        "VirtualAlloc",
                        true,
                    );
                }
                Ok((
                    address,
                    format!("Allocated {} virtual bytes", size),
                    vec![
                        format!("0x{address:08x}"),
                        size.to_string(),
                        permissions.display(),
                    ],
                ))
            }
            Err(error) => {
                self.warnings.push(error.to_string());
                Ok((
                    0,
                    "Virtual allocation failed safely".into(),
                    vec![size.to_string()],
                ))
            }
        }
    }

    fn heap_alloc(
        &mut self,
        requested_size: u32,
        operation: &str,
    ) -> Result<(u32, String, Vec<String>), DynamicError> {
        let size = align_page(requested_size.max(1) as usize);
        let address = self.heap_next;
        self.heap_next = self.heap_next.saturating_add(size as u32 + 0x1000);
        match self
            .memory
            .map(address, size, Permissions::READ_WRITE, operation)
        {
            Ok(()) => {
                self.memory_events.push(MemoryEvent {
                    operation: "allocate".into(),
                    address,
                    size: size as u32,
                    permissions: Permissions::READ_WRITE.display(),
                });
                Ok((
                    address,
                    format!("{operation} allocated {size} virtual bytes"),
                    vec![format!("0x{address:08x}"), size.to_string()],
                ))
            }
            Err(error) => {
                self.windows.set_last_error(8);
                self.warnings.push(error.to_string());
                Ok((
                    0,
                    format!("{operation} failed safely"),
                    vec![size.to_string()],
                ))
            }
        }
    }

    fn heap_free(
        &mut self,
        address: u32,
        operation: &str,
    ) -> Result<(u32, String, Vec<String>), DynamicError> {
        self.capture_memory_region(address, "memory_release", operation, false);
        let released = self.memory.unmap(address);
        if !released {
            self.windows.set_last_error(87);
        }
        self.memory_events.push(MemoryEvent {
            operation: "free".into(),
            address,
            size: 0,
            permissions: "---".into(),
        });
        let success_value = if matches!(operation, "LocalFree" | "GlobalFree") {
            0
        } else {
            u32::from(released)
        };
        Ok((
            success_value,
            format!(
                "{operation} {} virtual allocation at 0x{address:08x}",
                if released {
                    "released"
                } else {
                    "could not release"
                }
            ),
            vec![format!("0x{address:08x}")],
        ))
    }

    fn write_guest_string(
        &mut self,
        destination: u32,
        capacity: usize,
        value: &str,
        wide: bool,
    ) -> usize {
        if destination == 0 || capacity == 0 {
            return if wide {
                value.encode_utf16().count()
            } else {
                value.len()
            };
        }
        if wide {
            let units: Vec<u16> = value
                .encode_utf16()
                .take(capacity.saturating_sub(1))
                .collect();
            let mut bytes: Vec<u8> = units.iter().flat_map(|unit| unit.to_le_bytes()).collect();
            bytes.extend_from_slice(&[0, 0]);
            let _ = self.memory.write(destination, &bytes);
            units.len()
        } else {
            let bytes = value.as_bytes();
            let length = bytes.len().min(capacity.saturating_sub(1));
            let mut output = bytes[..length].to_vec();
            output.push(0);
            let _ = self.memory.write(destination, &output);
            length
        }
    }

    fn virtual_protect(
        &mut self,
        args: &[u32],
    ) -> Result<(u32, String, Vec<String>), DynamicError> {
        let address = args.first().copied().unwrap_or(0);
        let size = args.get(1).copied().unwrap_or(0) as usize;
        let permissions = protection(args.get(2).copied().unwrap_or(0x04));
        if let Some(old_pointer) = args.get(3).copied().filter(|pointer| *pointer != 0) {
            let _ = self.memory.write_u32(old_pointer, 0x04);
        }
        match self
            .memory
            .set_permissions(address, size.max(1), permissions)
        {
            Ok(()) => {
                self.memory_events.push(MemoryEvent {
                    operation: "protect".into(),
                    address,
                    size: size as u32,
                    permissions: permissions.display(),
                });
                if permissions.execute {
                    self.capture_memory_region(
                        address,
                        "executable_transition",
                        "VirtualProtect",
                        true,
                    );
                }
                Ok((
                    1,
                    format!(
                        "Changed virtual memory protection to {}",
                        permissions.display()
                    ),
                    vec![
                        format!("0x{address:08x}"),
                        size.to_string(),
                        permissions.display(),
                    ],
                ))
            }
            Err(error) => {
                self.warnings.push(error.to_string());
                Ok((
                    0,
                    "Virtual protection change failed safely".into(),
                    vec![format!("0x{address:08x}")],
                ))
            }
        }
    }

    fn read_sockaddr(&self, address: u32) -> String {
        let port = self
            .memory
            .read_u16(address.wrapping_add(2))
            .unwrap_or(0)
            .swap_bytes();
        let octets = self
            .memory
            .read(address.wrapping_add(4), 4)
            .unwrap_or(&[0, 0, 0, 0]);
        format!(
            "{}.{}.{}.{}:{port}",
            octets[0], octets[1], octets[2], octets[3]
        )
    }

    fn build_findings(&self) -> Vec<DynamicFinding> {
        let mut findings = Vec::new();
        let process_calls: Vec<_> = self
            .processes
            .iter()
            .filter(|event| {
                matches!(
                    event.operation.as_str(),
                    "execute" | "create" | "shell_execute"
                )
            })
            .map(|event| event.command.clone())
            .collect();
        if !process_calls.is_empty() {
            findings.push(DynamicFinding {
                id: "process-execution".into(),
                title: "Process execution requested".into(),
                severity: DynamicSeverity::High,
                rationale: "The emulated sample requested creation of another process.".into(),
                evidence: process_calls,
            });
        }
        if !self.network.is_empty() {
            findings.push(DynamicFinding { id: "network-activity".into(), title: "Network activity observed".into(), severity: DynamicSeverity::Medium, rationale: "All network operations were captured by the synthetic sink and never left the browser.".into(), evidence: self.network.iter().take(10).map(|event| format!("{} {}", event.operation, event.destination)).collect() });
        }
        if !self.registry.is_empty() {
            findings.push(DynamicFinding {
                id: "registry-activity".into(),
                title: "Registry activity observed".into(),
                severity: DynamicSeverity::Medium,
                rationale: "The sample accessed the synthetic Windows registry.".into(),
                evidence: self
                    .registry
                    .iter()
                    .take(10)
                    .map(|event| format!("{} {}", event.operation, event.key))
                    .collect(),
            });
        }
        if !self.filesystem.is_empty() {
            findings.push(DynamicFinding {
                id: "filesystem-activity".into(),
                title: "Filesystem activity observed".into(),
                severity: DynamicSeverity::Low,
                rationale: "The sample accessed the in-memory virtual filesystem.".into(),
                evidence: self
                    .filesystem
                    .iter()
                    .take(10)
                    .map(|event| format!("{} {}", event.operation, event.path))
                    .collect(),
            });
        }
        let executable_memory: Vec<_> = self
            .memory_events
            .iter()
            .filter(|event| event.permissions.contains('x') && event.operation == "protect")
            .map(|event| {
                format!(
                    "0x{:08x} {} bytes {}",
                    event.address, event.size, event.permissions
                )
            })
            .collect();
        if !executable_memory.is_empty() {
            findings.push(DynamicFinding { id: "executable-memory".into(), title: "Memory made executable".into(), severity: DynamicSeverity::High, rationale: "Changing writable memory to executable is commonly associated with unpacking or injected code.".into(), evidence: executable_memory });
        }
        if !self.injection.is_empty() {
            let wrote_remote = self
                .injection
                .iter()
                .any(|event| event.operation == "write_remote");
            let executed_remote = self.injection.iter().any(|event| {
                matches!(
                    event.operation.as_str(),
                    "execute_remote" | "queue_apc" | "resume_thread"
                )
            });
            findings.push(DynamicFinding {
                id: "process-injection".into(),
                title: if wrote_remote && executed_remote { "Process injection chain observed".into() } else { "Process injection primitive observed".into() },
                severity: if wrote_remote && executed_remote { DynamicSeverity::High } else { DynamicSeverity::Medium },
                rationale: "All remote process operations targeted synthetic address spaces and never reached a host process.".into(),
                evidence: self.injection.iter().take(20).map(|event| format!("{} process 0x{:08x} address 0x{:08x} size {}", event.operation, event.process_handle, event.address, event.size)).collect(),
            });
        }
        let mut persistence_evidence: Vec<String> = self
            .persistence
            .iter()
            .map(|event| {
                format!(
                    "{} {} {}{}",
                    event.mechanism,
                    event.operation,
                    event.target,
                    event
                        .value
                        .as_ref()
                        .map_or(String::new(), |value| format!(" -> {value}"))
                )
            })
            .collect();
        persistence_evidence.extend(
            self.registry
                .iter()
                .filter(|event| {
                    let key = event.key.to_ascii_lowercase();
                    key.contains("\\currentversion\\run")
                        || key.contains("\\currentversion\\runonce")
                        || key.contains("\\services\\")
                })
                .map(|event| format!("registry {} {}", event.operation, event.key)),
        );
        if !persistence_evidence.is_empty() {
            findings.push(DynamicFinding {
                id: "persistence".into(),
                title: "Persistence mechanism observed".into(),
                severity: DynamicSeverity::High,
                rationale: "The sample changed a synthetic persistence location or service. No host configuration was modified.".into(),
                evidence: persistence_evidence.into_iter().take(20).collect(),
            });
        }
        if !self.exceptions.is_empty() {
            findings.push(DynamicFinding { id: "exception-dispatch".into(), title: "Structured exception handling observed".into(), severity: DynamicSeverity::Medium, rationale: "The sample registered or reached guest exception handlers. Handlers executed only inside the bounded interpreter.".into(), evidence: self.exceptions.iter().take(20).map(|event| format!("{} at 0x{:08x} -> {}", event.name, event.address, event.outcome)).collect() });
        }
        if self.thread_states.len() > 1 {
            findings.push(DynamicFinding { id: "guest-threads".into(), title: "Guest thread execution observed".into(), severity: DynamicSeverity::Medium, rationale: "Created threads were scheduled deterministically with isolated registers, stacks, and synthetic TEBs over shared guest memory.".into(), evidence: self.thread_states.iter().skip(1).map(|thread| format!("thread {} start 0x{:08x} · {} instructions", thread.tid, thread.start_address, thread.instruction_count)).collect() });
        }
        if findings.is_empty() {
            findings.push(DynamicFinding { id: "no-modeled-behavior".into(), title: "No modeled high-level behavior observed".into(), severity: DynamicSeverity::Info, rationale: "Execution may have completed, hit an unsupported instruction, or avoided the modeled APIs.".into(), evidence: vec![format!("{} instructions emulated", self.instruction_count)] });
        }
        findings
    }
}

fn set_to_jump(mnemonic: Mnemonic) -> Mnemonic {
    match mnemonic {
        Mnemonic::Sete => Mnemonic::Je,
        Mnemonic::Setne => Mnemonic::Jne,
        Mnemonic::Seta => Mnemonic::Ja,
        Mnemonic::Setae => Mnemonic::Jae,
        Mnemonic::Setb => Mnemonic::Jb,
        Mnemonic::Setbe => Mnemonic::Jbe,
        Mnemonic::Setg => Mnemonic::Jg,
        Mnemonic::Setge => Mnemonic::Jge,
        Mnemonic::Setl => Mnemonic::Jl,
        Mnemonic::Setle => Mnemonic::Jle,
        Mnemonic::Sets => Mnemonic::Js,
        Mnemonic::Setns => Mnemonic::Jns,
        Mnemonic::Seto => Mnemonic::Jo,
        Mnemonic::Setno => Mnemonic::Jno,
        Mnemonic::Setp => Mnemonic::Jp,
        Mnemonic::Setnp => Mnemonic::Jnp,
        _ => unreachable!(),
    }
}

fn cmov_to_jump(mnemonic: Mnemonic) -> Mnemonic {
    match mnemonic {
        Mnemonic::Cmove => Mnemonic::Je,
        Mnemonic::Cmovne => Mnemonic::Jne,
        Mnemonic::Cmova => Mnemonic::Ja,
        Mnemonic::Cmovae => Mnemonic::Jae,
        Mnemonic::Cmovb => Mnemonic::Jb,
        Mnemonic::Cmovbe => Mnemonic::Jbe,
        Mnemonic::Cmovg => Mnemonic::Jg,
        Mnemonic::Cmovge => Mnemonic::Jge,
        Mnemonic::Cmovl => Mnemonic::Jl,
        Mnemonic::Cmovle => Mnemonic::Jle,
        Mnemonic::Cmovs => Mnemonic::Js,
        Mnemonic::Cmovns => Mnemonic::Jns,
        Mnemonic::Cmovo => Mnemonic::Jo,
        Mnemonic::Cmovno => Mnemonic::Jno,
        Mnemonic::Cmovp => Mnemonic::Jp,
        Mnemonic::Cmovnp => Mnemonic::Jnp,
        _ => unreachable!(),
    }
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

fn protection(value: u32) -> Permissions {
    match value & 0xff {
        0x10 => Permissions {
            read: false,
            write: false,
            execute: true,
        },
        0x20 => Permissions {
            read: true,
            write: false,
            execute: true,
        },
        0x40 | 0x80 => Permissions {
            read: true,
            write: true,
            execute: true,
        },
        0x02 => Permissions::READ,
        _ => Permissions::READ_WRITE,
    }
}

fn align_page(size: usize) -> usize {
    size.saturating_add(0xfff) & !0xfff
}

fn printable_preview(data: &[u8]) -> String {
    data.iter()
        .take(128)
        .map(|byte| {
            if matches!(*byte, b' '..=b'~') {
                *byte as char
            } else {
                '.'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine_with_code(code: &[u8]) -> Machine {
        let mut memory = Memory::default();
        memory
            .map(
                0x1000,
                0x1000,
                Permissions {
                    read: true,
                    write: false,
                    execute: true,
                },
                "test code",
            )
            .unwrap();
        memory.write_force(0x1000, code).unwrap();
        memory
            .map(0x3000, 0x1000, Permissions::READ_WRITE, "test data")
            .unwrap();
        memory
            .map(0x8000, 0x1000, Permissions::READ_WRITE, "test stack")
            .unwrap();
        let cpu = Cpu {
            eip: 0x1000,
            esp: 0x8f00,
            ebp: 0x8f00,
            ..Cpu::default()
        };
        Machine {
            cpu: cpu.clone(),
            memory,
            imports: BTreeMap::new(),
            options: DynamicOptions {
                max_instructions: 1_000,
                max_trace_events: 100,
                ..DynamicOptions::default()
            },
            instruction_count: 0,
            virtual_time_ms: 1_000_000,
            instructions: Vec::new(),
            api_calls: Vec::new(),
            processes: Vec::new(),
            filesystem: Vec::new(),
            registry: Vec::new(),
            network: Vec::new(),
            memory_events: Vec::new(),
            injection: Vec::new(),
            persistence: Vec::new(),
            exceptions: Vec::new(),
            warnings: Vec::new(),
            termination: None,
            truncated: false,
            windows: VirtualWindows::default(),
            heap_next: HEAP_BASE,
            dynamic_api_next: DYNAMIC_API_BASE,
            timeline: Vec::new(),
            unique_instruction_addresses: BTreeSet::new(),
            unique_api_names: BTreeSet::new(),
            modeled_api_calls: 0,
            unmodeled_api_calls: 0,
            dynamic_api_resolutions: 0,
            entry_point: 0x1000,
            tls_callbacks: VecDeque::new(),
            artifacts: ArtifactStore::default(),
            generations: GenerationTracker::default(),
            environment: crate::EnvironmentProfile::default(),
            pending_exception: None,
            vectored_handlers: Vec::new(),
            queued_exception: None,
            thread_states: vec![GuestThread {
                tid: 1,
                start_address: 0x1000,
                parameter: 0,
                cpu,
                state: GuestThreadState::Runnable,
                instruction_count: 0,
                exit_code: None,
            }],
            thread_events: Vec::new(),
            current_thread: 0,
            thread_exit_requested: None,
            next_thread_switch: THREAD_QUANTUM,
            first_unsupported: None,
            invalid_instruction_count: 0,
        }
    }

    #[test]
    fn supports_carry_flags_setcc_and_rep_movsb() {
        let code = [
            0xb8, 0xff, 0xff, 0xff, 0xff, // mov eax, -1
            0xf9, // stc
            0x83, 0xd0, 0x00, // adc eax, 0
            0x0f, 0x92, 0xc3, // setb bl
            0xbe, 0x00, 0x30, 0x00, 0x00, // mov esi, 0x3000
            0xbf, 0x10, 0x30, 0x00, 0x00, // mov edi, 0x3010
            0xb9, 0x04, 0x00, 0x00, 0x00, // mov ecx, 4
            0xf3, 0xa4, // rep movsb
            0xf4, // hlt
        ];
        let mut machine = machine_with_code(&code);
        machine.memory.write(0x3000, b"Aegis").unwrap();
        machine.execute();
        assert_eq!(machine.cpu.eax, 0);
        assert_eq!(machine.cpu.ebx & 0xff, 1);
        assert_eq!(machine.memory.read(0x3010, 4).unwrap(), b"Aegi");
        assert_eq!(machine.cpu.ecx, 0);
        assert!(matches!(machine.termination, Some(Termination::Halted)));
    }

    #[test]
    fn resolves_getprocaddress_to_an_executable_api_stub() {
        let mut machine = machine_with_code(&[0xf4]);
        machine.memory.write(0x3000, b"user32.dll\0").unwrap();
        machine
            .memory
            .map(0x13000, 0x1000, Permissions::READ_WRITE, "api names")
            .unwrap();
        machine.memory.write(0x13000, b"CreateProcessA\0").unwrap();
        let (module, _, _) = machine.emulate_api("loadlibrarya", &[0x3000]).unwrap();
        let (stub, summary, _) = machine
            .emulate_api("getprocaddress", &[module, 0x13000])
            .unwrap();
        let import = machine.imports.get(&stub).unwrap();
        assert_eq!(import.module, "user32.dll");
        assert_eq!(import.name, "CreateProcessA");
        assert_eq!(import.argument_count, 10);
        assert!(summary.contains("Resolved dynamic symbol"));
        assert_eq!(machine.dynamic_api_resolutions, 1);
    }

    #[test]
    fn supports_bounded_repne_scasb() {
        let code = [
            0xbf, 0x00, 0x30, 0x00, 0x00, // mov edi, 0x3000
            0xb8, b'g', 0x00, 0x00, 0x00, // mov eax, 'g'
            0xb9, 0x05, 0x00, 0x00, 0x00, // mov ecx, 5
            0xf2, 0xae, // repne scasb
            0xf4,
        ];
        let mut machine = machine_with_code(&code);
        machine.memory.write(0x3000, b"Aegis").unwrap();
        machine.execute();
        assert_eq!(machine.cpu.edi, 0x3003);
        assert_eq!(machine.cpu.ecx, 2);
        assert!(machine.cpu.zf);
        assert!(matches!(machine.termination, Some(Termination::Halted)));
    }

    #[test]
    fn resolves_fs_relative_teb_access() {
        let mut machine = machine_with_code(&[
            0x64, 0xa1, 0x30, 0x00, 0x00, 0x00, // mov eax, fs:[0x30]
            0xf4,
        ]);
        machine
            .memory
            .map(TEB_BASE, 0x1000, Permissions::READ_WRITE, "test TEB")
            .unwrap();
        machine.memory.write_u32(TEB_BASE + 0x30, PEB_BASE).unwrap();
        machine.cpu.fs_base = TEB_BASE;
        machine.execute();
        assert_eq!(machine.cpu.eax, PEB_BASE);
        assert!(matches!(machine.termination, Some(Termination::Halted)));
    }

    #[test]
    fn correlates_a_synthetic_process_injection_chain() {
        let mut machine = machine_with_code(&[0xf4]);
        machine.memory.write(0x3000, b"payload bytes").unwrap();
        let (process, _, _) = machine
            .emulate_api("openprocess", &[0x1f0fff, 0, 4242])
            .unwrap();
        let (remote, _, _) = machine
            .emulate_api("virtualallocex", &[process, 0, 4096, 0x3000, 0x04])
            .unwrap();
        machine
            .emulate_api("writeprocessmemory", &[process, remote, 0x3000, 13, 0])
            .unwrap();
        machine
            .emulate_api("createremotethread", &[process, 0, 0, remote, 0, 0, 0])
            .unwrap();
        let finding = machine
            .build_findings()
            .into_iter()
            .find(|finding| finding.id == "process-injection")
            .unwrap();
        assert_eq!(finding.severity, DynamicSeverity::High);
        assert_eq!(machine.injection.len(), 3);
        assert!(finding.title.contains("chain"));
    }

    #[test]
    fn runs_tls_callbacks_before_the_entry_point() {
        let callback = [
            0xb8, 0x42, 0x00, 0x00, 0x00, // mov eax, 0x42
            0xc2, 0x0c, 0x00, // ret 12
        ];
        let mut machine = machine_with_code(&callback);
        machine.memory.write_force(0x1100, &[0xf4]).unwrap();
        machine
            .memory
            .map(
                crate::loader::STACK_BASE,
                crate::loader::STACK_SIZE,
                Permissions::READ_WRITE,
                "TLS test stack",
            )
            .unwrap();
        machine.entry_point = 0x1100;
        machine.tls_callbacks.push_back(0x1000);
        machine.start_execution().unwrap();
        machine.execute();
        assert_eq!(machine.cpu.eax, 0x42);
        assert!(matches!(machine.termination, Some(Termination::Halted)));
        assert!(machine.instructions[0].text.starts_with("mov eax"));
        assert_eq!(machine.instructions.last().unwrap().address, 0x1100);
    }

    #[test]
    fn models_runtime_string_memory_and_interlocked_helpers() {
        let mut machine = machine_with_code(&[0xf4]);
        machine.memory.write(0x3000, b"runtime\0").unwrap();
        let (length, _, _) = machine.emulate_api("strlen", &[0x3000]).unwrap();
        assert_eq!(length, 7);
        machine.emulate_api("memcpy", &[0x3040, 0x3000, 8]).unwrap();
        assert_eq!(machine.memory.read(0x3040, 8).unwrap(), b"runtime\0");
        machine.memory.write_u32(0x3080, 41).unwrap();
        let (value, _, _) = machine
            .emulate_api("interlockedincrement", &[0x3080])
            .unwrap();
        assert_eq!(value, 42);
        assert_eq!(machine.memory.read_u32(0x3080).unwrap(), 42);
    }

    #[test]
    fn detects_synthetic_service_persistence() {
        let mut machine = machine_with_code(&[0xf4]);
        machine.memory.write(0x3000, b"AegisUpdater\0").unwrap();
        machine
            .memory
            .write(0x3040, b"C:\\Temp\\updater.exe\0")
            .unwrap();
        let mut args = [0u32; 13];
        args[1] = 0x3000;
        args[7] = 0x3040;
        machine.emulate_api("createservicea", &args).unwrap();
        let finding = machine
            .build_findings()
            .into_iter()
            .find(|finding| finding.id == "persistence")
            .unwrap();
        assert_eq!(finding.severity, DynamicSeverity::High);
        assert!(finding.evidence[0].contains("AegisUpdater"));
    }

    #[test]
    fn offline_profile_changes_network_results_without_host_access() {
        let mut machine = machine_with_code(&[0xf4]);
        machine.environment = crate::EnvironmentProfile::hardened();
        machine.memory.write(0x3000, b"example.test\0").unwrap();
        let (dns, summary, _) = machine.emulate_api("gethostbyname", &[0x3000]).unwrap();
        let (connect, _, _) = machine.emulate_api("connect", &[0, 0, 0]).unwrap();
        assert_eq!(dns, 0);
        assert_eq!(connect, u32::MAX);
        assert!(summary.contains("offline"));
        assert!(
            machine
                .network
                .iter()
                .all(|event| event.synthetic_result.contains("offline"))
        );
    }

    #[test]
    fn detects_entry_point_overwrite_as_a_payload_generation() {
        let mut machine = machine_with_code(&[0x90, 0xf4]);
        machine.entry_point = 0x1000;
        machine
            .memory
            .set_permissions(0x1000, 2, Permissions::READ_WRITE)
            .unwrap();
        machine.memory.write(0x1000, &[0x90, 0xf4]).unwrap();
        machine
            .memory
            .set_permissions(
                0x1000,
                2,
                Permissions {
                    read: true,
                    write: false,
                    execute: true,
                },
            )
            .unwrap();
        machine.capture_memory_region(0x1000, "executable_transition", "VirtualProtect", true);
        let (generations, _) = machine.generations.finish();
        assert_eq!(generations.len(), 1);
        assert!(generations[0].entry_point_overwrite);
    }

    #[test]
    fn seh_continue_search_reaches_the_next_handler() {
        let mut code = vec![0x90; 0x21];
        code[0..5].copy_from_slice(&[0x31, 0xc0, 0xc2, 0x10, 0x00]);
        code[0x10..0x18].copy_from_slice(&[0xb8, 0xff, 0xff, 0xff, 0xff, 0xc2, 0x10, 0x00]);
        code[0x20] = 0xf4;
        let mut machine = machine_with_code(&code);
        machine
            .memory
            .map(
                EXCEPTION_SCRATCH_BASE,
                0x1000,
                Permissions::READ_WRITE,
                "exception scratch",
            )
            .unwrap();
        machine
            .memory
            .map(TEB_BASE, 0x1000, Permissions::READ_WRITE, "test TEB")
            .unwrap();
        machine.memory.write_u32(TEB_BASE, 0x3000).unwrap();
        machine.memory.write_u32(0x3000, 0x3008).unwrap();
        machine.memory.write_u32(0x3004, 0x1000).unwrap();
        machine.memory.write_u32(0x3008, u32::MAX).unwrap();
        machine.memory.write_u32(0x300c, 0x1010).unwrap();
        assert!(machine.dispatch_exception(
            0x8000_0003,
            "breakpoint",
            0x1020,
            0x1020,
            Termination::Halted
        ));
        machine.execute();
        assert_eq!(machine.exceptions.len(), 2);
        assert_eq!(machine.exceptions[0].outcome, "continued_search");
        assert_eq!(machine.exceptions[1].outcome, "continued_execution");
    }

    #[test]
    fn vectored_handler_runs_before_the_seh_chain() {
        let mut code = vec![0x90; 0x11];
        code[0..8].copy_from_slice(&[0xb8, 0xff, 0xff, 0xff, 0xff, 0xc2, 0x04, 0x00]);
        code[0x10] = 0xf4;
        let mut machine = machine_with_code(&code);
        machine
            .memory
            .map(
                EXCEPTION_SCRATCH_BASE,
                0x1000,
                Permissions::READ_WRITE,
                "exception scratch",
            )
            .unwrap();
        machine
            .memory
            .map(TEB_BASE, 0x1000, Permissions::READ_WRITE, "test TEB")
            .unwrap();
        machine.memory.write_u32(TEB_BASE, u32::MAX).unwrap();
        machine.vectored_handlers.push(0x1000);
        assert!(machine.dispatch_exception(
            0xe042_4242,
            "raised_exception",
            0x1010,
            0x1010,
            Termination::Halted
        ));
        machine.execute();
        assert_eq!(machine.exceptions.len(), 1);
        assert_eq!(machine.exceptions[0].establisher_frame, None);
        assert_eq!(machine.exceptions[0].outcome, "continued_execution");
    }

    #[test]
    fn executes_bit_scan_atomic_and_double_shift_families() {
        let code = [
            0xb8, 0x10, 0x00, 0x00, 0x00, // mov eax, 0x10
            0x0f, 0xba, 0xe8, 0x01, // bts eax, 1
            0x0f, 0xbc, 0xd8, // bsf ebx, eax
            0xb9, 0x03, 0x00, 0x00, 0x00, // mov ecx, 3
            0x0f, 0xc1, 0xc8, // xadd eax, ecx
            0xba, 0x00, 0x00, 0x00, 0x80, // mov edx, 0x80000000
            0x0f, 0xa4, 0xd0, 0x01, // shld eax, edx, 1
            0xf4,
        ];
        let mut machine = machine_with_code(&code);
        machine.execute();
        assert_eq!(machine.cpu.ebx, 1);
        assert_eq!(machine.cpu.ecx, 0x12);
        assert_eq!(machine.cpu.eax, 0x2b);
    }

    #[test]
    fn executes_sse2_scalar_arithmetic_and_moves() {
        let code = [
            0xb8, 0x00, 0x00, 0xc0, 0x3f, // mov eax, 1.5f
            0x66, 0x0f, 0x6e, 0xc0, // movd xmm0, eax
            0xbb, 0x00, 0x00, 0x00, 0x40, // mov ebx, 2.0f
            0x66, 0x0f, 0x6e, 0xcb, // movd xmm1, ebx
            0xf3, 0x0f, 0x58, 0xc1, // addss xmm0, xmm1
            0x66, 0x0f, 0x7e, 0xc1, // movd ecx, xmm0
            0xf4,
        ];
        let mut machine = machine_with_code(&code);
        machine.execute();
        assert_eq!(f32::from_bits(machine.cpu.ecx), 3.5);
    }

    #[test]
    fn executes_bounded_x87_stack_arithmetic() {
        let code = [
            0xd9, 0xe8, // fld1
            0xd9, 0xe8, // fld1
            0xde, 0xc1, // faddp st(1), st(0)
            0xd9, 0x1d, 0x00, 0x30, 0x00, 0x00, // fstp dword ptr [0x3000]
            0xf4,
        ];
        let mut machine = machine_with_code(&code);
        machine.execute();
        let value = f32::from_le_bytes(machine.memory.read(0x3000, 4).unwrap().try_into().unwrap());
        assert_eq!(value, 2.0);
        assert_eq!(machine.cpu.x87_depth, 0);
    }

    #[test]
    fn records_nearby_context_for_unsupported_and_malformed_instructions() {
        let mut unsupported = machine_with_code(&[0x90, 0x0f, 0x0b]); // nop; ud2
        unsupported.execute();
        let diagnostic = unsupported.first_unsupported.unwrap();
        assert_eq!(diagnostic.address, 0x1001);
        assert!(diagnostic.instruction.contains("ud2"));
        assert!(
            diagnostic
                .nearby_trace
                .iter()
                .any(|event| event.text == "nop")
        );

        let mut malformed = machine_with_code(&[0x66; 16]);
        malformed.execute();
        assert_eq!(malformed.invalid_instruction_count, 1);
        assert!(
            malformed
                .first_unsupported
                .unwrap()
                .bytes
                .starts_with("6666")
        );
    }
}
