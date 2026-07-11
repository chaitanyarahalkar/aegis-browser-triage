use crate::{
    ApiEvent, ArtifactStats, DynamicAnalysis, DynamicError, DynamicFinding, DynamicOptions,
    DynamicReport, DynamicSeverity, ExecutionCoverage, ExecutionDiagnostics, ExecutionProfile,
    ExecutionSnapshot, GenerationStats, InstructionDiagnostic, InstructionEvent, MemoryEvent,
    ProcessEvent, ProvenanceSource, ProvenanceSourceKind, ProvenanceStats, SnapshotEventCounts,
    SnapshotRegisters, SnapshotStats, SystemEvent, Termination, ThreadSummary, TimelineEvent,
    api::normalize_name,
    cpu64::Cpu64,
    loader::ApiImport,
    loader64::{self, STACK64_TOP},
    memory::Permissions,
    memory64::Memory64,
};
use iced_x86::{Code, Decoder, DecoderOptions, Instruction, Mnemonic};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const ENTRY64_RETURN_SENTINEL: u64 = 0x0000_006e_ffff_fff0;
const TLS64_RETURN_SENTINEL: u64 = 0x0000_006e_ffff_ffe0;
const PROCESS_ENV64_BASE: u64 = 0x0000_007e_0000_0000;
const COMMAND_LINE64_A: u64 = PROCESS_ENV64_BASE;
const TEB64_BASE: u64 = 0x0000_007f_fde0_0000;
const PEB64_BASE: u64 = 0x0000_007f_fdf0_0000;
const HEAP64_BASE: u64 = 0x0000_0050_0000_0000;
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

    let environment = options.environment.clone();
    let profile = ExecutionProfile {
        architecture: "x86-64 (64-bit)".into(),
        operating_system: environment.windows_version.clone(),
        image_base: loaded.image_base,
        entry_point: loaded.entry_point,
        instruction_limit: options.max_instructions,
        trace_limit: options.max_trace_events,
        network_mode: environment.network_mode.description().into(),
        environment: environment.clone(),
        network_scenario: options.network_scenario.id.clone(),
    };
    let mut machine = Machine64 {
        cpu: Cpu64 {
            rip: loaded.entry_point,
            gs_base: TEB64_BASE,
            ..Cpu64::default()
        },
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
        memory_events: Vec::new(),
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
    };
    machine.start_next_target()?;
    machine.record_snapshot("entry", false);
    machine.execute();
    machine.record_snapshot("final", true);

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
    let sample_source = ProvenanceSource {
        id: "source-0001".into(),
        kind: ProvenanceSourceKind::Sample,
        label: "loaded PE64 image".into(),
        address: loaded.image_base,
        size: loaded.image_size,
        api: "loader64".into(),
        instruction: 0,
        parent_ids: Vec::new(),
    };
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
        filesystem: Vec::new(),
        registry: Vec::new(),
        network: Vec::new(),
        network_exchanges: Vec::new(),
        provenance_sources: vec![sample_source],
        provenance_flows: Vec::new(),
        provenance_stats: ProvenanceStats {
            source_count: 1,
            flow_count: 0,
            tracked_ranges: 1,
            truncated: false,
        },
        snapshots: machine.snapshots,
        snapshot_stats,
        unwind_functions: loaded.unwind_functions,
        memory: machine.memory_events,
        injection: Vec::new(),
        persistence: Vec::new(),
        exceptions: Vec::new(),
        threads: vec![ThreadSummary {
            tid: 1,
            start_address: machine.entry_point,
            parameter: 0,
            state: "terminated".into(),
            instruction_count: machine.instruction_count,
            exit_code: match machine.termination {
                Some(Termination::ExitProcess { code }) => Some(code),
                _ => None,
            },
        }],
        thread_events: Vec::new(),
        system: vec![
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
        artifacts: Vec::new(),
        artifact_stats: ArtifactStats {
            count: 0,
            retained_bytes: 0,
            truncated: false,
        },
        payload_generations: Vec::new(),
        generation_stats: GenerationStats {
            count: 0,
            chains: 0,
            executed_generations: 0,
            truncated: false,
        },
        timeline: machine.timeline,
        coverage: ExecutionCoverage {
            unique_instruction_addresses: machine.unique_instruction_addresses.len(),
            unique_api_names: machine.unique_api_names.len(),
            modeled_api_calls: machine.modeled_api_calls,
            unmodeled_api_calls: machine.unmodeled_api_calls,
            dynamic_api_resolutions: 0,
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
        artifacts: BTreeMap::new(),
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
    memory_events: Vec<MemoryEvent>,
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
}

impl Machine64 {
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
            if self.cpu.rip == ENTRY64_RETURN_SENTINEL {
                self.termination = Some(Termination::ReturnedFromEntryPoint);
                break;
            }
            if self.cpu.rip == TLS64_RETURN_SENTINEL {
                if let Err(error) = self.start_next_target() {
                    self.termination = Some(memory_termination(error, "TLS callback"));
                }
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
            self.unique_instruction_addresses.insert(address);
            let bytes = match self.memory.fetch(address, 15) {
                Ok(bytes) => bytes.to_vec(),
                Err(error) => {
                    self.termination = Some(memory_termination(error, "x64 execute"));
                    break;
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
                self.termination = Some(Termination::InvalidInstruction { address });
                break;
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
            if let Err(error) = self.execute_instruction(&instruction) {
                self.warnings.push(error.to_string());
                self.first_unsupported.get_or_insert(InstructionDiagnostic {
                    address,
                    instruction: instruction.to_string(),
                    bytes: hex::encode(&bytes[..length]),
                    nearby_trace: self.instructions.iter().rev().take(4).cloned().collect(),
                });
                self.termination = Some(match error {
                    DynamicError::MemoryRead { .. }
                    | DynamicError::MemoryWrite { .. }
                    | DynamicError::MemoryExecute { .. } => {
                        memory_termination(error, "x64 instruction")
                    }
                    _ => Termination::UnsupportedInstruction {
                        address,
                        instruction: instruction.to_string(),
                    },
                });
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
            Int3 | Hlt => self.termination = Some(Termination::Halted),
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

    fn handle_api(&mut self, import: ApiImport) -> Result<(), DynamicError> {
        let return_address = self.cpu.pop(&self.memory)?;
        let args = x64_api_arguments(&self.cpu, &self.memory, import.argument_count)?;
        let name = normalize_name(&import.name);
        self.unique_api_names.insert(name.clone());
        let supported = matches!(
            name.as_str(),
            "gettickcount"
                | "gettickcount64"
                | "getcurrentprocess"
                | "getcurrentprocessid"
                | "getcurrentthreadid"
                | "getcommandlinea"
                | "isdebuggerpresent"
                | "sleep"
                | "winexec"
                | "createprocessa"
                | "virtualalloc"
                | "virtualprotect"
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
                1,
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
                }
                (
                    u64::from(ok),
                    format!("Changed x64 memory protection to {}", permissions.display()),
                    "memory".into(),
                    "protect".into(),
                    format!("0x{address:016x}"),
                )
            }
            "exitprocess" => {
                let code = args.first().copied().unwrap_or(0) as u32;
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
        let behavior = self.processes.len() + self.memory_events.len();
        let events = SnapshotEventCounts {
            api_calls: self.api_calls.len(),
            processes: self.processes.len(),
            filesystem: 0,
            registry: 0,
            network: 0,
            memory: self.memory_events.len(),
            injection: 0,
            persistence: 0,
            provenance_flows: 0,
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
