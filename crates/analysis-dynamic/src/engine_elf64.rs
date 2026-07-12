use crate::{
    ApiEvent, ArtifactKind, ArtifactOrigin, DynamicAnalysis, DynamicError, DynamicFinding,
    DynamicOptions, DynamicReport, DynamicSeverity, ExecutionCoverage, ExecutionDiagnostics,
    ExecutionProfile, ExecutionSnapshot, FileEvent, GenerationStats, InstructionDiagnostic,
    InstructionEvent, MemoryEvent, NetworkEvent, NetworkExchange, NetworkMode, ProcessEvent,
    ProvenanceSinkKind, ProvenanceSourceKind, SnapshotEventCounts, SnapshotRegisters,
    SnapshotStats, SystemEvent, Termination, ThreadSummary, TimelineEvent,
    artifact::{ArtifactCapture, ArtifactStore, MAX_ARTIFACT_BYTES},
    cpu64::Cpu64,
    loader_elf64::{self, LINUX_HEAP_BASE, LINUX_HEAP_SIZE, LINUX_MMAP_BASE, LinuxImport},
    memory::Permissions,
    memory64::Memory64,
    network::NetworkRuntime,
    provenance::ProvenanceTracker,
};
use iced_x86::{Code, Decoder, DecoderOptions, Instruction, Mnemonic};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const ENTRY_RETURN_SENTINEL: u64 = 0x0000_006d_ffff_fff0;
const MAX_IO_BYTES: usize = 1024 * 1024;
const PAGE_SIZE: u64 = 0x1000;

#[derive(Debug, Clone)]
struct FileDescriptor {
    path: String,
    cursor: usize,
    writable: bool,
    socket: bool,
}

pub(crate) fn run(
    name: String,
    bytes: &[u8],
    options: DynamicOptions,
) -> Result<DynamicAnalysis, DynamicError> {
    let loaded = loader_elf64::load(&name, bytes)?;
    let environment = options.environment.clone();
    let network_scenario = options.network_scenario.clone();
    let mut cpu = Cpu64 {
        rip: loaded.entry_point,
        ..Cpu64::default()
    };
    cpu.set_rsp(loaded.initial_rsp);
    let mut provenance = ProvenanceTracker::default();
    provenance.source(
        ProvenanceSourceKind::Sample,
        "loaded ELF64 image",
        loaded.image_base,
        loaded.image_size as usize,
        "linux-loader",
        0,
    );
    let mut machine = LinuxMachine {
        cpu,
        memory: loaded.memory,
        imports: loaded.imports,
        options,
        initial_rsp: loaded.initial_rsp,
        argv: loaded.argv,
        envp: loaded.envp,
        entry_point: loaded.entry_point,
        image_base: loaded.image_base,
        image_size: loaded.image_size,
        instruction_count: 0,
        virtual_time_ms: environment.initial_virtual_time_ms,
        instructions: Vec::new(),
        api_calls: Vec::new(),
        processes: Vec::new(),
        filesystem_events: Vec::new(),
        network_events: Vec::new(),
        network_exchanges: Vec::new(),
        memory_events: Vec::new(),
        system: Vec::new(),
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
        files: default_files(&environment),
        descriptors: default_descriptors(),
        next_fd: 3,
        heap_next: LINUX_HEAP_BASE + 0x1000,
        brk: LINUX_HEAP_BASE + 0x1000,
        mmap_next: LINUX_MMAP_BASE,
        network_runtime: NetworkRuntime::new(network_scenario),
        artifacts: ArtifactStore::default(),
        provenance,
        dynamic_imports: BTreeMap::new(),
        environment,
    };
    machine.system.push(SystemEvent {
        category: "loader".into(),
        operation: "map_elf64".into(),
        target: format!("0x{:016x}", machine.entry_point),
        detail: format!(
            "ELF64 image {} bytes · argc/argv/envp/auxv stack at 0x{:016x}",
            machine.image_size, machine.initial_rsp
        ),
        result: machine.image_size,
    });
    machine.record_timeline(
        "loader",
        "enter",
        format!("ELF64 entry 0x{:016x}", machine.entry_point),
        "synthetic Linux loader",
    );
    machine.execute();

    let executable_regions: Vec<_> = machine
        .memory
        .dirty_regions()
        .filter(|region| region.permissions.execute)
        .map(|region| {
            (
                region.start,
                region.name.to_owned(),
                region.permissions.display(),
                region.data[..region.data.len().min(MAX_ARTIFACT_BYTES)].to_vec(),
            )
        })
        .collect();
    for (address, region_name, permissions, data) in executable_regions {
        let origin = machine.artifact_origin("mprotect", "executable_memory", Some(address), None);
        machine.artifacts.capture(
            ArtifactCapture {
                kind: ArtifactKind::Memory,
                name: format!("linux-memory-{address:016x}.bin"),
                trigger: "executable_memory",
                address: Some(address),
                path: None,
                permissions: Some(permissions),
                force: true,
            },
            &data,
            origin,
        );
        machine.system.push(SystemEvent {
            category: "memory".into(),
            operation: "capture_executable_region".into(),
            target: format!("0x{address:016x}"),
            detail: region_name,
            result: data.len() as u64,
        });
    }

    let snapshots = vec![machine.snapshot("final")];
    let (artifacts, artifact_stats, artifact_blobs) = machine.artifacts.finish();
    let (provenance_sources, provenance_flows, provenance_stats) =
        std::mem::take(&mut machine.provenance).finish();
    let termination = machine
        .termination
        .clone()
        .unwrap_or(Termination::InstructionLimit);
    let mut findings = vec![DynamicFinding {
        id: "linux-user-mode-execution".into(),
        title: "Linux user-mode execution completed".into(),
        severity: DynamicSeverity::Info,
        rationale: "The ELF ran in the bounded x86-64 interpreter against deterministic synthetic Linux syscalls; no host process or kernel operation occurred.".into(),
        evidence: vec![format!(
            "{} instructions · {} syscall/libc events",
            machine.instruction_count,
            machine.api_calls.len()
        )],
    }];
    if !machine.processes.is_empty() {
        findings.push(DynamicFinding {
            id: "linux-process-execution".into(),
            title: "Process execution requested".into(),
            severity: DynamicSeverity::High,
            rationale: "The sample requested execve or a command-oriented libc function. The request was recorded and denied inside the synthetic runtime.".into(),
            evidence: machine
                .processes
                .iter()
                .map(|event| format!("{} · {}", event.operation, event.command))
                .collect(),
        });
    }
    if machine
        .filesystem_events
        .iter()
        .any(|event| event.operation == "write")
    {
        findings.push(DynamicFinding {
            id: "linux-file-write".into(),
            title: "Virtual filesystem content written".into(),
            severity: DynamicSeverity::Medium,
            rationale: "The sample wrote bytes to the synthetic Linux filesystem. Captured content is available as a bounded runtime artifact.".into(),
            evidence: machine
                .filesystem_events
                .iter()
                .filter(|event| event.operation == "write")
                .map(|event| format!("{} · {} bytes", event.path, event.size.unwrap_or_default()))
                .collect(),
        });
    }
    if !machine.network_events.is_empty() {
        findings.push(DynamicFinding {
            id: "linux-network-activity".into(),
            title: "Synthetic network activity observed".into(),
            severity: DynamicSeverity::Medium,
            rationale: "Linux socket syscalls reached the deterministic network sink; the browser made no external connection.".into(),
            evidence: machine
                .network_events
                .iter()
                .map(|event| format!("{} · {}", event.operation, event.destination))
                .collect(),
        });
    }
    if machine
        .memory_events
        .iter()
        .any(|event| event.permissions.contains('x') && event.operation == "protect")
    {
        findings.push(DynamicFinding {
            id: "linux-executable-memory".into(),
            title: "Executable memory protection requested".into(),
            severity: DynamicSeverity::Medium,
            rationale: "The sample requested executable permissions through mmap or mprotect."
                .into(),
            evidence: machine
                .memory_events
                .iter()
                .filter(|event| event.permissions.contains('x'))
                .map(|event| format!("0x{:016x} · {}", event.address, event.permissions))
                .collect(),
        });
    }

    let operating_system = if machine.environment.windows_version.starts_with("Linux") {
        format!(
            "{} (synthetic user mode)",
            machine.environment.windows_version
        )
    } else {
        "Linux 6.8 (synthetic user mode)".into()
    };
    let profile = ExecutionProfile {
        architecture: "x86-64 (64-bit)".into(),
        operating_system,
        image_base: machine.image_base,
        entry_point: machine.entry_point,
        instruction_limit: machine.options.max_instructions,
        trace_limit: machine.options.max_trace_events,
        network_mode: machine.environment.network_mode.description().into(),
        environment: machine.environment.clone(),
        network_scenario: machine.network_runtime.scenario_id().into(),
    };
    let thread_state = if matches!(termination, Termination::ExitProcess { .. }) {
        "terminated"
    } else {
        "stopped"
    };
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
        filesystem: machine.filesystem_events,
        registry: Vec::new(),
        network: machine.network_events,
        network_exchanges: machine.network_exchanges,
        provenance_sources,
        provenance_flows,
        provenance_stats,
        snapshots,
        snapshot_stats: SnapshotStats {
            count: 1,
            truncated: false,
            max_snapshots: 256,
            max_dirty_regions: 64,
            sampled_bytes_per_region: 512,
        },
        unwind_functions: Vec::new(),
        memory: machine.memory_events,
        injection: Vec::new(),
        persistence: Vec::new(),
        exceptions: Vec::new(),
        threads: vec![ThreadSummary {
            tid: 1,
            start_address: machine.entry_point,
            parameter: 0,
            state: thread_state.into(),
            instruction_count: machine.instruction_count,
            exit_code: match machine.termination {
                Some(Termination::ExitProcess { code }) => Some(code),
                _ => None,
            },
        }],
        thread_events: Vec::new(),
        system: machine.system,
        artifacts,
        artifact_stats,
        payload_generations: Vec::new(),
        generation_stats: GenerationStats {
            count: 0,
            chains: 0,
            executed_generations: 0,
            entry_point_candidates: 0,
            reconstructed_imports: 0,
            truncated: false,
        },
        timeline: machine.timeline,
        coverage: ExecutionCoverage {
            unique_instruction_addresses: machine.unique_instruction_addresses.len(),
            unique_api_names: machine.unique_api_names.len(),
            modeled_api_calls: machine.modeled_api_calls,
            unmodeled_api_calls: machine.unmodeled_api_calls,
            dynamic_api_resolutions: machine.dynamic_imports.len(),
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

struct LinuxMachine {
    cpu: Cpu64,
    memory: Memory64,
    imports: BTreeMap<u64, LinuxImport>,
    options: DynamicOptions,
    initial_rsp: u64,
    argv: u64,
    envp: u64,
    entry_point: u64,
    image_base: u64,
    image_size: u64,
    instruction_count: u64,
    virtual_time_ms: u64,
    instructions: Vec<InstructionEvent>,
    api_calls: Vec<ApiEvent>,
    processes: Vec<ProcessEvent>,
    filesystem_events: Vec<FileEvent>,
    network_events: Vec<NetworkEvent>,
    network_exchanges: Vec<NetworkExchange>,
    memory_events: Vec<MemoryEvent>,
    system: Vec<SystemEvent>,
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
    files: BTreeMap<String, Vec<u8>>,
    descriptors: BTreeMap<i32, FileDescriptor>,
    next_fd: i32,
    heap_next: u64,
    brk: u64,
    mmap_next: u64,
    network_runtime: NetworkRuntime,
    artifacts: ArtifactStore,
    provenance: ProvenanceTracker,
    dynamic_imports: BTreeMap<String, u64>,
    environment: crate::EnvironmentProfile,
}

impl LinuxMachine {
    fn execute(&mut self) {
        while self.termination.is_none() && self.instruction_count < self.options.max_instructions {
            if self.cpu.rip == ENTRY_RETURN_SENTINEL {
                self.termination = Some(Termination::ExitProcess {
                    code: self.cpu.gpr[0] as u32,
                });
                break;
            }
            if let Some(import) = self.imports.get(&self.cpu.rip).cloned() {
                if let Err(error) = self.handle_import(import) {
                    self.stop_for_error(error, self.cpu.rip, "linux libc import");
                }
                continue;
            }
            let address = self.cpu.rip;
            self.unique_instruction_addresses.insert(address);
            let bytes = match self.memory.fetch(address, 15) {
                Ok(bytes) => bytes.to_vec(),
                Err(error) => {
                    self.stop_for_error(error, address, "linux execute");
                    break;
                }
            };
            let mut decoder = Decoder::with_ip(64, &bytes, address, DecoderOptions::NONE);
            let instruction = decoder.decode();
            if instruction.code() == Code::INVALID {
                self.invalid_instruction_count += 1;
                self.first_unsupported.get_or_insert(InstructionDiagnostic {
                    address,
                    instruction: "invalid x86-64 instruction".into(),
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
                self.stop_for_error(error, address, "linux instruction");
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
                let value = self.cpu.read_operand(&self.memory, instruction, 0)?.0;
                self.cpu.push(&mut self.memory, value)?;
            }
            Pop => {
                let value = self.cpu.pop(&self.memory)?;
                self.cpu
                    .write_operand(&mut self.memory, instruction, 0, value)?;
            }
            Call => {
                let target = self.cpu.read_operand(&self.memory, instruction, 0)?.0;
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
                let right = self.cpu.read_operand(&self.memory, instruction, 1)?.0;
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
                let right = self.cpu.read_operand(&self.memory, instruction, 1)?.0;
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
                };
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
            Syscall => self.handle_syscall()?,
            Nop | Endbr64 => {}
            Int3 | Hlt => self.termination = Some(Termination::Halted),
            _ => {
                return Err(DynamicError::UnsupportedOperand(format!(
                    "linux x86-64 {instruction}"
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

    fn handle_syscall(&mut self) -> Result<(), DynamicError> {
        let number = self.cpu.gpr[0];
        let args = [
            self.cpu.gpr[7],
            self.cpu.gpr[6],
            self.cpu.gpr[2],
            self.cpu.gpr[10],
            self.cpu.gpr[8],
            self.cpu.gpr[9],
        ];
        let name = syscall_name(number);
        let unmodeled_before = self.unmodeled_api_calls;
        let result = self.dispatch_linux_call(number, &args)?;
        self.cpu.gpr[0] = result;
        self.record_api(
            "linux",
            name,
            &args,
            result,
            syscall_summary(name, result),
            self.unmodeled_api_calls == unmodeled_before,
        );
        Ok(())
    }

    fn dispatch_linux_call(&mut self, number: u64, args: &[u64; 6]) -> Result<u64, DynamicError> {
        match number {
            0 => self.sys_read(args[0] as i32, args[1], args[2] as usize),
            1 => self.sys_write(args[0] as i32, args[1], args[2] as usize),
            2 => {
                let path = self.memory.read_c_string(args[0], 4096);
                Ok(self.open_path(path, args[1]) as i64 as u64)
            }
            3 => Ok(self.close_fd(args[0] as i32) as i64 as u64),
            9 => self.sys_mmap(args),
            10 => self.sys_mprotect(args[0], args[1] as usize, args[2]),
            11 => {
                let size = align_page(args[1] as usize);
                self.memory.set_permissions(
                    args[0],
                    size,
                    Permissions {
                        read: false,
                        write: false,
                        execute: false,
                    },
                )?;
                self.memory_events.push(MemoryEvent {
                    operation: "unmap".into(),
                    address: args[0],
                    size: size.min(u32::MAX as usize) as u32,
                    permissions: "---".into(),
                });
                Ok(0)
            }
            12 => Ok(self.sys_brk(args[0])),
            21 => {
                let path = self.memory.read_c_string(args[0], 4096);
                Ok(if self.files.contains_key(&path) {
                    0
                } else {
                    errno(2)
                })
            }
            35 | 230 => {
                self.virtual_time_ms = self.virtual_time_ms.saturating_add(1);
                Ok(0)
            }
            39 => Ok(4242),
            41 => Ok(self.sys_socket(args[0], args[1], args[2])),
            42 => Ok(self.sys_connect(args[0] as i32, args[1], args[2] as usize)),
            44 => self.sys_send(args[0] as i32, args[1], args[2] as usize),
            45 => self.sys_recv(args[0] as i32, args[1], args[2] as usize),
            59 => Ok(self.sys_execve(args[0])),
            60 | 231 => {
                self.termination = Some(Termination::ExitProcess {
                    code: args[0] as u32,
                });
                Ok(0)
            }
            63 => self.sys_uname(args[0]),
            89 => self.sys_readlink(args[0], args[1], args[2] as usize),
            96 | 228 => self.sys_clock(args[1]),
            102 | 104 | 107 | 108 => Ok(1000),
            158 => self.sys_arch_prctl(args[0], args[1]),
            202 | 218 | 273 | 334 => Ok(0),
            257 => {
                let path = self.memory.read_c_string(args[1], 4096);
                Ok(self.open_path(path, args[2]) as i64 as u64)
            }
            262 => self.sys_stat(args[1], args[2]),
            302 => Ok(0),
            318 => self.sys_getrandom(args[0], args[1] as usize),
            _ => {
                self.unmodeled_api_calls += 1;
                self.warnings.push(format!(
                    "Linux syscall {number} is not modeled; returned -ENOSYS"
                ));
                Ok(errno(38))
            }
        }
    }

    fn handle_import(&mut self, import: LinuxImport) -> Result<(), DynamicError> {
        let args = [
            self.cpu.gpr[7],
            self.cpu.gpr[6],
            self.cpu.gpr[2],
            self.cpu.gpr[1],
            self.cpu.gpr[8],
            self.cpu.gpr[9],
        ];
        let normalized = import.name.trim_start_matches('_').to_ascii_lowercase();
        let result = match normalized.as_str() {
            "libc_start_main" => {
                let main = args[0];
                self.cpu.set_rsp(self.initial_rsp);
                self.cpu.push(&mut self.memory, ENTRY_RETURN_SENTINEL)?;
                self.cpu.gpr[7] = 1;
                self.cpu.gpr[6] = self.argv;
                self.cpu.gpr[2] = self.envp;
                self.cpu.rip = main;
                self.record_api(
                    &import.module,
                    &import.name,
                    &args,
                    main,
                    format!("Entered main at 0x{main:016x} through synthetic libc startup"),
                    true,
                );
                return Ok(());
            }
            "exit" | "exit_group" => {
                self.termination = Some(Termination::ExitProcess {
                    code: args[0] as u32,
                });
                0
            }
            "puts" | "printf" | "fprintf" | "fputs" => {
                let text = self.memory.read_c_string(args[0], 4096);
                self.filesystem_events.push(FileEvent {
                    operation: "write".into(),
                    path: "/dev/stdout".into(),
                    size: Some(text.len() as u32),
                    preview: Some(preview(text.as_bytes())),
                });
                text.len() as u64
            }
            "strlen" => self.memory.read_c_string(args[0], MAX_IO_BYTES).len() as u64,
            "memcpy" | "memmove" => {
                let count = (args[2] as usize).min(MAX_IO_BYTES);
                let bytes = self.memory.read(args[1], count)?.to_vec();
                self.memory.write(args[0], &bytes)?;
                self.provenance.propagate(args[1], args[0], count);
                args[0]
            }
            "memset" => {
                let count = (args[2] as usize).min(MAX_IO_BYTES);
                self.memory.write(args[0], &vec![args[1] as u8; count])?;
                self.provenance.clear(args[0], count);
                args[0]
            }
            "malloc" => self.allocate_heap(args[0] as usize),
            "calloc" => self.allocate_heap((args[0] as usize).saturating_mul(args[1] as usize)),
            "realloc" => self.allocate_heap(args[1] as usize),
            "free" => 0,
            "write" => self.sys_write(args[0] as i32, args[1], args[2] as usize)?,
            "read" => self.sys_read(args[0] as i32, args[1], args[2] as usize)?,
            "open" | "open64" => {
                let path = self.memory.read_c_string(args[0], 4096);
                self.open_path(path, args[1]) as i64 as u64
            }
            "openat" => {
                let path = self.memory.read_c_string(args[1], 4096);
                self.open_path(path, args[2]) as i64 as u64
            }
            "close" => self.close_fd(args[0] as i32) as i64 as u64,
            "getpid" => 4242,
            "getuid" | "geteuid" | "getgid" | "getegid" => 1000,
            "mmap" | "mmap64" => {
                let syscall_args = [args[0], args[1], args[2], args[3], args[4], args[5]];
                self.sys_mmap(&syscall_args)?
            }
            "mprotect" => self.sys_mprotect(args[0], args[1] as usize, args[2])?,
            "socket" => self.sys_socket(args[0], args[1], args[2]),
            "connect" => self.sys_connect(args[0] as i32, args[1], args[2] as usize),
            "send" | "sendto" => self.sys_send(args[0] as i32, args[1], args[2] as usize)?,
            "recv" | "recvfrom" => self.sys_recv(args[0] as i32, args[1], args[2] as usize)?,
            "execve" => self.sys_execve(args[0]),
            "system" => {
                let command = self.memory.read_c_string(args[0], 4096);
                self.processes.push(ProcessEvent {
                    operation: "system".into(),
                    command: command.clone(),
                    synthetic_result: "denied by synthetic Linux runtime".into(),
                });
                errno(13)
            }
            "getenv" => 0,
            "dlopen" | "dlsym" => {
                self.unmodeled_api_calls += 1;
                0
            }
            "errno_location" => self.allocate_heap(8),
            _ => {
                self.unmodeled_api_calls += 1;
                self.warnings.push(format!(
                    "Linux import {} is not modeled; returned 0",
                    import.name
                ));
                0
            }
        };
        self.cpu.gpr[0] = result;
        let modeled = !matches!(normalized.as_str(), "dlopen" | "dlsym")
            && !normalized.is_empty()
            && !self.warnings.last().is_some_and(|warning| {
                warning.contains(&format!("Linux import {} is not modeled", import.name))
            });
        self.record_api(
            &import.module,
            &import.name,
            &args,
            result,
            format!("Modeled synthetic Linux libc call {}", import.name),
            modeled,
        );
        if self.termination.is_none() {
            self.cpu.rip = self.cpu.pop(&self.memory)?;
        }
        Ok(())
    }

    fn sys_read(&mut self, fd: i32, address: u64, requested: usize) -> Result<u64, DynamicError> {
        let requested = requested.min(MAX_IO_BYTES);
        let Some(descriptor) = self.descriptors.get(&fd).cloned() else {
            return Ok(errno(9));
        };
        let bytes = if descriptor.socket {
            self.network_runtime
                .recv_socket(fd as u32, requested)
                .unwrap_or_default()
        } else {
            let source = self
                .files
                .get(&descriptor.path)
                .cloned()
                .unwrap_or_default();
            source
                .get(
                    descriptor.cursor
                        ..descriptor
                            .cursor
                            .saturating_add(requested)
                            .min(source.len()),
                )
                .unwrap_or_default()
                .to_vec()
        };
        self.memory.write(address, &bytes)?;
        if let Some(current) = self.descriptors.get_mut(&fd) {
            current.cursor = current.cursor.saturating_add(bytes.len());
        }
        if descriptor.socket {
            let destination = self
                .network_runtime
                .socket_destination(fd as u32)
                .unwrap_or_else(|| "unconnected".into());
            if !bytes.is_empty() {
                self.provenance.source(
                    ProvenanceSourceKind::Network,
                    destination.clone(),
                    address,
                    bytes.len(),
                    "recvfrom",
                    self.instruction_count,
                );
            }
            self.network_events.push(NetworkEvent {
                operation: "receive".into(),
                destination,
                size: Some(bytes.len() as u32),
                preview: Some(preview(&bytes)),
                synthetic_result: "scripted response".into(),
            });
        } else {
            if !bytes.is_empty() {
                self.provenance.source(
                    ProvenanceSourceKind::VirtualFile,
                    descriptor.path.clone(),
                    address,
                    bytes.len(),
                    "read",
                    self.instruction_count,
                );
            }
            self.filesystem_events.push(FileEvent {
                operation: "read".into(),
                path: descriptor.path,
                size: Some(bytes.len() as u32),
                preview: Some(preview(&bytes)),
            });
        }
        Ok(bytes.len() as u64)
    }

    fn sys_write(&mut self, fd: i32, address: u64, requested: usize) -> Result<u64, DynamicError> {
        let requested = requested.min(MAX_IO_BYTES);
        let bytes = self.memory.read(address, requested)?.to_vec();
        if fd == 1 || fd == 2 {
            self.filesystem_events.push(FileEvent {
                operation: "write".into(),
                path: if fd == 1 {
                    "/dev/stdout"
                } else {
                    "/dev/stderr"
                }
                .into(),
                size: Some(bytes.len() as u32),
                preview: Some(preview(&bytes)),
            });
            return Ok(bytes.len() as u64);
        }
        let Some(descriptor) = self.descriptors.get(&fd).cloned() else {
            return Ok(errno(9));
        };
        if descriptor.socket {
            let destination = self
                .network_runtime
                .socket_destination(fd as u32)
                .unwrap_or_else(|| "unconnected".into());
            self.provenance.observe(
                address,
                bytes.len(),
                ProvenanceSinkKind::NetworkRequest,
                destination.clone(),
                "sendto",
                self.instruction_count,
            );
            self.network_events.push(NetworkEvent {
                operation: "send".into(),
                destination: destination.clone(),
                size: Some(bytes.len() as u32),
                preview: Some(preview(&bytes)),
                synthetic_result: "captured by deterministic sink".into(),
            });
            self.network_exchanges.push(NetworkExchange {
                sequence: self.network_exchanges.len() as u64,
                protocol: "tcp".into(),
                operation: "send".into(),
                destination,
                request_headers: Vec::new(),
                request_preview: Some(preview(&bytes)),
                request_size: bytes.len() as u64,
                request_sha256: Some(hex::encode(Sha256::digest(&bytes))),
                response_status: None,
                response_headers: Vec::new(),
                response_size: 0,
                response_sha256: None,
                artifact_id: None,
                outcome: "synthetic sink".into(),
            });
            return Ok(bytes.len() as u64);
        }
        if !descriptor.writable {
            return Ok(errno(9));
        }
        let file = self.files.entry(descriptor.path.clone()).or_default();
        if descriptor.cursor > file.len() {
            file.resize(descriptor.cursor, 0);
        }
        if descriptor.cursor.saturating_add(bytes.len()) > MAX_IO_BYTES {
            self.truncated = true;
            return Ok(errno(27));
        }
        let end = descriptor.cursor + bytes.len();
        if end > file.len() {
            file.resize(end, 0);
        }
        file[descriptor.cursor..end].copy_from_slice(&bytes);
        if let Some(current) = self.descriptors.get_mut(&fd) {
            current.cursor = end;
        }
        self.filesystem_events.push(FileEvent {
            operation: "write".into(),
            path: descriptor.path.clone(),
            size: Some(bytes.len() as u32),
            preview: Some(preview(&bytes)),
        });
        self.provenance.observe(
            address,
            bytes.len(),
            ProvenanceSinkKind::VirtualFile,
            descriptor.path.clone(),
            "write",
            self.instruction_count,
        );
        let captured = file.clone();
        let origin = self.artifact_origin(
            "write",
            "virtual_file_write",
            None,
            Some(descriptor.path.clone()),
        );
        self.artifacts.capture(
            ArtifactCapture {
                kind: ArtifactKind::VirtualFile,
                name: descriptor
                    .path
                    .rsplit('/')
                    .next()
                    .unwrap_or("linux-file.bin")
                    .into(),
                trigger: "virtual_file_write",
                address: None,
                path: Some(descriptor.path),
                permissions: None,
                force: true,
            },
            &captured,
            origin,
        );
        Ok(bytes.len() as u64)
    }

    fn open_path(&mut self, path: String, flags: u64) -> i32 {
        if path.is_empty() {
            return -2;
        }
        let create = flags & 0o100 != 0;
        let truncate = flags & 0o1000 != 0;
        let writable = flags & 3 != 0;
        if !self.files.contains_key(&path) && !create {
            self.filesystem_events.push(FileEvent {
                operation: "open_failed".into(),
                path,
                size: None,
                preview: None,
            });
            return -2;
        }
        if create {
            self.files.entry(path.clone()).or_default();
        }
        if truncate && writable {
            self.files.insert(path.clone(), Vec::new());
        }
        let fd = self.next_fd;
        self.next_fd += 1;
        self.descriptors.insert(
            fd,
            FileDescriptor {
                path: path.clone(),
                cursor: 0,
                writable,
                socket: false,
            },
        );
        self.filesystem_events.push(FileEvent {
            operation: "open".into(),
            path,
            size: None,
            preview: None,
        });
        fd
    }

    fn close_fd(&mut self, fd: i32) -> i32 {
        if self.descriptors.remove(&fd).is_some() {
            self.network_runtime.close(fd as u32);
            0
        } else {
            -9
        }
    }

    fn sys_mmap(&mut self, args: &[u64; 6]) -> Result<u64, DynamicError> {
        let size = align_page((args[1] as usize).clamp(1, 16 * 1024 * 1024));
        let requested = args[0];
        let address = if requested != 0 && args[3] & 0x10 != 0 {
            requested & !(PAGE_SIZE - 1)
        } else {
            let address = self.mmap_next;
            self.mmap_next = self.mmap_next.saturating_add(size as u64 + PAGE_SIZE);
            address
        };
        let permissions = linux_permissions(args[2]);
        if self
            .memory
            .map(address, size, permissions, "Linux mmap allocation")
            .is_err()
        {
            return Ok(errno(12));
        }
        if args[4] as i64 >= 0
            && let Some(descriptor) = self.descriptors.get(&(args[4] as i32))
            && let Some(file) = self.files.get(&descriptor.path)
        {
            let offset = args[5] as usize;
            if let Some(data) = file.get(offset..offset.saturating_add(size).min(file.len())) {
                self.memory.write_force(address, data)?;
                self.provenance.source(
                    ProvenanceSourceKind::VirtualFile,
                    descriptor.path.clone(),
                    address,
                    data.len(),
                    "mmap",
                    self.instruction_count,
                );
            }
        }
        self.memory_events.push(MemoryEvent {
            operation: "allocate".into(),
            address,
            size: size as u32,
            permissions: permissions.display(),
        });
        Ok(address)
    }

    fn sys_mprotect(&mut self, address: u64, size: usize, prot: u64) -> Result<u64, DynamicError> {
        let size = align_page(size.max(1));
        let permissions = linux_permissions(prot);
        if self
            .memory
            .set_permissions(address, size, permissions)
            .is_err()
        {
            return Ok(errno(12));
        }
        if permissions.execute {
            self.provenance.observe(
                address,
                size,
                ProvenanceSinkKind::ExecutableMemory,
                format!("0x{address:016x}"),
                "mprotect",
                self.instruction_count,
            );
        }
        self.memory_events.push(MemoryEvent {
            operation: "protect".into(),
            address,
            size: size.min(u32::MAX as usize) as u32,
            permissions: permissions.display(),
        });
        Ok(0)
    }

    fn sys_brk(&mut self, requested: u64) -> u64 {
        if requested == 0 {
            return self.brk;
        }
        let maximum = LINUX_HEAP_BASE + LINUX_HEAP_SIZE as u64;
        if requested >= LINUX_HEAP_BASE && requested <= maximum {
            self.brk = requested;
        }
        self.brk
    }

    fn sys_socket(&mut self, domain: u64, kind: u64, _protocol: u64) -> u64 {
        if domain != 2 || kind & 0xf != 1 {
            return errno(97);
        }
        let fd = self.next_fd;
        self.next_fd += 1;
        self.descriptors.insert(
            fd,
            FileDescriptor {
                path: format!("socket:{fd}"),
                cursor: 0,
                writable: true,
                socket: true,
            },
        );
        self.network_runtime.register_socket(fd as u32);
        fd as u64
    }

    fn sys_connect(&mut self, fd: i32, sockaddr: u64, length: usize) -> u64 {
        if !self.descriptors.get(&fd).is_some_and(|item| item.socket) || length < 8 {
            return errno(9);
        }
        let Ok(bytes) = self.memory.read(sockaddr, length.min(16)) else {
            return errno(14);
        };
        if bytes.len() < 8 || u16::from_le_bytes([bytes[0], bytes[1]]) != 2 {
            return errno(97);
        }
        let port = u16::from_be_bytes([bytes[2], bytes[3]]);
        let destination = format!("{}.{}.{}.{}:{port}", bytes[4], bytes[5], bytes[6], bytes[7]);
        if self.environment.network_mode == NetworkMode::Offline {
            self.network_events.push(NetworkEvent {
                operation: "connect".into(),
                destination,
                size: None,
                preview: None,
                synthetic_result: "offline profile".into(),
            });
            return errno(101);
        }
        self.network_runtime
            .connect_socket(fd as u32, destination.clone());
        self.network_events.push(NetworkEvent {
            operation: "connect".into(),
            destination,
            size: None,
            preview: None,
            synthetic_result: "connected to deterministic sink".into(),
        });
        0
    }

    fn sys_send(&mut self, fd: i32, buffer: u64, size: usize) -> Result<u64, DynamicError> {
        self.sys_write(fd, buffer, size)
    }

    fn sys_recv(&mut self, fd: i32, buffer: u64, size: usize) -> Result<u64, DynamicError> {
        self.sys_read(fd, buffer, size)
    }

    fn sys_execve(&mut self, path_pointer: u64) -> u64 {
        let command = self.memory.read_c_string(path_pointer, 4096);
        self.provenance.observe(
            path_pointer,
            command.len(),
            ProvenanceSinkKind::ProcessCommand,
            command.clone(),
            "execve",
            self.instruction_count,
        );
        self.processes.push(ProcessEvent {
            operation: "execve".into(),
            command: command.clone(),
            synthetic_result: "denied by synthetic Linux runtime".into(),
        });
        self.record_timeline("process", "execve", command, "linux syscall");
        errno(13)
    }

    fn sys_uname(&mut self, address: u64) -> Result<u64, DynamicError> {
        let fields = [
            "Linux",
            "NOPE-LINUX",
            "6.8.0-nope",
            "#1 SMP",
            "x86_64",
            "localdomain",
        ];
        for (index, value) in fields.iter().enumerate() {
            let mut field = [0u8; 65];
            let bytes = value.as_bytes();
            field[..bytes.len().min(64)].copy_from_slice(&bytes[..bytes.len().min(64)]);
            self.memory.write(address + (index * 65) as u64, &field)?;
        }
        Ok(0)
    }

    fn sys_readlink(
        &mut self,
        path_pointer: u64,
        output: u64,
        size: usize,
    ) -> Result<u64, DynamicError> {
        let path = self.memory.read_c_string(path_pointer, 4096);
        let target = if path == "/proc/self/exe" {
            "/sample/nope-linux"
        } else {
            return Ok(errno(2));
        };
        let bytes = &target.as_bytes()[..target.len().min(size).min(4096)];
        self.memory.write(output, bytes)?;
        Ok(bytes.len() as u64)
    }

    fn sys_clock(&mut self, address: u64) -> Result<u64, DynamicError> {
        if address != 0 {
            let seconds = self.virtual_time_ms / 1000;
            let nanos = (self.virtual_time_ms % 1000) * 1_000_000;
            self.memory.write(address, &seconds.to_le_bytes())?;
            self.memory.write(address + 8, &nanos.to_le_bytes())?;
        }
        Ok(0)
    }

    fn sys_arch_prctl(&mut self, code: u64, address: u64) -> Result<u64, DynamicError> {
        match code {
            0x1002 => self.cpu.fs_base = address,
            0x1001 => self.cpu.gs_base = address,
            0x1003 if address != 0 => self
                .memory
                .write(address, &self.cpu.fs_base.to_le_bytes())?,
            0x1004 if address != 0 => self
                .memory
                .write(address, &self.cpu.gs_base.to_le_bytes())?,
            _ => return Ok(errno(22)),
        }
        self.system.push(SystemEvent {
            category: "process".into(),
            operation: "arch_prctl".into(),
            target: format!("0x{address:016x}"),
            detail: format!("code 0x{code:x}"),
            result: 0,
        });
        Ok(0)
    }

    fn sys_stat(&mut self, path_pointer: u64, output: u64) -> Result<u64, DynamicError> {
        let path = self.memory.read_c_string(path_pointer, 4096);
        let Some(file) = self.files.get(&path) else {
            return Ok(errno(2));
        };
        let mut stat = [0u8; 144];
        stat[24..28].copy_from_slice(&0o100644u32.to_le_bytes());
        stat[48..56].copy_from_slice(&(file.len() as u64).to_le_bytes());
        self.memory.write(output, &stat)?;
        Ok(0)
    }

    fn sys_getrandom(&mut self, output: u64, size: usize) -> Result<u64, DynamicError> {
        let size = size.min(4096);
        let bytes: Vec<u8> = (0..size)
            .map(|index| b"NOPE-LINUX-RANDOM"[index % 17])
            .collect();
        self.memory.write(output, &bytes)?;
        Ok(size as u64)
    }

    fn allocate_heap(&mut self, size: usize) -> u64 {
        let size = size.clamp(1, MAX_IO_BYTES).saturating_add(15) & !15;
        let address = self.heap_next;
        let next = address.saturating_add(size as u64);
        if next > LINUX_HEAP_BASE + LINUX_HEAP_SIZE as u64 {
            return 0;
        }
        self.heap_next = next;
        address
    }

    fn record_api(
        &mut self,
        module: &str,
        name: &str,
        args: &[u64; 6],
        result: u64,
        summary: String,
        modeled: bool,
    ) {
        if self.api_calls.len() >= crate::HARD_MAX_API_EVENTS {
            self.truncated = true;
            return;
        }
        if modeled {
            self.modeled_api_calls += 1;
        }
        self.unique_api_names.insert(name.into());
        self.api_calls.push(ApiEvent {
            index: self.api_calls.len() as u64,
            instruction: self.instruction_count,
            module: module.into(),
            name: name.into(),
            arguments: args.iter().map(|value| format!("0x{value:016x}")).collect(),
            result,
            summary: summary.clone(),
        });
        self.record_timeline("syscall", name, summary, module);
    }

    fn record_timeline(&mut self, category: &str, operation: &str, subject: String, source: &str) {
        if self.timeline.len() >= crate::HARD_MAX_API_EVENTS {
            self.truncated = true;
            return;
        }
        self.timeline.push(TimelineEvent {
            sequence: self.timeline.len() as u64,
            instruction: self.instruction_count,
            virtual_time_ms: self.virtual_time_ms,
            category: category.into(),
            operation: operation.into(),
            subject,
            source_api: source.into(),
        });
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

    fn snapshot(&self, trigger: &str) -> ExecutionSnapshot {
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
        let state = format!(
            "{:?}:{}:{}:{}:{}",
            self.cpu.gpr,
            self.cpu.rip,
            self.api_calls.len(),
            self.filesystem_events.len(),
            self.network_events.len()
        );
        ExecutionSnapshot {
            sequence: 0,
            trigger: trigger.into(),
            instruction: self.instruction_count,
            virtual_time_ms: self.virtual_time_ms,
            registers,
            events: SnapshotEventCounts {
                api_calls: self.api_calls.len(),
                processes: self.processes.len(),
                filesystem: self.filesystem_events.len(),
                registry: 0,
                network: self.network_events.len(),
                memory: self.memory_events.len(),
                injection: 0,
                persistence: 0,
                provenance_flows: self.provenance.flow_count(),
            },
            dirty_memory_regions: self.memory.dirty_regions().count(),
            state_sha256: hex::encode(Sha256::digest(state.as_bytes())),
        }
    }

    fn stop_for_error(&mut self, error: DynamicError, address: u64, operation: &str) {
        self.termination = Some(match error {
            DynamicError::MemoryRead { address }
            | DynamicError::MemoryWrite { address }
            | DynamicError::MemoryExecute { address } => Termination::MemoryFault {
                address,
                operation: operation.into(),
            },
            _ => Termination::UnsupportedInstruction {
                address,
                instruction: error.to_string(),
            },
        });
    }
}

fn default_descriptors() -> BTreeMap<i32, FileDescriptor> {
    [
        (0, "/dev/stdin", false),
        (1, "/dev/stdout", true),
        (2, "/dev/stderr", true),
    ]
    .into_iter()
    .map(|(fd, path, writable)| {
        (
            fd,
            FileDescriptor {
                path: path.into(),
                cursor: 0,
                writable,
                socket: false,
            },
        )
    })
    .collect()
}

fn default_files(environment: &crate::EnvironmentProfile) -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([
        ("/dev/stdin".into(), Vec::new()),
        ("/dev/stdout".into(), Vec::new()),
        ("/dev/stderr".into(), Vec::new()),
        ("/etc/hostname".into(), b"NOPE-LINUX\n".to_vec()),
        (
            "/proc/self/status".into(),
            format!(
                "Name:\tsample\nPid:\t4242\nUid:\t1000\t1000\t1000\t1000\nTracerPid:\t{}\n",
                if environment.debugger_present {
                    1337
                } else {
                    0
                }
            )
            .into_bytes(),
        ),
        (
            "/proc/cpuinfo".into(),
            format!(
                "processor\t: 0\nmodel name\t: Synthetic x86-64\ncpu cores\t: {}\n",
                environment.cpu_count
            )
            .into_bytes(),
        ),
    ])
}

fn syscall_name(number: u64) -> &'static str {
    match number {
        0 => "read",
        1 => "write",
        2 => "open",
        3 => "close",
        9 => "mmap",
        10 => "mprotect",
        11 => "munmap",
        12 => "brk",
        21 => "access",
        35 => "nanosleep",
        39 => "getpid",
        41 => "socket",
        42 => "connect",
        44 => "sendto",
        45 => "recvfrom",
        59 => "execve",
        60 => "exit",
        63 => "uname",
        89 => "readlink",
        96 => "gettimeofday",
        102 => "getuid",
        104 => "getgid",
        107 => "geteuid",
        108 => "getegid",
        158 => "arch_prctl",
        202 => "futex",
        218 => "set_tid_address",
        228 => "clock_gettime",
        230 => "clock_nanosleep",
        231 => "exit_group",
        257 => "openat",
        262 => "newfstatat",
        273 => "set_robust_list",
        302 => "prlimit64",
        318 => "getrandom",
        334 => "rseq",
        _ => "unknown_syscall",
    }
}

fn syscall_summary(name: &str, result: u64) -> String {
    if (result as i64) < 0 {
        format!("Synthetic Linux {name} returned {}", result as i64)
    } else {
        format!("Synthetic Linux {name} returned {result}")
    }
}

fn errno(value: i64) -> u64 {
    (-value) as u64
}

fn align_page(size: usize) -> usize {
    size.saturating_add(PAGE_SIZE as usize - 1) & !(PAGE_SIZE as usize - 1)
}

fn linux_permissions(prot: u64) -> Permissions {
    Permissions {
        read: prot & 1 != 0,
        write: prot & 2 != 0,
        execute: prot & 4 != 0,
    }
}

fn preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(96)
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            }
        })
        .collect()
}
