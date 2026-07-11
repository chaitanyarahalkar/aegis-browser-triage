use crate::{
    ApiEvent, DynamicError, DynamicFinding, DynamicOptions, DynamicReport, DynamicSeverity,
    ExecutionProfile, FileEvent, HARD_MAX_API_EVENTS, InstructionEvent, MemoryEvent, NetworkEvent,
    ProcessEvent, RegistryEvent, Termination,
    cpu::Cpu,
    loader::{self, ApiImport, STACK_TOP},
    memory::{Memory, Permissions},
};
use iced_x86::{Code, Decoder, DecoderOptions, Instruction, Mnemonic, OpKind};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const ENTRY_RETURN_SENTINEL: u32 = 0xffff_fff0;
const HEAP_BASE: u32 = 0x1000_0000;

pub(crate) fn run(
    _name: String,
    bytes: &[u8],
    options: DynamicOptions,
) -> Result<DynamicReport, DynamicError> {
    let loaded = loader::load(bytes)?;
    let profile = ExecutionProfile {
        architecture: "x86 (32-bit)".into(),
        operating_system: "Synthetic Windows user mode".into(),
        image_base: loaded.image_base,
        entry_point: loaded.entry_point,
        instruction_limit: options.max_instructions,
        trace_limit: options.max_trace_events,
        network_mode: "Synthetic sink; no external access".into(),
    };
    let mut machine = Machine {
        cpu: Cpu {
            eip: loaded.entry_point,
            esp: STACK_TOP,
            ebp: STACK_TOP,
            ..Cpu::default()
        },
        memory: loaded.memory,
        imports: loaded.imports,
        options,
        instruction_count: 0,
        virtual_time_ms: 1_000_000,
        instructions: Vec::new(),
        api_calls: Vec::new(),
        processes: Vec::new(),
        filesystem: Vec::new(),
        registry: Vec::new(),
        network: Vec::new(),
        memory_events: Vec::new(),
        warnings: loaded.warnings,
        termination: None,
        truncated: false,
        next_handle: 0x100,
        heap_next: HEAP_BASE,
    };
    machine
        .cpu
        .push(&mut machine.memory, ENTRY_RETURN_SENTINEL)?;
    machine.execute();

    let findings = machine.build_findings();
    let termination = machine
        .termination
        .clone()
        .unwrap_or(Termination::InstructionLimit);
    Ok(DynamicReport {
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
        findings,
        warnings: machine.warnings,
        truncated: machine.truncated,
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
    warnings: Vec<String>,
    termination: Option<Termination>,
    truncated: bool,
    next_handle: u32,
    heap_next: u32,
}

impl Machine {
    fn execute(&mut self) {
        while self.termination.is_none() && self.instruction_count < self.options.max_instructions {
            if self.cpu.eip == ENTRY_RETURN_SENTINEL {
                self.termination = Some(Termination::ReturnedFromEntryPoint);
                break;
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
            let bytes = match self.memory.fetch(address, 15) {
                Ok(bytes) => bytes,
                Err(error) => {
                    self.termination = Some(memory_termination(error, "execute"));
                    break;
                }
            };
            let mut decoder = Decoder::with_ip(32, bytes, address as u64, DecoderOptions::NONE);
            let instruction = decoder.decode();
            if instruction.code() == Code::INVALID {
                self.termination = Some(Termination::InvalidInstruction { address });
                break;
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
            if let Err(error) = self.execute_instruction(&instruction) {
                match error {
                    DynamicError::MemoryRead { .. }
                    | DynamicError::MemoryWrite { .. }
                    | DynamicError::MemoryExecute { .. } => {
                        self.termination = Some(memory_termination(error, "instruction"));
                    }
                    _ => {
                        self.termination = Some(Termination::UnsupportedInstruction {
                            address,
                            instruction: instruction.to_string(),
                        });
                        self.warnings.push(error.to_string());
                    }
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
            Add | Sub | Xor | And | Or => self.binary_operation(instruction)?,
            Cmp | Test => self.comparison(instruction)?,
            Inc | Dec => self.increment(instruction)?,
            Neg | Not => self.unary(instruction)?,
            Shl | Sal | Shr | Sar => self.shift(instruction)?,
            Imul => self.imul(instruction)?,
            Jmp => self.cpu.eip = self.branch_target(instruction, 0)?,
            Je | Jne | Ja | Jae | Jb | Jbe | Jg | Jge | Jl | Jle | Js | Jns => {
                if self.condition(instruction.mnemonic()) {
                    self.cpu.eip = self.branch_target(instruction, 0)?;
                }
            }
            Jecxz => {
                if self.cpu.ecx == 0 {
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
            Cld => self.cpu.direction = false,
            Std => self.cpu.direction = true,
            Nop => {}
            Int3 | Hlt => self.termination = Some(Termination::Halted),
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
            Mnemonic::Sub => left.wrapping_sub(right),
            Mnemonic::Xor => left ^ right,
            Mnemonic::And => left & right,
            Mnemonic::Or => left | right,
            _ => unreachable!(),
        };
        match instruction.mnemonic() {
            Mnemonic::Add => self.cpu.set_add_flags(left, right, result, size),
            Mnemonic::Sub => self.cpu.set_sub_flags(left, right, result, size),
            _ => self.cpu.set_logic_flags(result, size),
        }
        self.cpu
            .write_operand(&mut self.memory, instruction, 0, result)?;
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
            _ => unreachable!(),
        };
        self.cpu.set_logic_flags(result, size);
        self.cpu
            .write_operand(&mut self.memory, instruction, 0, result)?;
        Ok(())
    }

    fn imul(&mut self, instruction: &Instruction) -> Result<(), DynamicError> {
        if instruction.op_count() < 2 {
            return Err(DynamicError::UnsupportedOperand(
                "single-operand imul".into(),
            ));
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
            _ => false,
        }
    }

    fn handle_api(&mut self, import: ApiImport) -> Result<(), DynamicError> {
        let return_address = self.cpu.pop(&self.memory)?;
        let mut args = Vec::with_capacity(import.argument_count);
        for index in 0..import.argument_count {
            args.push(
                self.memory
                    .read_u32(self.cpu.esp.wrapping_add((index * 4) as u32))?,
            );
        }
        self.cpu.esp = self
            .cpu
            .esp
            .wrapping_add((import.argument_count * 4) as u32);
        let lower = import.name.to_ascii_lowercase();
        let (result, summary, display_args) = self.emulate_api(&lower, &args)?;
        self.cpu.eax = result;
        self.cpu.eip = return_address;
        self.api_calls.push(ApiEvent {
            index: self.api_calls.len() as u64,
            instruction: self.instruction_count,
            module: import.module,
            name: import.name,
            arguments: display_args,
            result,
            summary,
        });
        Ok(())
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
                self.termination = Some(Termination::ExitProcess { code });
                Ok((
                    0,
                    format!("Process exited with code {code}"),
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
            "getcurrentprocessid" => Ok((1337, "Returned synthetic process ID".into(), Vec::new())),
            "getcurrentthreadid" => Ok((1, "Returned synthetic thread ID".into(), Vec::new())),
            "getmodulehandlea" => Ok((
                0x0040_0000,
                "Returned synthetic module handle".into(),
                hex_args(),
            )),
            "loadlibrarya" => {
                let library = self
                    .memory
                    .read_c_string(args.first().copied().unwrap_or(0), 260);
                Ok((
                    0x7600_0000,
                    format!("Modeled loading {library}"),
                    vec![library],
                ))
            }
            "getprocaddress" => {
                let symbol = self
                    .memory
                    .read_c_string(args.get(1).copied().unwrap_or(0), 260);
                Ok((
                    0,
                    format!("Recorded dynamic symbol lookup for {symbol}"),
                    vec![
                        format!("0x{:08x}", args.first().copied().unwrap_or(0)),
                        symbol,
                    ],
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
            "virtualalloc" => self.virtual_alloc(args),
            "virtualprotect" => self.virtual_protect(args),
            "createfilea" => {
                let path = self
                    .memory
                    .read_c_string(args.first().copied().unwrap_or(0), 1_024);
                let handle = self.allocate_handle();
                self.filesystem.push(FileEvent {
                    operation: "open".into(),
                    path: path.clone(),
                    size: None,
                    preview: None,
                });
                Ok((handle, format!("Opened virtual file {path}"), vec![path]))
            }
            "writefile" => {
                let length = args.get(2).copied().unwrap_or(0).min(65_536);
                let data = self
                    .memory
                    .read(args.get(1).copied().unwrap_or(0), length as usize)
                    .unwrap_or_default();
                let preview = printable_preview(data);
                if let Some(pointer) = args.get(3).copied().filter(|pointer| *pointer != 0) {
                    let _ = self.memory.write_u32(pointer, length);
                }
                self.filesystem.push(FileEvent {
                    operation: "write".into(),
                    path: format!("handle:0x{:x}", args.first().copied().unwrap_or(0)),
                    size: Some(length),
                    preview: Some(preview.clone()),
                });
                Ok((
                    1,
                    format!("Captured {length} bytes written to a virtual file"),
                    vec![
                        format!("handle:0x{:x}", args.first().copied().unwrap_or(0)),
                        preview,
                    ],
                ))
            }
            "deletefilea" => {
                let path = self
                    .memory
                    .read_c_string(args.first().copied().unwrap_or(0), 1_024);
                self.filesystem.push(FileEvent {
                    operation: "delete".into(),
                    path: path.clone(),
                    size: None,
                    preview: None,
                });
                Ok((1, format!("Deleted virtual file {path}"), vec![path]))
            }
            "regopenkeyexa" => {
                let key = self
                    .memory
                    .read_c_string(args.get(1).copied().unwrap_or(0), 1_024);
                let handle = self.allocate_handle();
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
            "regsetvalueexa" => {
                let value_name = self
                    .memory
                    .read_c_string(args.get(1).copied().unwrap_or(0), 512);
                let length = args.get(5).copied().unwrap_or(0).min(4_096);
                let data = self
                    .memory
                    .read(args.get(4).copied().unwrap_or(0), length as usize)
                    .unwrap_or_default();
                let preview = printable_preview(data);
                self.registry.push(RegistryEvent {
                    operation: "set".into(),
                    key: format!(
                        "handle:0x{:x}\\{value_name}",
                        args.first().copied().unwrap_or(0)
                    ),
                    value: Some(preview.clone()),
                });
                Ok((
                    0,
                    format!("Set synthetic registry value {value_name}"),
                    vec![value_name, preview],
                ))
            }
            "internetopena" => {
                let agent = self
                    .memory
                    .read_c_string(args.first().copied().unwrap_or(0), 512);
                let handle = self.allocate_handle();
                Ok((
                    handle,
                    format!("Created synthetic internet session for {agent}"),
                    vec![agent],
                ))
            }
            "internetopenurla" => {
                let url = self
                    .memory
                    .read_c_string(args.get(1).copied().unwrap_or(0), 2_048);
                self.network.push(NetworkEvent {
                    operation: "http_open".into(),
                    destination: url.clone(),
                    size: None,
                    preview: None,
                    synthetic_result: "HTTP 404 from local sink".into(),
                });
                let handle = self.allocate_handle();
                Ok((handle, format!("Captured HTTP request to {url}"), vec![url]))
            }
            "connect" => {
                let destination = self.read_sockaddr(args.get(1).copied().unwrap_or(0));
                self.network.push(NetworkEvent {
                    operation: "connect".into(),
                    destination: destination.clone(),
                    size: None,
                    preview: None,
                    synthetic_result: "connected to local sink".into(),
                });
                Ok((
                    0,
                    format!("Captured connection to {destination}"),
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
                self.network.push(NetworkEvent {
                    operation: "send".into(),
                    destination: format!("socket:0x{:x}", args.first().copied().unwrap_or(0)),
                    size: Some(length),
                    preview: Some(preview.clone()),
                    synthetic_result: "accepted by local sink".into(),
                });
                Ok((
                    length,
                    format!("Captured {length} outbound bytes"),
                    vec![preview],
                ))
            }
            "recv" => Ok((0, "Synthetic network sink returned EOF".into(), hex_args())),
            "closehandle" | "regclosekey" | "internetclosehandle" => {
                Ok((1, "Closed synthetic handle".into(), hex_args()))
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

    fn allocate_handle(&mut self) -> u32 {
        let handle = self.next_handle;
        self.next_handle = self.next_handle.saturating_add(1);
        handle
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
        if findings.is_empty() {
            findings.push(DynamicFinding { id: "no-modeled-behavior".into(), title: "No modeled high-level behavior observed".into(), severity: DynamicSeverity::Info, rationale: "Execution may have completed, hit an unsupported instruction, or avoided the modeled APIs.".into(), evidence: vec![format!("{} instructions emulated", self.instruction_count)] });
        }
        findings
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
