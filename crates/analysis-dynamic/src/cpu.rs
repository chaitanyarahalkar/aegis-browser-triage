use crate::{DynamicError, memory::Memory};
use iced_x86::{Instruction, OpKind, Register};

#[derive(Debug, Default, Clone)]
pub struct Cpu {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub esi: u32,
    pub edi: u32,
    pub ebp: u32,
    pub esp: u32,
    pub eip: u32,
    pub zf: bool,
    pub sf: bool,
    pub cf: bool,
    pub of: bool,
    pub direction: bool,
}

impl Cpu {
    pub fn read_register(&self, register: Register) -> Result<u32, DynamicError> {
        let value = match register {
            Register::EAX => self.eax,
            Register::EBX => self.ebx,
            Register::ECX => self.ecx,
            Register::EDX => self.edx,
            Register::ESI => self.esi,
            Register::EDI => self.edi,
            Register::EBP => self.ebp,
            Register::ESP => self.esp,
            Register::EIP => self.eip,
            Register::AX => self.eax & 0xffff,
            Register::BX => self.ebx & 0xffff,
            Register::CX => self.ecx & 0xffff,
            Register::DX => self.edx & 0xffff,
            Register::SI => self.esi & 0xffff,
            Register::DI => self.edi & 0xffff,
            Register::BP => self.ebp & 0xffff,
            Register::SP => self.esp & 0xffff,
            Register::AL => self.eax & 0xff,
            Register::AH => (self.eax >> 8) & 0xff,
            Register::BL => self.ebx & 0xff,
            Register::BH => (self.ebx >> 8) & 0xff,
            Register::CL => self.ecx & 0xff,
            Register::CH => (self.ecx >> 8) & 0xff,
            Register::DL => self.edx & 0xff,
            Register::DH => (self.edx >> 8) & 0xff,
            Register::None => 0,
            _ => return Err(DynamicError::UnsupportedRegister(format!("{register:?}"))),
        };
        Ok(value)
    }

    pub fn write_register(&mut self, register: Register, value: u32) -> Result<(), DynamicError> {
        match register {
            Register::EAX => self.eax = value,
            Register::EBX => self.ebx = value,
            Register::ECX => self.ecx = value,
            Register::EDX => self.edx = value,
            Register::ESI => self.esi = value,
            Register::EDI => self.edi = value,
            Register::EBP => self.ebp = value,
            Register::ESP => self.esp = value,
            Register::EIP => self.eip = value,
            Register::AX => self.eax = (self.eax & !0xffff) | (value & 0xffff),
            Register::BX => self.ebx = (self.ebx & !0xffff) | (value & 0xffff),
            Register::CX => self.ecx = (self.ecx & !0xffff) | (value & 0xffff),
            Register::DX => self.edx = (self.edx & !0xffff) | (value & 0xffff),
            Register::SI => self.esi = (self.esi & !0xffff) | (value & 0xffff),
            Register::DI => self.edi = (self.edi & !0xffff) | (value & 0xffff),
            Register::BP => self.ebp = (self.ebp & !0xffff) | (value & 0xffff),
            Register::SP => self.esp = (self.esp & !0xffff) | (value & 0xffff),
            Register::AL => self.eax = (self.eax & !0xff) | (value & 0xff),
            Register::AH => self.eax = (self.eax & !0xff00) | ((value & 0xff) << 8),
            Register::BL => self.ebx = (self.ebx & !0xff) | (value & 0xff),
            Register::BH => self.ebx = (self.ebx & !0xff00) | ((value & 0xff) << 8),
            Register::CL => self.ecx = (self.ecx & !0xff) | (value & 0xff),
            Register::CH => self.ecx = (self.ecx & !0xff00) | ((value & 0xff) << 8),
            Register::DL => self.edx = (self.edx & !0xff) | (value & 0xff),
            Register::DH => self.edx = (self.edx & !0xff00) | ((value & 0xff) << 8),
            _ => return Err(DynamicError::UnsupportedRegister(format!("{register:?}"))),
        }
        Ok(())
    }

    pub fn effective_address(&self, instruction: &Instruction) -> Result<u32, DynamicError> {
        let base = self.read_register(instruction.memory_base())?;
        let index = self.read_register(instruction.memory_index())?;
        Ok(base
            .wrapping_add(index.wrapping_mul(instruction.memory_index_scale()))
            .wrapping_add(instruction.memory_displacement32()))
    }

    pub fn read_operand(
        &self,
        memory: &Memory,
        instruction: &Instruction,
        operand: u32,
    ) -> Result<(u32, u32), DynamicError> {
        let kind = instruction.op_kind(operand);
        let value = match kind {
            OpKind::Register => {
                let register = instruction.op_register(operand);
                (self.read_register(register)?, register_size(register))
            }
            OpKind::Immediate8 => (instruction.immediate8() as u32, 8),
            OpKind::Immediate8to16 => (instruction.immediate8to16() as i32 as u32, 16),
            OpKind::Immediate8to32 => (instruction.immediate8to32() as u32, 32),
            OpKind::Immediate16 => (instruction.immediate16() as u32, 16),
            OpKind::Immediate32 => (instruction.immediate32(), 32),
            OpKind::NearBranch16 | OpKind::NearBranch32 => {
                (instruction.near_branch_target() as u32, 32)
            }
            OpKind::Memory => {
                let address = self.effective_address(instruction)?;
                let size = (instruction.memory_size().size() * 8) as u32;
                let value = match size {
                    8 => memory.read_u8(address)? as u32,
                    16 => memory.read_u16(address)? as u32,
                    32 => memory.read_u32(address)?,
                    _ => {
                        return Err(DynamicError::UnsupportedOperand(format!(
                            "{size}-bit memory"
                        )));
                    }
                };
                (value, size)
            }
            _ => return Err(DynamicError::UnsupportedOperand(format!("{kind:?}"))),
        };
        Ok(value)
    }

    pub fn write_operand(
        &mut self,
        memory: &mut Memory,
        instruction: &Instruction,
        operand: u32,
        value: u32,
    ) -> Result<u32, DynamicError> {
        match instruction.op_kind(operand) {
            OpKind::Register => {
                let register = instruction.op_register(operand);
                let size = register_size(register);
                self.write_register(register, mask(value, size))?;
                Ok(size)
            }
            OpKind::Memory => {
                let address = self.effective_address(instruction)?;
                let size = (instruction.memory_size().size() * 8) as u32;
                match size {
                    8 => memory.write_u8(address, value as u8)?,
                    16 => memory.write_u16(address, value as u16)?,
                    32 => memory.write_u32(address, value)?,
                    _ => {
                        return Err(DynamicError::UnsupportedOperand(format!(
                            "{size}-bit memory"
                        )));
                    }
                }
                Ok(size)
            }
            kind => Err(DynamicError::UnsupportedOperand(format!("write {kind:?}"))),
        }
    }

    pub fn push(&mut self, memory: &mut Memory, value: u32) -> Result<(), DynamicError> {
        self.esp = self.esp.wrapping_sub(4);
        memory.write_u32(self.esp, value)
    }

    pub fn pop(&mut self, memory: &Memory) -> Result<u32, DynamicError> {
        let value = memory.read_u32(self.esp)?;
        self.esp = self.esp.wrapping_add(4);
        Ok(value)
    }

    pub fn set_logic_flags(&mut self, value: u32, size: u32) {
        let value = mask(value, size);
        self.zf = value == 0;
        self.sf = value & sign_bit(size) != 0;
        self.cf = false;
        self.of = false;
    }

    pub fn set_sub_flags(&mut self, left: u32, right: u32, result: u32, size: u32) {
        let mask_value = bit_mask(size);
        let left = left & mask_value;
        let right = right & mask_value;
        let result = result & mask_value;
        self.zf = result == 0;
        self.sf = result & sign_bit(size) != 0;
        self.cf = left < right;
        self.of = ((left ^ right) & (left ^ result) & sign_bit(size)) != 0;
    }

    pub fn set_add_flags(&mut self, left: u32, right: u32, result: u32, size: u32) {
        let mask_value = bit_mask(size);
        let left = left & mask_value;
        let right = right & mask_value;
        let result = result & mask_value;
        self.zf = result == 0;
        self.sf = result & sign_bit(size) != 0;
        self.cf = (left as u64 + right as u64) > mask_value as u64;
        self.of = (!(left ^ right) & (left ^ result) & sign_bit(size)) != 0;
    }
}

pub fn register_size(register: Register) -> u32 {
    match register {
        Register::AL
        | Register::AH
        | Register::BL
        | Register::BH
        | Register::CL
        | Register::CH
        | Register::DL
        | Register::DH => 8,
        Register::AX
        | Register::BX
        | Register::CX
        | Register::DX
        | Register::SI
        | Register::DI
        | Register::BP
        | Register::SP => 16,
        _ => 32,
    }
}

pub fn bit_mask(size: u32) -> u32 {
    match size {
        8 => 0xff,
        16 => 0xffff,
        _ => u32::MAX,
    }
}

pub fn mask(value: u32, size: u32) -> u32 {
    value & bit_mask(size)
}

fn sign_bit(size: u32) -> u32 {
    match size {
        8 => 0x80,
        16 => 0x8000,
        _ => 0x8000_0000,
    }
}
