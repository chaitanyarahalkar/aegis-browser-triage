use crate::{DynamicError, memory64::Memory64};
use iced_x86::{Instruction, OpKind, Register};

#[derive(Debug, Clone, Default)]
pub(crate) struct Cpu64 {
    pub gpr: [u64; 16],
    pub rip: u64,
    pub gs_base: u64,
    pub zf: bool,
    pub sf: bool,
    pub cf: bool,
    pub of: bool,
    pub pf: bool,
}

impl Cpu64 {
    pub fn rsp(&self) -> u64 {
        self.gpr[4]
    }

    pub fn set_rsp(&mut self, value: u64) {
        self.gpr[4] = value;
    }

    pub fn read_register(&self, register: Register) -> Result<u64, DynamicError> {
        if register == Register::RIP || register == Register::EIP {
            return Ok(self.rip);
        }
        let full = register.full_register();
        let index = gpr_index(full)
            .ok_or_else(|| DynamicError::UnsupportedRegister(format!("x64 {register:?}")))?;
        let value = self.gpr[index];
        let size = register.size() * 8;
        let value = if is_high_byte(register) {
            (value >> 8) & 0xff
        } else {
            value & mask(size)
        };
        Ok(value)
    }

    pub fn write_register(&mut self, register: Register, value: u64) -> Result<(), DynamicError> {
        let full = register.full_register();
        let index = gpr_index(full)
            .ok_or_else(|| DynamicError::UnsupportedRegister(format!("x64 {register:?}")))?;
        let size = register.size() * 8;
        self.gpr[index] = if is_high_byte(register) {
            (self.gpr[index] & !0xff00) | ((value & 0xff) << 8)
        } else {
            match size {
                64 => value,
                32 => value & 0xffff_ffff,
                16 => (self.gpr[index] & !0xffff) | (value & 0xffff),
                8 => (self.gpr[index] & !0xff) | (value & 0xff),
                _ => {
                    return Err(DynamicError::UnsupportedRegister(format!(
                        "x64 {register:?}"
                    )));
                }
            }
        };
        Ok(())
    }

    pub fn effective_address(&self, instruction: &Instruction) -> Result<u64, DynamicError> {
        if instruction.is_ip_rel_memory_operand() {
            return Ok(instruction.ip_rel_memory_address());
        }
        let base = match instruction.memory_base() {
            Register::None => 0,
            register => self.read_register(register)?,
        };
        let index = match instruction.memory_index() {
            Register::None => 0,
            register => self.read_register(register)?,
        };
        let segment = if instruction.memory_segment() == Register::GS {
            self.gs_base
        } else {
            0
        };
        Ok(segment
            .wrapping_add(base)
            .wrapping_add(index.wrapping_mul(instruction.memory_index_scale() as u64))
            .wrapping_add(instruction.memory_displacement64()))
    }

    pub fn read_operand(
        &self,
        memory: &Memory64,
        instruction: &Instruction,
        operand: u32,
    ) -> Result<(u64, usize), DynamicError> {
        let kind = instruction.op_kind(operand);
        match kind {
            OpKind::Register => {
                let register = instruction.op_register(operand);
                Ok((self.read_register(register)?, register.size() * 8))
            }
            OpKind::Immediate8 => Ok((instruction.immediate8() as u64, 8)),
            OpKind::Immediate8to16 => Ok((instruction.immediate8to16() as i64 as u64, 16)),
            OpKind::Immediate8to32 => Ok((instruction.immediate8to32() as i64 as u64, 32)),
            OpKind::Immediate8to64 => Ok((instruction.immediate8to64() as u64, 64)),
            OpKind::Immediate16 => Ok((instruction.immediate16() as u64, 16)),
            OpKind::Immediate32 => Ok((instruction.immediate32() as u64, 32)),
            OpKind::Immediate32to64 => Ok((instruction.immediate32to64() as u64, 64)),
            OpKind::Immediate64 => Ok((instruction.immediate64(), 64)),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                Ok((instruction.near_branch_target(), 64))
            }
            OpKind::Memory => {
                let address = self.effective_address(instruction)?;
                let size = instruction.memory_size().size() * 8;
                let bytes = memory.read(address, size / 8)?;
                let mut value = [0u8; 8];
                value[..bytes.len()].copy_from_slice(bytes);
                Ok((u64::from_le_bytes(value), size))
            }
            _ => Err(DynamicError::UnsupportedOperand(format!("x64 {kind:?}"))),
        }
    }

    pub fn write_operand(
        &mut self,
        memory: &mut Memory64,
        instruction: &Instruction,
        operand: u32,
        value: u64,
    ) -> Result<usize, DynamicError> {
        match instruction.op_kind(operand) {
            OpKind::Register => {
                let register = instruction.op_register(operand);
                let size = register.size() * 8;
                self.write_register(register, value)?;
                Ok(size)
            }
            OpKind::Memory => {
                let address = self.effective_address(instruction)?;
                let size = instruction.memory_size().size() * 8;
                memory.write(address, &value.to_le_bytes()[..size / 8])?;
                Ok(size)
            }
            kind => Err(DynamicError::UnsupportedOperand(format!(
                "x64 write {kind:?}"
            ))),
        }
    }

    pub fn push(&mut self, memory: &mut Memory64, value: u64) -> Result<(), DynamicError> {
        self.set_rsp(self.rsp().wrapping_sub(8));
        memory.write_u64(self.rsp(), value)
    }

    pub fn pop(&mut self, memory: &Memory64) -> Result<u64, DynamicError> {
        let value = memory.read_u64(self.rsp())?;
        self.set_rsp(self.rsp().wrapping_add(8));
        Ok(value)
    }

    pub fn set_logic_flags(&mut self, value: u64, size: usize) {
        let value = value & mask(size);
        self.zf = value == 0;
        self.sf = value & (1u64 << (size - 1)) != 0;
        self.pf = (value as u8).count_ones().is_multiple_of(2);
        self.cf = false;
        self.of = false;
    }

    pub fn set_add_flags(&mut self, left: u64, right: u64, result: u64, size: usize) {
        let mask = mask(size);
        let sign = 1u64 << (size - 1);
        let left = left & mask;
        let right = right & mask;
        let result = result & mask;
        self.set_logic_flags(result, size);
        self.cf = (left as u128 + right as u128) > mask as u128;
        self.of = (!(left ^ right) & (left ^ result) & sign) != 0;
    }

    pub fn set_sub_flags(&mut self, left: u64, right: u64, result: u64, size: usize) {
        let mask = mask(size);
        let sign = 1u64 << (size - 1);
        let left = left & mask;
        let right = right & mask;
        let result = result & mask;
        self.set_logic_flags(result, size);
        self.cf = left < right;
        self.of = ((left ^ right) & (left ^ result) & sign) != 0;
    }

    pub fn flags_value(&self) -> u64 {
        0x2 | u64::from(self.cf)
            | (u64::from(self.pf) << 2)
            | (u64::from(self.zf) << 6)
            | (u64::from(self.sf) << 7)
            | (u64::from(self.of) << 11)
    }
}

fn gpr_index(register: Register) -> Option<usize> {
    Some(match register {
        Register::RAX => 0,
        Register::RCX => 1,
        Register::RDX => 2,
        Register::RBX => 3,
        Register::RSP => 4,
        Register::RBP => 5,
        Register::RSI => 6,
        Register::RDI => 7,
        Register::R8 => 8,
        Register::R9 => 9,
        Register::R10 => 10,
        Register::R11 => 11,
        Register::R12 => 12,
        Register::R13 => 13,
        Register::R14 => 14,
        Register::R15 => 15,
        _ => return None,
    })
}

fn is_high_byte(register: Register) -> bool {
    matches!(
        register,
        Register::AH | Register::BH | Register::CH | Register::DH
    )
}

fn mask(size: usize) -> u64 {
    if size >= 64 {
        u64::MAX
    } else {
        (1u64 << size) - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions};

    #[test]
    fn applies_x64_partial_register_rules() {
        let mut cpu = Cpu64::default();
        cpu.write_register(Register::RAX, u64::MAX).unwrap();
        cpu.write_register(Register::EAX, 0x1234_5678).unwrap();
        assert_eq!(cpu.read_register(Register::RAX).unwrap(), 0x1234_5678);
        cpu.write_register(Register::AH, 0xab).unwrap();
        assert_eq!(cpu.read_register(Register::AX).unwrap(), 0xab78);
        cpu.write_register(Register::AL, 0xcd).unwrap();
        assert_eq!(cpu.read_register(Register::AX).unwrap(), 0xabcd);
    }

    #[test]
    fn resolves_rip_relative_addresses_above_four_gibibytes() {
        let bytes = [0x48, 0x8d, 0x0d, 0x10, 0x00, 0x00, 0x00];
        let mut decoder = Decoder::with_ip(64, &bytes, 0x0000_0001_4000_1000, DecoderOptions::NONE);
        let instruction = decoder.decode();
        assert_eq!(
            Cpu64::default().effective_address(&instruction).unwrap(),
            0x0000_0001_4000_1017
        );
    }
}
