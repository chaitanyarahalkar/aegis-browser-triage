use crate::{DynamicError, memory::Permissions, memory64::Memory64};
use goblin::elf::{self, Elf};
use std::collections::{BTreeMap, BTreeSet};

pub const LINUX_STACK_BASE: u64 = 0x0000_007f_ef00_0000;
pub const LINUX_STACK_SIZE: usize = 1024 * 1024;
pub const LINUX_STACK_TOP: u64 = LINUX_STACK_BASE + LINUX_STACK_SIZE as u64 - 0x100;
pub const LINUX_HEAP_BASE: u64 = 0x0000_0055_8000_0000;
pub const LINUX_HEAP_SIZE: usize = 16 * 1024 * 1024;
pub const LINUX_MMAP_BASE: u64 = 0x0000_0060_0000_0000;
const PIE_BASE: u64 = 0x0000_0055_5555_4000;
const IMPORT_STUB_BASE: u64 = 0x0000_006d_0000_0000;
const PAGE_SIZE: u64 = 0x1000;

#[derive(Debug, Clone)]
pub(crate) struct LinuxImport {
    pub name: String,
    pub module: String,
}

pub(crate) struct LoadedElf64 {
    pub memory: Memory64,
    pub image_base: u64,
    pub image_size: u64,
    pub entry_point: u64,
    pub initial_rsp: u64,
    pub argv: u64,
    pub envp: u64,
    pub imports: BTreeMap<u64, LinuxImport>,
    pub warnings: Vec<String>,
}

#[derive(Clone)]
struct Page {
    bytes: Vec<u8>,
    permissions: Permissions,
}

pub(crate) fn load(name: &str, bytes: &[u8]) -> Result<LoadedElf64, DynamicError> {
    let binary = Elf::parse(bytes)
        .map_err(|error| DynamicError::UnsupportedTarget(format!("invalid ELF: {error}")))?;
    if !binary.is_64
        || !binary.little_endian
        || binary.header.e_machine != elf::header::EM_X86_64
        || !matches!(
            binary.header.e_type,
            elf::header::ET_EXEC | elf::header::ET_DYN
        )
    {
        return Err(DynamicError::UnsupportedTarget(
            "Linux dynamic analysis currently supports little-endian ELF64 x86-64 ET_EXEC and PIE executables only".into(),
        ));
    }

    let image_base = if binary.header.e_type == elf::header::ET_DYN {
        PIE_BASE
    } else {
        0
    };
    let mut pages = BTreeMap::<u64, Page>::new();
    let mut image_start = u64::MAX;
    let mut image_end = 0u64;
    for (index, segment) in binary.program_headers.iter().enumerate() {
        if segment.p_type != elf::program_header::PT_LOAD || segment.p_memsz == 0 {
            continue;
        }
        let start = image_base
            .checked_add(segment.p_vaddr)
            .ok_or(DynamicError::MemoryLimit)?;
        let end = start
            .checked_add(segment.p_memsz)
            .ok_or(DynamicError::MemoryLimit)?;
        image_start = image_start.min(start);
        image_end = image_end.max(end);
        let first_page = start & !(PAGE_SIZE - 1);
        let last_page = align_page_u64(end);
        let permissions = Permissions {
            read: segment.p_flags & elf::program_header::PF_R != 0,
            write: segment.p_flags & elf::program_header::PF_W != 0,
            execute: segment.p_flags & elf::program_header::PF_X != 0,
        };
        for address in (first_page..last_page).step_by(PAGE_SIZE as usize) {
            let page = pages.entry(address).or_insert_with(|| Page {
                bytes: vec![0; PAGE_SIZE as usize],
                permissions,
            });
            page.permissions.read |= permissions.read;
            page.permissions.write |= permissions.write;
            page.permissions.execute |= permissions.execute;
        }

        let file_start = segment.p_offset as usize;
        let file_size = segment.p_filesz.min(segment.p_memsz) as usize;
        let file_end = file_start
            .checked_add(file_size)
            .ok_or_else(|| DynamicError::UnsupportedTarget("ELF segment range overflow".into()))?;
        let source = bytes.get(file_start..file_end).ok_or_else(|| {
            DynamicError::UnsupportedTarget(format!("ELF PT_LOAD {index} exceeds the input"))
        })?;
        let mut copied = 0usize;
        while copied < source.len() {
            let address = start + copied as u64;
            let page_address = address & !(PAGE_SIZE - 1);
            let page_offset = (address - page_address) as usize;
            let count = (PAGE_SIZE as usize - page_offset).min(source.len() - copied);
            pages.get_mut(&page_address).unwrap().bytes[page_offset..page_offset + count]
                .copy_from_slice(&source[copied..copied + count]);
            copied += count;
        }
    }
    if pages.is_empty() {
        return Err(DynamicError::UnsupportedTarget(
            "ELF has no loadable segments".into(),
        ));
    }

    let mut memory = Memory64::default();
    for (address, page) in &pages {
        memory.map(
            *address,
            PAGE_SIZE as usize,
            page.permissions,
            "ELF64 image page",
        )?;
        memory.write_force(*address, &page.bytes)?;
    }
    memory.map(
        LINUX_STACK_BASE,
        LINUX_STACK_SIZE,
        Permissions::READ_WRITE,
        "Linux x86-64 initial stack",
    )?;
    memory.map(
        LINUX_HEAP_BASE,
        LINUX_HEAP_SIZE,
        Permissions::READ_WRITE,
        "Linux synthetic brk heap",
    )?;

    let entry_point = image_base
        .checked_add(binary.entry)
        .ok_or(DynamicError::MemoryLimit)?;
    if memory.fetch(entry_point, 1).is_err() {
        return Err(DynamicError::UnsupportedTarget(format!(
            "ELF entry point 0x{entry_point:x} is not executable"
        )));
    }

    let phdr_address = binary
        .program_headers
        .iter()
        .find(|segment| {
            segment.p_type == elf::program_header::PT_LOAD
                && binary.header.e_phoff >= segment.p_offset
                && binary.header.e_phoff < segment.p_offset.saturating_add(segment.p_filesz)
        })
        .map(|segment| {
            image_base + segment.p_vaddr + binary.header.e_phoff.saturating_sub(segment.p_offset)
        })
        .unwrap_or(0);
    let (initial_rsp, argv, envp) = initialize_stack(
        &mut memory,
        name,
        entry_point,
        phdr_address,
        binary.header.e_phentsize,
        binary.header.e_phnum,
    )?;

    let mut warnings = Vec::new();
    if let Some(interpreter) = binary.interpreter {
        warnings.push(format!(
            "ELF interpreter {interpreter} was replaced by bounded synthetic relocation and libc stubs"
        ));
    }
    let mut imports = BTreeMap::new();
    let mut import_addresses = BTreeMap::<String, u64>::new();
    let mut unsupported_relocations = BTreeSet::new();
    for relocation in binary
        .dynrelas
        .iter()
        .chain(binary.dynrels.iter())
        .chain(binary.pltrelocs.iter())
    {
        let target = image_base
            .checked_add(relocation.r_offset)
            .ok_or(DynamicError::MemoryLimit)?;
        match relocation.r_type {
            elf::reloc::R_X86_64_RELATIVE => {
                let addend = relocation
                    .r_addend
                    .unwrap_or_else(|| memory.read_u64(target).unwrap_or_default() as i64);
                let value = image_base.wrapping_add_signed(addend);
                memory.write_force(target, &value.to_le_bytes())?;
            }
            elf::reloc::R_X86_64_GLOB_DAT | elf::reloc::R_X86_64_JUMP_SLOT => {
                let symbol = binary.dynsyms.get(relocation.r_sym).ok_or_else(|| {
                    DynamicError::UnsupportedTarget("ELF relocation has an invalid symbol".into())
                })?;
                let symbol_name = binary
                    .dynstrtab
                    .get_at(symbol.st_name)
                    .unwrap_or("unknown")
                    .to_owned();
                let value = if symbol.st_value != 0 {
                    image_base.saturating_add(symbol.st_value)
                } else {
                    let next = IMPORT_STUB_BASE + import_addresses.len().min(4095) as u64 * 0x100;
                    *import_addresses.entry(symbol_name.clone()).or_insert(next)
                };
                memory.write_force(target, &value.to_le_bytes())?;
                if value >= IMPORT_STUB_BASE {
                    imports.entry(value).or_insert_with(|| LinuxImport {
                        name: symbol_name,
                        module: "linux-libc".into(),
                    });
                }
            }
            elf::reloc::R_X86_64_64 if relocation.r_sym != 0 => {
                if let Some(symbol) = binary.dynsyms.get(relocation.r_sym) {
                    let value = image_base
                        .saturating_add(symbol.st_value)
                        .wrapping_add_signed(relocation.r_addend.unwrap_or_default());
                    memory.write_force(target, &value.to_le_bytes())?;
                }
            }
            other => {
                unsupported_relocations.insert(other);
            }
        }
    }
    if !unsupported_relocations.is_empty() {
        warnings.push(format!(
            "ELF relocation types not modeled: {}",
            unsupported_relocations
                .into_iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if imports.len() >= 4_096 {
        warnings.push("ELF import stubs truncated at 4096 symbols".into());
    }

    Ok(LoadedElf64 {
        memory,
        image_base: image_start,
        image_size: image_end.saturating_sub(image_start),
        entry_point,
        initial_rsp,
        argv,
        envp,
        imports,
        warnings,
    })
}

fn initialize_stack(
    memory: &mut Memory64,
    name: &str,
    entry: u64,
    phdr: u64,
    phent: u16,
    phnum: u16,
) -> Result<(u64, u64, u64), DynamicError> {
    let clean_name: String = name
        .chars()
        .filter(|character| !character.is_control())
        .take(128)
        .collect();
    let executable = if clean_name.is_empty() {
        "/sample".to_owned()
    } else {
        format!("/sample/{clean_name}")
    };
    let mut cursor = LINUX_STACK_TOP;
    let mut put = |value: &[u8]| -> Result<u64, DynamicError> {
        cursor = cursor.saturating_sub(value.len() as u64);
        memory.write_force(cursor, value)?;
        Ok(cursor)
    };
    let exec_pointer = put(format!("{executable}\0").as_bytes())?;
    let path_pointer = put(b"PATH=/usr/bin:/bin\0")?;
    let home_pointer = put(b"HOME=/home/analyst\0")?;
    let user_pointer = put(b"USER=analyst\0")?;
    let random_pointer = put(b"NOPE-LINUX-AUXV")?;
    cursor &= !0xf;
    let env = [path_pointer, home_pointer, user_pointer];
    let mut words = vec![1, exec_pointer, 0];
    let envp_index = words.len();
    words.extend(env);
    words.push(0);
    words.extend([
        3,
        phdr,
        4,
        phent as u64,
        5,
        phnum as u64,
        6,
        PAGE_SIZE,
        9,
        entry,
        11,
        1000,
        12,
        1000,
        13,
        1000,
        14,
        1000,
        25,
        random_pointer,
        31,
        exec_pointer,
        0,
        0,
    ]);
    let bytes = words.len() * 8;
    let rsp = (cursor.saturating_sub(bytes as u64)) & !0xf;
    for (index, word) in words.iter().enumerate() {
        memory.write_force(rsp + index as u64 * 8, &word.to_le_bytes())?;
    }
    Ok((rsp, rsp + 8, rsp + envp_index as u64 * 8))
}

fn align_page_u64(value: u64) -> u64 {
    value.saturating_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_segments_bss_and_a_linux_process_entry_stack() {
        let bytes = crate::fixture::safe_dynamic_elf64();
        let loaded = load("nope-linux", &bytes).unwrap();
        assert_eq!(loaded.image_base, 0x0040_0000);
        assert_eq!(loaded.entry_point, 0x0040_0200);
        assert_eq!(loaded.initial_rsp % 16, 0);
        assert_eq!(loaded.memory.read_u64(loaded.initial_rsp).unwrap(), 1);

        let argv0 = loaded.memory.read_u64(loaded.argv).unwrap();
        assert_eq!(
            loaded.memory.read_c_string(argv0, 256),
            "/sample/nope-linux"
        );
        let env0 = loaded.memory.read_u64(loaded.envp).unwrap();
        assert_eq!(loaded.memory.read_c_string(env0, 256), "PATH=/usr/bin:/bin");
        assert_eq!(loaded.memory.read(0x0040_2000, 64).unwrap(), &[0; 64]);

        let mut auxv = loaded.envp + 4 * 8;
        let mut keys = BTreeSet::new();
        loop {
            let key = loaded.memory.read_u64(auxv).unwrap();
            let value = loaded.memory.read_u64(auxv + 8).unwrap();
            auxv += 16;
            if key == 0 {
                assert_eq!(value, 0);
                break;
            }
            keys.insert(key);
        }
        for key in [3, 4, 5, 6, 9, 25, 31] {
            assert!(keys.contains(&key), "missing auxv key {key}");
        }
    }
}
