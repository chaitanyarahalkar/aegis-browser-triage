use crate::{
    DynamicError,
    memory::{Memory, Permissions},
};
use goblin::pe;
use std::collections::BTreeMap;

pub const STACK_BASE: u32 = 0x0fe0_0000;
pub const STACK_SIZE: usize = 1024 * 1024;
pub const STACK_TOP: u32 = STACK_BASE + STACK_SIZE as u32 - 0x100;
pub const API_STUB_BASE: u32 = 0x7000_0000;

#[derive(Debug, Clone)]
pub struct ApiImport {
    pub module: String,
    pub name: String,
    pub argument_count: usize,
}

#[derive(Debug)]
pub struct LoadedImage {
    pub memory: Memory,
    pub image_base: u32,
    pub entry_point: u32,
    pub imports: BTreeMap<u32, ApiImport>,
    pub warnings: Vec<String>,
}

pub fn load(bytes: &[u8]) -> Result<LoadedImage, DynamicError> {
    let pe = pe::PE::parse(bytes).map_err(|error| DynamicError::InvalidPe(error.to_string()))?;
    if pe.is_64 || pe.header.coff_header.machine != pe::header::COFF_MACHINE_X86 {
        return Err(DynamicError::UnsupportedTarget(
            "dynamic analysis currently supports PE32/x86 executables only".into(),
        ));
    }
    let optional = pe
        .header
        .optional_header
        .ok_or_else(|| DynamicError::InvalidPe("missing optional header".into()))?;
    let image_base = u32::try_from(pe.image_base)
        .map_err(|_| DynamicError::InvalidPe("image base does not fit PE32".into()))?;
    let entry_point = image_base
        .checked_add(pe.entry)
        .ok_or_else(|| DynamicError::InvalidPe("entry point overflow".into()))?;
    let mut memory = Memory::default();
    let mut warnings = Vec::new();

    let header_size = (optional.windows_fields.size_of_headers as usize)
        .max(0x200)
        .min(bytes.len().max(0x200));
    memory.map(
        image_base,
        align_page(header_size),
        Permissions::READ,
        "PE headers",
    )?;
    memory.write_force(image_base, &bytes[..header_size.min(bytes.len())])?;

    for section in &pe.sections {
        let size = (section.virtual_size as usize)
            .max(section.size_of_raw_data as usize)
            .max(1);
        let address = image_base
            .checked_add(section.virtual_address)
            .ok_or_else(|| DynamicError::InvalidPe("section address overflow".into()))?;
        let permissions = Permissions {
            read: section.characteristics & pe::section_table::IMAGE_SCN_MEM_READ != 0,
            write: section.characteristics & pe::section_table::IMAGE_SCN_MEM_WRITE != 0,
            execute: section.characteristics & pe::section_table::IMAGE_SCN_MEM_EXECUTE != 0,
        };
        let name = section.name().unwrap_or("<invalid>").to_owned();
        memory.map(address, align_page(size), permissions, name.clone())?;
        let raw_start = section.pointer_to_raw_data as usize;
        let raw_size = section.size_of_raw_data as usize;
        if let Some(raw) = raw_start
            .checked_add(raw_size)
            .and_then(|end| bytes.get(raw_start..end))
        {
            memory.write_force(address, raw)?;
        } else if raw_size != 0 {
            warnings.push(format!("section {name} has out-of-range raw data"));
        }
    }

    memory.map(
        STACK_BASE,
        STACK_SIZE,
        Permissions::READ_WRITE,
        "thread stack",
    )?;

    let mut imports = BTreeMap::new();
    for (index, import) in pe.imports.iter().enumerate() {
        if index >= 4_096 {
            warnings.push("import table truncated at 4096 functions".into());
            break;
        }
        let stub = API_STUB_BASE + index as u32 * 0x100;
        let iat_address = image_base
            .checked_add(import.offset as u32)
            .ok_or_else(|| DynamicError::InvalidPe("IAT address overflow".into()))?;
        memory.write_force(iat_address, &stub.to_le_bytes())?;
        let name = import.name.to_string();
        imports.insert(
            stub,
            ApiImport {
                argument_count: argument_count(&name),
                module: import.dll.to_owned(),
                name,
            },
        );
    }

    Ok(LoadedImage {
        memory,
        image_base,
        entry_point,
        imports,
        warnings,
    })
}

fn align_page(size: usize) -> usize {
    size.saturating_add(0xfff) & !0xfff
}

fn argument_count(name: &str) -> usize {
    match name.to_ascii_lowercase().as_str() {
        "gettickcount" | "getcurrentprocessid" | "getcurrentthreadid" => 0,
        "exitprocess" | "sleep" | "getmodulehandlea" | "loadlibrarya" | "deletefilea"
        | "closehandle" => 1,
        "winexec" | "getprocaddress" | "virtualfree" => 2,
        "virtualprotect" | "connect" => 3,
        "virtualalloc" | "send" | "recv" => 4,
        "regopenkeyexa" | "internetopena" | "writefile" => 5,
        "regsetvalueexa" | "internetopenurla" => 6,
        "createfilea" => 7,
        _ => 0,
    }
}
