use crate::{
    DynamicError, RuntimeFunction, api::signature, loader::ApiImport, memory::Permissions,
    memory64::Memory64,
};
use goblin::pe;
use std::collections::BTreeMap;

pub const STACK64_BASE: u64 = 0x0000_007f_0000_0000;
pub const STACK64_SIZE: usize = 1024 * 1024;
pub const STACK64_TOP: u64 = STACK64_BASE + STACK64_SIZE as u64 - 0x100;
pub const API64_STUB_BASE: u64 = 0x0000_006f_0000_0000;
const MAX_UNWIND_FUNCTIONS: usize = 4_096;

pub(crate) struct LoadedImage64 {
    pub memory: Memory64,
    pub image_base: u64,
    pub image_size: u64,
    pub entry_point: u64,
    pub imports: BTreeMap<u64, ApiImport>,
    pub warnings: Vec<String>,
    pub tls_callbacks: Vec<u64>,
    pub unwind_functions: Vec<RuntimeFunction>,
}

pub(crate) fn load(bytes: &[u8]) -> Result<LoadedImage64, DynamicError> {
    let pe = pe::PE::parse(bytes).map_err(|error| DynamicError::InvalidPe(error.to_string()))?;
    if !pe.is_64 || pe.header.coff_header.machine != pe::header::COFF_MACHINE_X86_64 {
        return Err(DynamicError::UnsupportedTarget(
            "PE64 dynamic analysis currently supports x86-64 executables only".into(),
        ));
    }
    let optional = pe
        .header
        .optional_header
        .ok_or_else(|| DynamicError::InvalidPe("missing optional header".into()))?;
    let image_base = pe.image_base;
    let entry_point = image_base
        .checked_add(pe.entry as u64)
        .ok_or_else(|| DynamicError::InvalidPe("entry point overflow".into()))?;
    let mut memory = Memory64::default();
    let mut warnings = Vec::new();
    if optional
        .data_directories
        .get_delay_import_descriptor()
        .is_some()
    {
        warnings.push("PE64 delay-import table is present but not yet mapped".into());
    }
    let header_size = (optional.windows_fields.size_of_headers as usize)
        .max(0x200)
        .min(bytes.len().max(0x200));
    memory.map(
        image_base,
        align_page(header_size),
        Permissions::READ,
        "PE64 headers",
    )?;
    memory.write_force(image_base, &bytes[..header_size.min(bytes.len())])?;

    for section in &pe.sections {
        let size = (section.virtual_size as usize)
            .max(section.size_of_raw_data as usize)
            .max(1);
        let address = image_base
            .checked_add(section.virtual_address as u64)
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
        STACK64_BASE,
        STACK64_SIZE,
        Permissions::READ_WRITE,
        "x64 thread stack",
    )?;

    let mut imports = BTreeMap::new();
    for (index, import) in pe.imports.iter().enumerate() {
        if index >= 4_096 {
            warnings.push("import table truncated at 4096 functions".into());
            break;
        }
        let stub = API64_STUB_BASE + index as u64 * 0x100;
        let iat_address = image_base
            .checked_add(import.offset as u64)
            .ok_or_else(|| DynamicError::InvalidPe("IAT address overflow".into()))?;
        memory.write_force(iat_address, &stub.to_le_bytes())?;
        let name = import.name.to_string();
        imports.insert(
            stub,
            ApiImport {
                argument_count: signature(&name).argument_count,
                module: import.dll.to_owned(),
                name,
            },
        );
    }

    let mut tls_callbacks = Vec::new();
    if let Some(tls) = &pe.tls_data {
        tls_callbacks.extend(tls.callbacks.iter().copied().take(64));
        if tls.callbacks.len() > 64 {
            warnings.push("TLS callback list truncated at 64 entries".into());
        }
    }
    let mut unwind_functions = Vec::new();
    if let Some(exception_data) = &pe.exception_data {
        for function in exception_data.functions().take(MAX_UNWIND_FUNCTIONS) {
            match function {
                Ok(function) => unwind_functions.push(RuntimeFunction {
                    begin_address: image_base + function.begin_address as u64,
                    end_address: image_base + function.end_address as u64,
                    unwind_info_address: image_base + function.unwind_info_address as u64,
                }),
                Err(error) => warnings.push(format!("invalid x64 unwind entry: {error}")),
            }
        }
        if exception_data.functions().len() > MAX_UNWIND_FUNCTIONS {
            warnings.push("x64 unwind metadata truncated at 4096 functions".into());
        }
    }

    Ok(LoadedImage64 {
        memory,
        image_base,
        image_size: optional.windows_fields.size_of_image as u64,
        entry_point,
        imports,
        warnings,
        tls_callbacks,
        unwind_functions,
    })
}

fn align_page(size: usize) -> usize {
    size.saturating_add(0xfff) & !0xfff
}
