use crate::{
    AnalysisError, AnalysisWarning, BinaryFormat, Confidence, Finding, FormatReport,
    MAX_COLLECTION_ITEMS, MAX_SECTIONS, MachSlice, SectionRecord, Severity, SymbolRecord,
};
use goblin::{Object, elf, mach, pe};
use wasmparser::{Encoding, Parser, Payload, TypeRef, Validator};

pub(crate) struct ParsedFormat {
    pub binary_format: BinaryFormat,
    pub architecture: Option<String>,
    pub format: FormatReport,
    pub sections: Vec<SectionRecord>,
    pub imports: Vec<SymbolRecord>,
    pub exports: Vec<SymbolRecord>,
    pub findings: Vec<Finding>,
    pub warnings: Vec<AnalysisWarning>,
    pub collections_truncated: bool,
}

pub(crate) fn parse(bytes: &[u8]) -> Result<ParsedFormat, AnalysisError> {
    if bytes.starts_with(b"\0asm") {
        return parse_wasm(bytes);
    }

    let appears_known =
        bytes.starts_with(b"MZ") || bytes.starts_with(b"\x7fELF") || is_mach_magic(bytes);

    match Object::parse(bytes) {
        Ok(Object::PE(binary)) => parse_pe(bytes, binary),
        Ok(Object::Elf(binary)) => parse_elf(bytes, binary),
        Ok(Object::Mach(binary)) => parse_mach(bytes, binary),
        Ok(_) | Err(_) if !appears_known => Ok(unknown(bytes)),
        Err(error) => Err(AnalysisError::Parse {
            format: format_hint(bytes),
            message: error.to_string(),
        }),
        Ok(_) => Ok(unknown(bytes)),
    }
}

fn parse_pe(bytes: &[u8], binary: pe::PE<'_>) -> Result<ParsedFormat, AnalysisError> {
    let machine = pe::header::machine_to_str(binary.header.coff_header.machine).to_owned();
    let bitness = if binary.is_64 { 64 } else { 32 };
    let mut sections = Vec::new();
    let mut findings = Vec::new();
    let mut warnings = Vec::new();
    let mut truncated = binary.sections.len() > MAX_SECTIONS;

    for section in binary.sections.iter().take(MAX_SECTIONS) {
        let offset = section.pointer_to_raw_data as usize;
        let declared = section.size_of_raw_data as usize;
        let data = bounded_slice(bytes, offset, declared);
        if data.len() != declared && declared > 0 {
            warnings.push(AnalysisWarning {
                code: "section-out-of-range".into(),
                message: format!(
                    "PE section {} extends beyond the sample",
                    section.name().unwrap_or("<invalid>")
                ),
            });
        }
        sections.push(SectionRecord {
            name: section.name().unwrap_or("<invalid>").to_owned(),
            offset: offset as u64,
            virtual_address: Some(section.virtual_address as u64),
            size: declared as u64,
            entropy: entropy(data),
            permissions: permissions(
                section.characteristics & pe::section_table::IMAGE_SCN_MEM_READ != 0,
                section.characteristics & pe::section_table::IMAGE_SCN_MEM_WRITE != 0,
                section.characteristics & pe::section_table::IMAGE_SCN_MEM_EXECUTE != 0,
            ),
        });
    }

    let imports = binary
        .imports
        .iter()
        .take(MAX_COLLECTION_ITEMS)
        .map(|item| SymbolRecord {
            name: item.name.to_string(),
            module: Some(item.dll.to_owned()),
            address: Some(item.rva as u64),
            kind: "function".into(),
        })
        .collect();
    let exports = binary
        .exports
        .iter()
        .take(MAX_COLLECTION_ITEMS)
        .map(|item| SymbolRecord {
            name: item.name.unwrap_or("<ordinal>").to_owned(),
            module: binary.name.map(str::to_owned),
            address: Some(item.rva as u64),
            kind: "function".into(),
        })
        .collect();
    truncated |=
        binary.imports.len() > MAX_COLLECTION_ITEMS || binary.exports.len() > MAX_COLLECTION_ITEMS;

    let (subsystem, mitigations) = if let Some(optional) = binary.header.optional_header {
        let fields = optional.windows_fields;
        let flags = fields.dll_characteristics;
        let mut mitigations = Vec::new();
        if flags & pe::dll_characteristic::IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0 {
            mitigations.push("ASLR".into());
        }
        if flags & pe::dll_characteristic::IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0 {
            mitigations.push("DEP/NX".into());
        }
        if flags & pe::dll_characteristic::IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA != 0 {
            mitigations.push("High-entropy VA".into());
        }
        if flags & pe::dll_characteristic::IMAGE_DLLCHARACTERISTICS_GUARD_CF != 0 {
            mitigations.push("Control Flow Guard".into());
        }
        (Some(pe_subsystem(fields.subsystem).to_owned()), mitigations)
    } else {
        (None, Vec::new())
    };

    if binary.entry == 0 && !binary.is_lib {
        findings.push(Finding {
            id: "missing-entry-point".into(),
            title: "Executable has no entry point".into(),
            severity: Severity::Low,
            confidence: Confidence::High,
            rationale: "A native executable without an entry point is unusual and may be malformed or intentionally evasive.".into(),
            evidence: vec![],
        });
    }

    Ok(ParsedFormat {
        binary_format: BinaryFormat::Pe,
        architecture: Some(format!("{}-bit {machine}", bitness)),
        format: FormatReport::Pe {
            bitness,
            machine,
            subsystem,
            timestamp: binary.header.coff_header.time_date_stamp,
            entry_point: binary.entry as u64,
            image_base: binary.image_base,
            libraries: binary
                .libraries
                .into_iter()
                .take(MAX_COLLECTION_ITEMS)
                .map(str::to_owned)
                .collect(),
            is_dll: binary.is_lib,
            has_tls: binary.tls_data.is_some(),
            has_resources: binary.resource_data.is_some(),
            has_signature: !binary.certificates.is_empty(),
            is_dotnet: binary.clr_data.is_some(),
            mitigations,
        },
        sections,
        imports,
        exports,
        findings,
        warnings,
        collections_truncated: truncated,
    })
}

fn parse_elf(bytes: &[u8], binary: elf::Elf<'_>) -> Result<ParsedFormat, AnalysisError> {
    let machine = elf::header::machine_to_str(binary.header.e_machine).to_owned();
    let bitness = if binary.is_64 { 64 } else { 32 };
    let mut sections = Vec::new();
    let mut warnings = Vec::new();
    let mut truncated = binary.section_headers.len() > MAX_SECTIONS;

    for section in binary.section_headers.iter().take(MAX_SECTIONS) {
        let offset = section.sh_offset as usize;
        let declared = section.sh_size as usize;
        let data = bounded_slice(bytes, offset, declared);
        if data.len() != declared
            && declared > 0
            && section.sh_type != elf::section_header::SHT_NOBITS
        {
            warnings.push(AnalysisWarning {
                code: "section-out-of-range".into(),
                message: format!("ELF section at 0x{offset:x} extends beyond the sample"),
            });
        }
        sections.push(SectionRecord {
            name: binary
                .shdr_strtab
                .get_at(section.sh_name)
                .unwrap_or("<unnamed>")
                .to_owned(),
            offset: section.sh_offset,
            virtual_address: Some(section.sh_addr),
            size: section.sh_size,
            entropy: entropy(data),
            permissions: permissions(
                section.sh_flags & elf::section_header::SHF_ALLOC as u64 != 0,
                section.sh_flags & elf::section_header::SHF_WRITE as u64 != 0,
                section.sh_flags & elf::section_header::SHF_EXECINSTR as u64 != 0,
            ),
        });
    }

    let mut imports = Vec::new();
    let mut exports = Vec::new();
    for symbol in &binary.dynsyms {
        let name = binary.dynstrtab.get_at(symbol.st_name).unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let record = SymbolRecord {
            name: name.to_owned(),
            module: None,
            address: Some(symbol.st_value),
            kind: elf::sym::type_to_str(symbol.st_type()).to_ascii_lowercase(),
        };
        if symbol.st_shndx == elf::section_header::SHN_UNDEF as usize {
            if imports.len() < MAX_COLLECTION_ITEMS {
                imports.push(record);
            } else {
                truncated = true;
            }
        } else if symbol.st_bind() == elf::sym::STB_GLOBAL {
            if exports.len() < MAX_COLLECTION_ITEMS {
                exports.push(record);
            } else {
                truncated = true;
            }
        }
    }

    let mut hardening = Vec::new();
    let has_relro = binary
        .program_headers
        .iter()
        .any(|header| header.p_type == elf::program_header::PT_GNU_RELRO);
    let stack = binary
        .program_headers
        .iter()
        .find(|header| header.p_type == elf::program_header::PT_GNU_STACK);
    if has_relro {
        hardening.push("RELRO".into());
    }
    if stack.is_some_and(|header| header.p_flags & elf::program_header::PF_X == 0) {
        hardening.push("NX stack".into());
    }
    if binary.header.e_type == elf::header::ET_DYN {
        hardening.push("PIE/shared object".into());
    }
    if binary
        .dynsyms
        .iter()
        .any(|symbol| binary.dynstrtab.get_at(symbol.st_name) == Some("__stack_chk_fail"))
    {
        hardening.push("Stack canary".into());
    }

    Ok(ParsedFormat {
        binary_format: BinaryFormat::Elf,
        architecture: Some(format!("{}-bit {machine}", bitness)),
        format: FormatReport::Elf {
            bitness,
            machine,
            file_type: elf::header::et_to_str(binary.header.e_type).to_owned(),
            entry_point: binary.entry,
            interpreter: binary.interpreter.map(str::to_owned),
            libraries: binary
                .libraries
                .into_iter()
                .take(MAX_COLLECTION_ITEMS)
                .map(str::to_owned)
                .collect(),
            rpaths: binary
                .rpaths
                .into_iter()
                .chain(binary.runpaths)
                .take(MAX_COLLECTION_ITEMS)
                .map(str::to_owned)
                .collect(),
            hardening,
        },
        sections,
        imports,
        exports,
        findings: Vec::new(),
        warnings,
        collections_truncated: truncated,
    })
}

fn parse_mach(bytes: &[u8], binary: mach::Mach<'_>) -> Result<ParsedFormat, AnalysisError> {
    match binary {
        mach::Mach::Binary(binary) => parse_mach_binary(bytes, binary),
        mach::Mach::Fat(fat) => {
            let arches = fat.arches().map_err(|error| AnalysisError::Parse {
                format: "Mach-O",
                message: error.to_string(),
            })?;
            let truncated = arches.len() > MAX_COLLECTION_ITEMS;
            let slices: Vec<_> = arches
                .iter()
                .take(MAX_COLLECTION_ITEMS)
                .map(|arch| MachSlice {
                    machine: mach_cpu(arch.cputype).to_owned(),
                    offset: arch.offset as u64,
                    size: arch.size as u64,
                })
                .collect();
            let machine = slices
                .iter()
                .map(|slice| slice.machine.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            Ok(ParsedFormat {
                binary_format: BinaryFormat::MachO,
                architecture: Some(format!("Universal ({machine})")),
                format: FormatReport::MachO {
                    bitness: None,
                    machine,
                    entry_point: None,
                    slices,
                    libraries: Vec::new(),
                    rpaths: Vec::new(),
                    has_code_signature: false,
                },
                sections: Vec::new(),
                imports: Vec::new(),
                exports: Vec::new(),
                findings: Vec::new(),
                warnings: vec![AnalysisWarning {
                    code: "fat-binary-summary".into(),
                    message: "Universal Mach-O slices are summarized; inspect each thin slice separately for full symbol details.".into(),
                }],
                collections_truncated: truncated,
            })
        }
    }
}

fn parse_mach_binary(
    _bytes: &[u8],
    binary: mach::MachO<'_>,
) -> Result<ParsedFormat, AnalysisError> {
    let bitness = if binary.is_64 { 64 } else { 32 };
    let machine = mach_cpu(binary.header.cputype).to_owned();
    let mut sections = Vec::new();
    let mut warnings = Vec::new();
    let mut truncated = false;
    'segments: for segment in &binary.segments {
        for section in segment {
            if sections.len() >= MAX_SECTIONS {
                truncated = true;
                break 'segments;
            }
            match section {
                Ok((section, data)) => sections.push(SectionRecord {
                    name: format!(
                        "{},{}",
                        section.segname().unwrap_or("?"),
                        section.name().unwrap_or("?")
                    ),
                    offset: section.offset as u64,
                    virtual_address: Some(section.addr),
                    size: section.size,
                    entropy: entropy(data),
                    permissions: mach_section_permissions(section.segname().unwrap_or("")),
                }),
                Err(error) => warnings.push(AnalysisWarning {
                    code: "invalid-section".into(),
                    message: error.to_string(),
                }),
            }
        }
    }
    let all_imports = binary.imports().unwrap_or_default();
    let all_exports = binary.exports().unwrap_or_default();
    truncated |=
        all_imports.len() > MAX_COLLECTION_ITEMS || all_exports.len() > MAX_COLLECTION_ITEMS;
    let imports = all_imports
        .into_iter()
        .take(MAX_COLLECTION_ITEMS)
        .map(|item| SymbolRecord {
            name: item.name.to_owned(),
            module: Some(item.dylib.to_owned()),
            address: Some(item.address),
            kind: if item.is_lazy {
                "lazy".into()
            } else {
                "symbol".into()
            },
        })
        .collect();
    let exports = all_exports
        .into_iter()
        .take(MAX_COLLECTION_ITEMS)
        .map(|item| SymbolRecord {
            name: item.name,
            module: binary.name.map(str::to_owned),
            address: Some(item.offset),
            kind: "symbol".into(),
        })
        .collect();
    let has_code_signature = binary.load_commands.iter().any(|command| {
        matches!(
            command.command,
            mach::load_command::CommandVariant::CodeSignature(_)
        )
    });

    Ok(ParsedFormat {
        binary_format: BinaryFormat::MachO,
        architecture: Some(format!("{}-bit {machine}", bitness)),
        format: FormatReport::MachO {
            bitness: Some(bitness),
            machine,
            entry_point: (binary.entry != 0).then_some(binary.entry),
            slices: Vec::new(),
            libraries: binary
                .libs
                .into_iter()
                .take(MAX_COLLECTION_ITEMS)
                .map(str::to_owned)
                .collect(),
            rpaths: binary
                .rpaths
                .into_iter()
                .take(MAX_COLLECTION_ITEMS)
                .map(str::to_owned)
                .collect(),
            has_code_signature,
        },
        sections,
        imports,
        exports,
        findings: Vec::new(),
        warnings,
        collections_truncated: truncated,
    })
}

fn parse_wasm(bytes: &[u8]) -> Result<ParsedFormat, AnalysisError> {
    let validation = Validator::new().validate_all(bytes);
    let valid = validation.is_ok();
    let mut encoding = "module".to_owned();
    let mut version = 1u16;
    let mut types = 0u32;
    let mut functions = 0u32;
    let mut memories = 0u32;
    let mut tables = 0u32;
    let mut globals = 0u32;
    let mut start_function = None;
    let mut custom_sections = Vec::new();
    let mut sections = Vec::new();
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    let mut warnings = Vec::new();
    let mut truncated = false;

    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload.map_err(|error| AnalysisError::Parse {
            format: "WebAssembly",
            message: error.to_string(),
        })?;
        match payload {
            Payload::Version {
                num,
                encoding: kind,
                range,
            } => {
                version = num;
                encoding = match kind {
                    Encoding::Module => "module",
                    Encoding::Component => "component",
                }
                .into();
                push_wasm_section(&mut sections, "header", range, bytes, &mut truncated);
            }
            Payload::TypeSection(reader) => {
                types = reader.count();
                push_wasm_section(
                    &mut sections,
                    "types",
                    reader.range(),
                    bytes,
                    &mut truncated,
                );
            }
            Payload::ImportSection(reader) => {
                let range = reader.range();
                for item in reader
                    .into_imports()
                    .take(MAX_COLLECTION_ITEMS - imports.len())
                {
                    let item = item.map_err(|error| AnalysisError::Parse {
                        format: "WebAssembly",
                        message: error.to_string(),
                    })?;
                    imports.push(SymbolRecord {
                        name: item.name.to_owned(),
                        module: Some(item.module.to_owned()),
                        address: None,
                        kind: wasm_type_name(item.ty).into(),
                    });
                }
                push_wasm_section(&mut sections, "imports", range, bytes, &mut truncated);
            }
            Payload::FunctionSection(reader) => {
                functions = reader.count();
                push_wasm_section(
                    &mut sections,
                    "functions",
                    reader.range(),
                    bytes,
                    &mut truncated,
                );
            }
            Payload::TableSection(reader) => {
                tables = reader.count();
                push_wasm_section(
                    &mut sections,
                    "tables",
                    reader.range(),
                    bytes,
                    &mut truncated,
                );
            }
            Payload::MemorySection(reader) => {
                memories = reader.count();
                push_wasm_section(
                    &mut sections,
                    "memories",
                    reader.range(),
                    bytes,
                    &mut truncated,
                );
            }
            Payload::GlobalSection(reader) => {
                globals = reader.count();
                push_wasm_section(
                    &mut sections,
                    "globals",
                    reader.range(),
                    bytes,
                    &mut truncated,
                );
            }
            Payload::ExportSection(reader) => {
                let range = reader.range();
                for item in reader
                    .into_iter()
                    .take(MAX_COLLECTION_ITEMS - exports.len())
                {
                    let item = item.map_err(|error| AnalysisError::Parse {
                        format: "WebAssembly",
                        message: error.to_string(),
                    })?;
                    exports.push(SymbolRecord {
                        name: item.name.to_owned(),
                        module: None,
                        address: Some(item.index as u64),
                        kind: format!("{:?}", item.kind).to_ascii_lowercase(),
                    });
                }
                push_wasm_section(&mut sections, "exports", range, bytes, &mut truncated);
            }
            Payload::StartSection { func, range } => {
                start_function = Some(func);
                push_wasm_section(&mut sections, "start", range, bytes, &mut truncated);
            }
            Payload::CodeSectionStart { count, range, .. } => {
                functions = functions.max(count);
                push_wasm_section(&mut sections, "code", range, bytes, &mut truncated);
            }
            Payload::DataSection(reader) => {
                push_wasm_section(&mut sections, "data", reader.range(), bytes, &mut truncated);
            }
            Payload::CustomSection(reader) => {
                if custom_sections.len() < MAX_COLLECTION_ITEMS {
                    custom_sections.push(reader.name().to_owned());
                } else {
                    truncated = true;
                }
                push_wasm_section(
                    &mut sections,
                    &format!("custom:{}", reader.name()),
                    reader.range(),
                    bytes,
                    &mut truncated,
                );
            }
            _ => {}
        }
    }

    if !valid {
        warnings.push(AnalysisWarning {
            code: "wasm-validation-failed".into(),
            message: validation
                .err()
                .map(|error| error.to_string())
                .unwrap_or_else(|| "validation failed".into()),
        });
    }

    Ok(ParsedFormat {
        binary_format: BinaryFormat::WebAssembly,
        architecture: Some("WebAssembly".into()),
        format: FormatReport::WebAssembly {
            encoding,
            version,
            valid,
            types,
            functions,
            memories,
            tables,
            globals,
            start_function,
            custom_sections,
        },
        sections,
        imports,
        exports,
        findings: Vec::new(),
        warnings,
        collections_truncated: truncated,
    })
}

fn push_wasm_section(
    sections: &mut Vec<SectionRecord>,
    name: &str,
    range: std::ops::Range<usize>,
    bytes: &[u8],
    truncated: &mut bool,
) {
    if sections.len() >= MAX_SECTIONS {
        *truncated = true;
        return;
    }
    let data = bounded_slice(bytes, range.start, range.len());
    sections.push(SectionRecord {
        name: name.chars().take(128).collect(),
        offset: range.start as u64,
        virtual_address: None,
        size: range.len() as u64,
        entropy: entropy(data),
        permissions: "r--".into(),
    });
}

fn unknown(bytes: &[u8]) -> ParsedFormat {
    ParsedFormat {
        binary_format: BinaryFormat::Unknown,
        architecture: None,
        format: FormatReport::Unknown {
            magic: hex::encode(&bytes[..bytes.len().min(16)]),
        },
        sections: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        findings: vec![Finding {
            id: "unknown-format".into(),
            title: "Unrecognized binary format".into(),
            severity: Severity::Info,
            confidence: Confidence::High,
            rationale:
                "The sample does not match a supported PE, ELF, Mach-O, or WebAssembly signature."
                    .into(),
            evidence: Vec::new(),
        }],
        warnings: Vec::new(),
        collections_truncated: false,
    }
}

fn bounded_slice(bytes: &[u8], offset: usize, length: usize) -> &[u8] {
    offset
        .checked_add(length)
        .and_then(|end| bytes.get(offset..end))
        .unwrap_or_else(|| bytes.get(offset..).unwrap_or_default())
}

fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let length = bytes.len() as f64;
    let value = counts
        .iter()
        .filter(|count| **count != 0)
        .fold(0.0, |total, count| {
            let probability = *count as f64 / length;
            total - probability * probability.log2()
        });
    (value * 100.0).round() / 100.0
}

fn permissions(read: bool, write: bool, execute: bool) -> String {
    format!(
        "{}{}{}",
        if read { 'r' } else { '-' },
        if write { 'w' } else { '-' },
        if execute { 'x' } else { '-' }
    )
}

fn format_hint(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(b"MZ") {
        "PE"
    } else if bytes.starts_with(b"\x7fELF") {
        "ELF"
    } else if is_mach_magic(bytes) {
        "Mach-O"
    } else {
        "binary"
    }
}

fn is_mach_magic(bytes: &[u8]) -> bool {
    bytes.get(..4).is_some_and(|magic| {
        matches!(
            magic,
            [0xfe, 0xed, 0xfa, 0xce]
                | [0xce, 0xfa, 0xed, 0xfe]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xcf, 0xfa, 0xed, 0xfe]
                | [0xca, 0xfe, 0xba, 0xbe]
        )
    })
}

fn pe_subsystem(value: u16) -> &'static str {
    match value {
        1 => "Native",
        2 => "Windows GUI",
        3 => "Windows console",
        5 => "OS/2 console",
        7 => "POSIX console",
        9 => "Windows CE",
        10 => "EFI application",
        11 => "EFI boot driver",
        12 => "EFI runtime driver",
        14 => "Xbox",
        16 => "Windows boot application",
        _ => "Unknown",
    }
}

fn mach_cpu(value: u32) -> &'static str {
    use mach::constants::cputype::*;
    match value {
        CPU_TYPE_X86 => "x86",
        CPU_TYPE_X86_64 => "x86_64",
        CPU_TYPE_ARM => "ARM",
        CPU_TYPE_ARM64 => "ARM64",
        CPU_TYPE_ARM64_32 => "ARM64_32",
        CPU_TYPE_POWERPC => "PowerPC",
        CPU_TYPE_POWERPC64 => "PowerPC64",
        _ => "Unknown",
    }
}

fn mach_section_permissions(segment: &str) -> String {
    match segment {
        "__TEXT" => "r-x",
        "__DATA_CONST" => "r--",
        "__DATA" => "rw-",
        _ => "r--",
    }
    .into()
}

fn wasm_type_name(value: TypeRef) -> &'static str {
    match value {
        TypeRef::Func(_) | TypeRef::FuncExact(_) => "function",
        TypeRef::Table(_) => "table",
        TypeRef::Memory(_) => "memory",
        TypeRef::Global(_) => "global",
        TypeRef::Tag(_) => "tag",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_has_expected_extremes() {
        assert_eq!(entropy(&[0; 512]), 0.0);
        let uniform: Vec<u8> = (0..=255).cycle().take(1024).collect();
        assert_eq!(entropy(&uniform), 8.0);
    }

    #[test]
    fn parses_minimal_wasm_module() {
        let bytes = b"\0asm\x01\0\0\0";
        let report = parse(bytes).unwrap();
        assert_eq!(report.binary_format, BinaryFormat::WebAssembly);
        assert!(matches!(
            report.format,
            FormatReport::WebAssembly { valid: true, .. }
        ));
    }

    #[test]
    fn rejects_truncated_known_format() {
        assert!(matches!(
            parse(b"MZ\0\0"),
            Err(AnalysisError::Parse { format: "PE", .. })
        ));
        assert!(matches!(
            parse(b"\x7fELF\0"),
            Err(AnalysisError::Parse { format: "ELF", .. })
        ));
    }
}
